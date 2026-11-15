"""Windows-specific, allowlisted Codex history discovery and read-only ingestion.

Codex rollout JSONL is a version-sensitive implementation format. This adapter
uses observed event envelopes and only emits derived, redacted evidence.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path, PureWindowsPath

from .core import MAX_LINE_BYTES, redact, stable_id

MAX_DB_ROWS = 50_000
MAX_EVENTS = 250_000
MAX_CORRECTION_MESSAGE_CHARS = 4_000
CORRECTION = re.compile(r"\b(?:as i said|as i already said|i already (?:said|asked|told you|specified)|i asked you to|i told you to|that's not what i asked|that isn't what i asked|not what i asked|you (?:ignored|changed|removed|didn't follow|did not follow)|you were asked|i meant)\b|\bactually\b.{0,100}\b(?:i meant|not what|don't|do not|should(?:n't| not)|you changed|you removed)\b", re.I | re.S)
AGENTS_CONTEXT_BLOCK = re.compile(r"(?ims)^\s*# AGENTS\.md instructions for[^\n]*\n.*?^\s*</INSTRUCTIONS>\s*")
ENVIRONMENT_CONTEXT_BLOCK = re.compile(r"(?ims)^\s*<environment_context\b[^>]*>.*?^\s*</environment_context>\s*")
FAILURE = re.compile(r"(?:^|\n)\s*(?:(?:process|command)\s+)?exited with (?:code|status)\s*[:=]?\s*([1-9]\d*)\b|(?:^|\n)\s*exit code\s*[:=]\s*([1-9]\d*)\b", re.I)
FILE_INSPECT = re.compile(r"(?:get-content|select-string|\btype\s+|\bcat\s+|\bmore\s+|\bhead\s+|\btail\s+|\bdir\b|\bget-childitem\b|\brg\b|\bfind\s+|\bgit\s+(?:log|show)\b)", re.I)
FLAG_FAIL = re.compile(r"unknown (?:option|flag)|unrecognized arguments|unknown argument|invalid option", re.I)
SHELL_PATH_FAIL = re.compile(r"command not found|not recognized as (?:an internal|the name)|cannot find path|path not found|no such file or directory", re.I)
DEPENDENCY_FAIL = re.compile(r"no module named|module not found|package .* not found|version .* incompatible", re.I)
VERIFY_FAIL = re.compile(r"test failed|assertionerror|test result: failed|npm err!", re.I)
VERIFY_COMMAND = re.compile(r"(?:pytest|\bpython\s+-m\s+unittest|npm\s+(?:run\s+)?test|\bjest\b|cargo\s+test|go\s+test|dotnet\s+test|\bvitest\b)", re.I)
REVERSAL_COMMAND = re.compile(r"\bgit\s+(?:restore|revert)\b|\bgit\s+checkout\s+--\b", re.I)
USER_HOME_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]|/)(?:Users|home)[\\/][^\\/\s\"']+")
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]|\\\\|/(?:Users|home)/)[^\s\"']+")

def _strip_injected_user_context(text: str) -> str:
    """Remove known Codex context blocks before testing for user corrections.

    A message that begins like an injected AGENTS/environment block but has no
    recognizable closing boundary is ignored rather than treated as user intent.
    """
    text = ENVIRONMENT_CONTEXT_BLOCK.sub(" ", text)
    text = AGENTS_CONTEXT_BLOCK.sub(" ", text)
    if re.search(r"(?im)^\s*# AGENTS\.md instructions for\b", text):
        return ""
    if re.search(r"(?im)^\s*<environment_context\b", text):
        return ""
    # Text-only harness context is emitted as a leading labeled block.
    text = re.sub(r"(?ims)^\s*Environment context\s*:\s*.*?(?=\n\s*\n|\Z)", " ", text)
    return text.strip()

def resolve_home(environ: dict[str, str] | None = None) -> tuple[Path, str]:
    env = os.environ if environ is None else environ
    configured = env.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser().resolve(), "CODEX_HOME"
    profile = env.get("USERPROFILE")
    if profile:
        return (Path(profile) / ".codex").resolve(), "USERPROFILE default candidate"
    return (Path.home() / ".codex").resolve(), "home-directory default candidate"

def resolve_sqlite_home(home: Path, environ: dict[str, str] | None = None) -> tuple[Path, str]:
    env = os.environ if environ is None else environ
    configured = env.get("CODEX_SQLITE_HOME")
    return (Path(configured).expanduser().resolve(), "CODEX_SQLITE_HOME") if configured else (home, "Codex home")

def _hash_file(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None

def _safe_source(path:Path, root:Path)->bool:
    try:return not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
    except (OSError,ValueError):return False

def discover(home: Path, sqlite_home: Path) -> tuple[list[dict], list[Path]]:
    """Enumerate only the exact source families named in the user request."""
    report: list[dict] = []
    rollouts: list[Path] = []
    for source_name in ("sessions", "archived_sessions"):
        root = home / source_name
        found: list[Path] = []
        if root.is_dir() and not root.is_symlink():
            try:
                found = sorted(p for p in root.rglob("rollout-*.jsonl") if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root.resolve()))
            except OSError as e:
                report.append({"source": source_name, "candidate": str(root), "status": "INACCESSIBLE", "reason": type(e).__name__})
        rollouts.extend(found)
        readable = 0
        for p in found:
            try:
                with p.open("rb") as f: f.read(1)
                readable += 1
            except OSError:
                pass
        root_status="SYMLINK_REFUSED" if root.is_symlink() else "ACCESSIBLE" if root.is_dir() else "MISSING"
        report.append({"source": source_name, "candidate": str(root), "status": root_status, "file_count": len(found), "readable_count": readable, "unreadable_count": len(found)-readable, "date_coverage": _date_coverage(found, root)})
    for label, p, allowed_root in (("state_5.sqlite", sqlite_home / "state_5.sqlite",sqlite_home), ("session_index.jsonl", home / "session_index.jsonl",home), ("history/history.jsonl", home / "history" / "history.jsonl",home)):
        symlink=p.is_symlink()
        exists = p.is_file() and _safe_source(p,allowed_root)
        readable = False
        if exists:
            try:
                with p.open("rb") as f: f.read(1)
                readable = True
            except OSError: pass
        report.append({"source": label, "candidate": str(p), "status": "SYMLINK_REFUSED" if symlink else "ACCESSIBLE" if readable else "INACCESSIBLE" if exists else "MISSING", "size_bytes": p.stat().st_size if exists and readable else None})
    return report, rollouts

def _date_coverage(files: list[Path], root: Path) -> dict | None:
    dates=[]
    for p in files:
        try:
            rel=p.relative_to(root).parts
            if len(rel)>=4 and all(x.isdigit() for x in rel[:3]): dates.append("-".join(rel[:3]))
        except ValueError: pass
    return {"first": min(dates), "last": max(dates)} if dates else None

def _line_records(path: Path):
    """Yield JSONL rows one bounded line at a time and structural problems."""
    try:
        with path.open("rb") as f:
            line_no=0
            while True:
                raw=f.readline(MAX_LINE_BYTES+1)
                if not raw: break
                line_no+=1
                if len(raw)>MAX_LINE_BYTES:
                    while raw and not raw.endswith(b"\n"):
                        raw=f.readline(MAX_LINE_BYTES+1)
                    yield line_no, None, "line exceeds 2 MB limit"
                    continue
                try:
                    row=json.loads(raw)
                    yield line_no, row if isinstance(row,dict) else None, None if isinstance(row,dict) else "record is not an object"
                except (json.JSONDecodeError,UnicodeDecodeError):
                    yield line_no,None,"malformed JSON"
    except OSError as e:
        yield 0,None,"inaccessible: "+type(e).__name__

def _safe_repo(cwd: str | None) -> tuple[str,str|None]:
    if not cwd: return "unknown",None
    # Path is evidence from session metadata; do not walk or inspect the repository.
    raw = str(cwd)
    label = PureWindowsPath(raw).name or "unknown"
    repo_id = stable_id(os.path.normcase(os.path.normpath(raw)))
    return repo_id,label

def _event_ref(path: Path, home: Path, ordinal: object, line: int) -> str:
    try: rel=path.relative_to(home).as_posix()
    except ValueError: rel=path.name
    return f"{rel}#ordinal={ordinal if ordinal is not None else line}"

def _text_blocks(value) -> str:
    if isinstance(value,str): return value
    if isinstance(value,list):
        return "\n".join(str(x.get("text", "")) for x in value if isinstance(x,dict) and x.get("type") in ("input_text","output_text","text"))
    return ""

def _command_from_call(payload: dict) -> str:
    raw=payload.get("input",payload.get("arguments", ""))
    if isinstance(raw,dict):
        if isinstance(raw.get("command"),str): raw=raw["command"]
        elif isinstance(raw.get("cmd"),str): raw=raw["cmd"]
        else: raw=json.dumps(raw,sort_keys=True,ensure_ascii=False)
    return str(raw)

def _command_signature(command: str) -> str:
    text=redact(command)
    text=ABSOLUTE_PATH.sub("<PATH>",text)
    text=re.sub(r"\s+"," ",text).strip().lower()
    return text[:400]

def _failure_kind(call: dict, output) -> str | None:
    """Return a failure class only for an explicit process/tool failure signal."""
    text = _text_blocks(output) if isinstance(output,list) else output if isinstance(output,str) else ""
    structured_rows=[]
    if isinstance(output,dict):
        structured_rows.append(output)
    elif isinstance(output,str):
        try:
            parsed=json.loads(output)
            if isinstance(parsed,dict): structured_rows.append(parsed)
        except json.JSONDecodeError:
            pass
    elif isinstance(output,list):
        for item in output:
            if not isinstance(item,dict) or item.get("type") not in ("input_text","output_text","text"):
                continue
            try:
                parsed=json.loads(str(item.get("text", "")))
                if isinstance(parsed,dict): structured_rows.append(parsed)
            except json.JSONDecodeError:
                continue
    status_values=[]
    exit_codes=[]
    structured_text=[]
    for row in structured_rows:
        if isinstance(row.get("output"),str): structured_text.append(row["output"])
        elif isinstance(row.get("output"),list): structured_text.append(_text_blocks(row["output"]))
        if row.get("status") is not None: status_values.append(row["status"])
        for field in (row.get("exit_code"),row.get("return_code")):
            if field is not None: exit_codes.append(field)
        metadata=row.get("metadata")
        if isinstance(metadata,dict):
            if metadata.get("status") is not None: status_values.append(metadata["status"])
            for field in (metadata.get("exit_code"),metadata.get("return_code")):
                if field is not None: exit_codes.append(field)
    if structured_text: text="\n".join(([text] if text else [])+structured_text)
    # The common wrapper places JSON inside each text item, so inspect both
    # each item's parsed metadata and its text markers without line anchoring.
    exit_marker = re.compile(r'(?i)(?:"?exit_code"?\s*:\s*|exit_code\s*=\s*|EXIT_CODE:\s*)([1-9]\d*)\b')
    text_items=[text]
    if isinstance(output,list):
        text_items=[str(x.get("text", "")) for x in output if isinstance(x,dict) and x.get("type") in ("input_text","output_text","text")]
    text_nonzero=bool(FAILURE.search(text) or any(exit_marker.search(item) for item in text_items))
    code_nonzero=any(isinstance(code,(int,float)) and not isinstance(code,bool) and code != 0 or isinstance(code,str) and code.strip().lstrip("+").isdigit() and int(code) != 0 for code in exit_codes)
    status_failure=any(str(status).casefold() in ("failed","error") for status in status_values)
    explicit_nonzero=text_nonzero or code_nonzero or status_failure
    command = call.get("command", "")
    tool = call.get("tool", "")
    # Read/search output often contains words such as “failed” or tracebacks as data.
    # Inspection output commonly contains failure vocabulary as data. Require
    # structured status/code, a line-anchored failure, or command-prefixed path error.
    if FILE_INSPECT.search(command):
        path_error = re.search(r"(?im)(?:^|\n)\s*(?:(?:get-content|get-childitem|select-string)\s*:\s*(?:cannot find path|path not found|file not found)|(?:cat|type|more|head|tail|rg|find|dir)\s*:\s*[^\n]*:\s*(?:no such file or directory|file not found))\b[^\n]*", text)
        inspection_failure = code_nonzero or status_failure or bool(FAILURE.search(text)) or bool(path_error)
        return "failed_tool_call" if inspection_failure else None
    if FLAG_FAIL.search(text): return "unsupported_flag"
    if SHELL_PATH_FAIL.search(text): return "shell_path_incompatibility"
    if explicit_nonzero and DEPENDENCY_FAIL.search(text): return "dependency_mismatch"
    if explicit_nonzero and VERIFY_COMMAND.search(command) and VERIFY_FAIL.search(text): return "verification_failure"
    if "mcp" in tool.casefold() and (explicit_nonzero or re.search(r"\btool call failed\b|\bstatus\s*[:=]\s*(?:failed|error)\b",text,re.I)): return "mcp_failure"
    if explicit_nonzero: return "failed_tool_call"
    return None

def _failure_evidence_basis(call: dict, output) -> str:
    """Describe which observable signal justified a failed-tool event."""
    text = _text_blocks(output) if isinstance(output,list) else output if isinstance(output,str) else ""
    rows=[]
    if isinstance(output,dict):
        rows.append(output)
    elif isinstance(output,str):
        try:
            parsed=json.loads(output)
            if isinstance(parsed,dict): rows.append(parsed)
        except json.JSONDecodeError:
            pass
    elif isinstance(output,list):
        for item in output:
            if isinstance(item,dict) and item.get("type") in ("input_text","output_text","text"):
                try:
                    parsed=json.loads(str(item.get("text", "")))
                    if isinstance(parsed,dict): rows.append(parsed)
                except json.JSONDecodeError:
                    pass
    codes=[];statuses=[];structured_text=[]
    for row in rows:
        if isinstance(row.get("output"),str): structured_text.append(row["output"])
        elif isinstance(row.get("output"),list): structured_text.append(_text_blocks(row["output"]))
        if row.get("status") is not None: statuses.append(row["status"])
        codes.extend(x for x in (row.get("exit_code"),row.get("return_code")) if x is not None)
        metadata=row.get("metadata")
        if isinstance(metadata,dict):
            if metadata.get("status") is not None: statuses.append(metadata["status"])
            codes.extend(x for x in (metadata.get("exit_code"),metadata.get("return_code")) if x is not None)
    if structured_text: text="\n".join(([text] if text else [])+structured_text)
    code_nonzero=any(isinstance(code,(int,float)) and not isinstance(code,bool) and code != 0 or isinstance(code,str) and code.strip().lstrip("+").isdigit() and int(code) != 0 for code in codes)
    status_failure=any(str(status).casefold() in ("failed","error") for status in statuses)
    if code_nonzero or status_failure: return "structured exit/status"
    if FILE_INSPECT.search(call.get("command", "")):
        if FAILURE.search(text): return "line-anchored failure marker"
        if re.search(r"(?im)(?:^|\n)\s*(?:(?:get-content|get-childitem|select-string)\s*:\s*(?:cannot find path|path not found|file not found)|(?:cat|type|more|head|tail|rg|find|dir)\s*:\s*[^\n]*:\s*(?:no such file or directory|file not found))\b[^\n]*", text):
            return "command-prefixed path error"
    elif FAILURE.search(text):
        return "line-anchored failure marker"
    if re.search(r'(?i)(?:"?exit_code"?\s*:\s*|exit_code\s*=\s*|EXIT_CODE:\s*)([1-9]\d*)\b',text):
        return "text exit marker (lower confidence)"
    return "tool output status signature"

def _path_key(value, home:Path)->str:
    """Lexically normalize Windows paths without traversing metadata paths."""
    raw=str(value).replace("/","\\")
    if raw.startswith("\\\\?\\"):
        raw=raw[4:]
    if not ntpath.isabs(raw):
        raw=ntpath.join(str(home).replace("/","\\"),raw)
    return ntpath.normcase(ntpath.normpath(raw))

def _make_event(kind: str, path: Path, home: Path, thread_id: str, session_id: str, repo_id: str, repo_label: str|None, timestamp, ordinal, line: int, signature: str|None=None, detail: str="", evidence_basis="observed rollout fields",source_event_id:str|None=None) -> dict:
    ref=_event_ref(path,home,ordinal,line)
    identity=str(ordinal if ordinal is not None else line)
    return {"event_id":stable_id(thread_id,source_event_id or identity,identity,kind,signature or ""),"source_event_id":source_event_id,"event_type":kind,"session_id":session_id,"thread_id":thread_id,"event_ref":ref,"source_type":"codex_rollout_jsonl","timestamp":timestamp,"timestamp_precision":"source-provided" if timestamp else "unknown","repository_id":repo_id,"repository_label":repo_label,"command_signature":signature,"detail":detail,"evidence_basis":evidence_basis}

def parse_rollout(path: Path, home: Path, known_thread: str|None=None, event_limit:int=MAX_EVENTS) -> dict:
    """Stream one rollout; retain only small identity state and friction evidence."""
    result={"path":path,"thread_id":known_thread,"metadata_thread_id":known_thread,"header_thread_id":None,"identity_conflict":False,"session_id":None,"cwd":None,"parent_ids":[],"events":[],"parse_errors":[],"record_count":0,"header_seen":False,"task_started_seen":False,"terminal_seen":False,"truncated":False,"sha256":None,"status":"READABLE","timestamp_start":None,"timestamp_end":None,"event_cap_reached":False,"event_limit":event_limit,"file_changed_during_read":False}
    pending={}; failed_signatures=set(); inspections=Counter(); recent_call_by_sig={}; seen_ids=set()
    initial_stat=None
    try:
        initial_stat=path.stat()
        if initial_stat.st_size:
            with path.open("rb") as f:
                f.seek(-1,os.SEEK_END)
                result["truncated"]=f.read(1)!=b"\n"
    except OSError: result["truncated"]=True
    for line,row,error in _line_records(path):
        if error:
            result["parse_errors"].append({"line":line,"error":error})
            if error.startswith("inaccessible"): result["status"]="UNREADABLE"
            continue
        if not isinstance(row,dict): continue
        result["record_count"]+=1
        kind=row.get("type"); payload=row.get("payload")
        if not isinstance(payload,dict): continue
        ordinal=row.get("ordinal"); timestamp=row.get("timestamp")
        if result["thread_id"] is None:
            inferred_thread=payload.get("thread_id") or payload.get("conversation_id") or row.get("thread_id")
            if inferred_thread:result["thread_id"]=str(inferred_thread)
        if result["session_id"] is None and row.get("session_id"):result["session_id"]=str(row["session_id"])
        if timestamp:
            result["timestamp_start"] = result["timestamp_start"] or timestamp
            result["timestamp_end"] = timestamp
        if kind=="session_meta":
            result["header_seen"]=True
            header_thread=str(payload.get("id") or "") or None
            result["header_thread_id"]=header_thread
            result["identity_conflict"]=bool(known_thread and header_thread and known_thread!=header_thread)
            result["thread_id"]=known_thread or header_thread or "unknown"
            result["session_id"]=str(known_thread or payload.get("session_id") or header_thread or result["thread_id"])
            result["cwd"]=payload.get("cwd") if isinstance(payload.get("cwd"),str) else None
            for k in ("parent_thread_id","forked_from_id","attached_thread_parent_id"):
                if payload.get(k): result["parent_ids"].append(str(payload[k]))
            continue
        if kind=="event_msg" and payload.get("type")=="task_started": result["task_started_seen"]=True
        if kind=="event_msg" and payload.get("type")=="task_complete": result["terminal_seen"]=True
        thread_id=result["thread_id"] or "unknown"; session_id=result["session_id"] or thread_id
        repo_id,repo_label=_safe_repo(result["cwd"])
        if kind!="response_item": continue
        rtype=payload.get("type")
        if rtype=="message" and payload.get("role")=="user":
            user_text=_strip_injected_user_context(_text_blocks(payload.get("content")))
            begins_as_context=bool(re.match(r"(?is)^\s*(?:<[^>\n]+>|#{1,6}\s|[A-Z][A-Z0-9 _-]{0,32}:)",user_text))
            if len(user_text)<=MAX_CORRECTION_MESSAGE_CHARS and not begins_as_context and CORRECTION.search(user_text):
                ev=_make_event("user_correction",path,home,thread_id,session_id,repo_id,repo_label,timestamp,ordinal,line,detail="possible correction phrase detected; low-confidence lexical signal; message content omitted",evidence_basis="low-confidence user-authored lexical marker",source_event_id=str(payload.get("id") or "") or None)
                _append_event(result,ev,seen_ids)
        elif rtype in ("custom_tool_call","function_call"):
            tool=str(payload.get("name", "unknown")); command=_command_from_call(payload)
            sig=_command_signature(command) if tool.casefold() in ("exec","shell","shell_command") else ""
            if sig and REVERSAL_COMMAND.search(command):
                ev=_make_event("reversal_command_observed",path,home,thread_id,session_id,repo_id,repo_label,timestamp,ordinal,line,sig,"rollback-style command observed; intent unknown",source_event_id=str(payload.get("id") or payload.get("call_id") or "") or None)
                _append_event(result,ev,seen_ids)
            call_id=str(payload.get("call_id",payload.get("id", "")))
            if call_id and len(pending)<10000: pending[call_id]={"signature":sig,"command":command,"tool":tool,"ref":_event_ref(path,home,ordinal,line),"timestamp":timestamp,"ordinal":ordinal,"line":line,"thread":thread_id,"session":session_id,"repo":repo_id,"repo_label":repo_label,"source_event_id":str(payload.get("id") or call_id)}
            if sig and FILE_INSPECT.search(command):
                inspections[sig]+=1
                if inspections[sig]>1:
                    ev=_make_event("repeated_file_inspection",path,home,thread_id,session_id,repo_id,repo_label,timestamp,ordinal,line,sig,"same inspection command repeated in this session",source_event_id=str(payload.get("id") or call_id) or None)
                    _append_event(result,ev,seen_ids)
            if sig and sig in failed_signatures and recent_call_by_sig.get(sig):
                ev=_make_event("command_retry",path,home,thread_id,session_id,repo_id,repo_label,timestamp,ordinal,line,sig,"command repeated after observed unsuccessful result",source_event_id=str(payload.get("id") or call_id) or None)
                _append_event(result,ev,seen_ids)
            if sig: recent_call_by_sig[sig]=call_id
            if str(payload.get("status","")).casefold() in ("failed","error"):
                ev=_make_event("failed_tool_call",path,home,thread_id,session_id,repo_id,repo_label,timestamp,ordinal,line,sig,"tool call marked unsuccessful; output omitted","structured exit/status",str(payload.get("id") or call_id) or None)
                _append_event(result,ev,seen_ids)
        elif rtype in ("custom_tool_call_output","function_call_output"):
            call_id=str(payload.get("call_id", "")); call=pending.pop(call_id,None)
            output=payload.get("output", "")
            if not call: continue
            # Output can contain secrets and arbitrary private content; inspect only for status,
            # never serialize it. A model/tool description alone is not independent evidence.
            out_text=output if isinstance(output,str) else json.dumps(output,ensure_ascii=False,default=str)
            failure_kind=_failure_kind(call, output)
            if failure_kind:
                sig=call["signature"]
                ev=_make_event(failure_kind,path,home,thread_id,session_id,repo_id,repo_label,call["timestamp"],call["ordinal"],call["line"],sig,"unsuccessful tool output observed; output omitted",_failure_evidence_basis(call,output),call["source_event_id"])
                _append_event(result,ev,seen_ids)
                if sig: failed_signatures.add(sig)
            elif call["signature"] and call["signature"] in failed_signatures:
                # A successful corrective retry is observable as recovery, not a failure.
                ev=_make_event("corrective_command",path,home,thread_id,session_id,repo_id,repo_label,call["timestamp"],call["ordinal"],call["line"],call["signature"],"command succeeded after an earlier unsuccessful call",source_event_id=call["source_event_id"])
                _append_event(result,ev,seen_ids)
        if len(result["events"])>=event_limit: result["event_cap_reached"]=True
    result["thread_id"]=result["thread_id"] or known_thread or "unknown"
    result["session_id"]=result["session_id"] or result["thread_id"]
    result["sha256"]=_hash_file(path)
    try:
        final_stat=path.stat()
        result["file_changed_during_read"]=initial_stat is None or (initial_stat.st_size,initial_stat.st_mtime_ns)!=(final_stat.st_size,final_stat.st_mtime_ns)
    except OSError:result["file_changed_during_read"]=True
    if not result["header_seen"] and result["status"]!="UNREADABLE": result["status"]="PARTIAL"
    if (result["parse_errors"] or result["truncated"] or result["event_cap_reached"] or result["file_changed_during_read"] or (result["task_started_seen"] and not result["terminal_seen"])) and result["status"]!="UNREADABLE": result["status"]="PARTIAL"
    return result

def _append_event(session:dict,event:dict,seen:set[str]):
    if event["event_id"] not in seen and len(seen)<MAX_EVENTS and len(session["events"])<session.get("event_limit",MAX_EVENTS):
        seen.add(event["event_id"]);session["events"].append(event)

def inspect_sqlite(path:Path, max_rows:int=MAX_DB_ROWS, allowed_root:Path|None=None)->dict:
    """Read the actual schema first, then bounded metadata-only selects, strictly read-only."""
    result={"path":str(path),"status":"MISSING","schema":[],"threads":[],"spawn_edges":[],"missing_rollouts":[],"row_limit":max_rows,"rows_truncated":False,"error":None}
    if not path.is_file():return result
    if not _safe_source(path,allowed_root or path.parent):
        result["status"]="SOURCE_SYMLINK_REFUSED";return result
    result["status"]="UNREADABLE"
    try:
        wal=Path(str(path)+"-wal"); shm=Path(str(path)+"-shm")
        # SQLite may create coordination sidecars while opening a WAL database.
        # Avoid creating them: a cleanly checkpointed DB can use immutable read-only
        # mode; an active WAL is read only when its existing shared-memory file exists.
        if wal.exists() and not shm.exists():
            result["status"]="SNAPSHOT_UNAVAILABLE"
            result["error"]="WAL exists without an existing shared-memory sidecar; refusing an open that could create one"
            return result
        query="mode=ro" if wal.exists() else "mode=ro&immutable=1"
        uri=path.resolve().as_uri()+"?"+query
        con=sqlite3.connect(uri,uri=True,timeout=2)
        try:
            con.execute("PRAGMA query_only=ON");con.execute("PRAGMA busy_timeout=2000");con.execute("BEGIN")
            tables=con.execute("SELECT type,name FROM sqlite_schema WHERE type IN ('table','view') ORDER BY type,name LIMIT ?",(500,)).fetchall()
            schema=[]
            for typ,name in tables:
                if typ!="table":schema.append({"type":typ,"name":name,"columns":[]});continue
                q='PRAGMA table_info("'+str(name).replace('"','""')+'")'
                cols=[r[1] for r in con.execute(q).fetchall()]
                schema.append({"type":typ,"name":name,"columns":cols})
            result["schema"]=schema; byname={x["name"]:x["columns"] for x in schema}
            if "threads" in byname:
                cols=byname["threads"]
                chosen=[x for x in ("id","rollout_path","created_at","updated_at","created_at_ms","updated_at_ms","cwd","source","attached_thread_parent_id") if x in cols]
                if "id" in chosen and "rollout_path" in chosen:
                    qcols=",".join('"'+x+'"' for x in chosen)
                    rows=con.execute(f'SELECT {qcols} FROM "threads" ORDER BY "id" LIMIT ?', (max_rows+1,)).fetchmany(max_rows+1)
                    result["rows_truncated"]=len(rows)>max_rows
                    rows=rows[:max_rows]
                    for row in rows:
                        item=dict(zip(chosen,row)); result["threads"].append(item)
            if "thread_spawn_edges" in byname:
                cols=byname["thread_spawn_edges"]
                chosen=[x for x in ("parent_thread_id","child_thread_id") if x in cols]
                if len(chosen)==2:
                    qcols=",".join('"'+x+'"' for x in chosen)
                    rows=con.execute(f'SELECT {qcols} FROM "thread_spawn_edges" ORDER BY "child_thread_id" LIMIT ?', (max_rows+1,)).fetchmany(max_rows+1)
                    result["spawn_edges"]=[dict(zip(chosen,r)) for r in rows[:max_rows]]
                    result["rows_truncated"]|=len(rows)>max_rows
            result["status"]="READ_ONLY_SCHEMA_AND_METADATA_READ"
            con.rollback()
        finally:con.close()
    except (sqlite3.Error,OSError) as e:
        result["error"]=type(e).__name__+": "+str(e)[:300]
        result["status"]="SNAPSHOT_UNAVAILABLE"
    return result

def _normalize_rollout_path(raw,home:Path)->Path|None:
    if not isinstance(raw,str) or not raw.strip():return None
    p=Path(raw)
    return p if p.is_absolute() else home/p

def _allowlisted_rollout(path:Path,home:Path)->bool:
    try:
        resolved=path.resolve()
        return any(resolved.is_relative_to((home/name).resolve()) for name in ("sessions","archived_sessions"))
    except (OSError,ValueError):return False

def reconcile(home:Path, rollouts:list[Path], sqlite_meta:dict, index_path:Path)->tuple[list[dict],list[dict]]:
    """Join independent metadata by ids and paths; do not use filenames as identity."""
    index={}; index_errors=[]
    if index_path.is_file():
        for n,row,error in _line_records(index_path):
            if error: index_errors.append({"line":n,"error":error});continue
            sid=str(row.get("id", ""));
            if sid:index[sid]={"id":sid,"updated_at":row.get("updated_at")}
    sqlite_meta["session_index_errors"]=index_errors
    db_by_id={str(r.get("id")):r for r in sqlite_meta.get("threads",[]) if r.get("id")}
    db_by_path={_path_key(r.get("rollout_path"),home):r for r in sqlite_meta.get("threads",[]) if r.get("rollout_path")}
    alias_to_canonical={}
    files_by_id={}; file_rows=[]; unknown_files=[]; accumulated_events=0
    for p in rollouts:
        db=db_by_path.get(_path_key(str(p),home))
        remaining=max(0,MAX_EVENTS-accumulated_events)
        parsed=parse_rollout(p,home,str(db.get("id")) if db else None,remaining)
        accumulated_events+=len(parsed["events"])
        tid=parsed["thread_id"]
        header_id=parsed.get("header_thread_id")
        if parsed.get("identity_conflict") and header_id and header_id not in db_by_id:
            alias_to_canonical[header_id]=tid
        row={"thread_id":tid,"session_id":parsed["session_id"],"path":p,"parsed":parsed,"db":db,"index":index.get(tid)}
        if tid and tid!="unknown":files_by_id.setdefault(tid,[]).append(row)
        else:unknown_files.append(row)
        file_rows.append(row)
    all_ids=set(files_by_id)|{x for x in db_by_id if x not in alias_to_canonical}|{x for x in index if x not in alias_to_canonical}
    for r in sqlite_meta.get("threads",[]):
        rp=_normalize_rollout_path(r.get("rollout_path"),home)
        if rp and _allowlisted_rollout(rp,home) and not rp.exists():sqlite_meta["missing_rollouts"].append({"thread_id":str(r.get("id")),"rollout_path":_event_ref(rp,home,"missing",0),"metadata_indicates_conversation":True})
    sessions=[]
    for tid in sorted(all_ids):
        file_items=files_by_id.get(tid,[]); db=db_by_id.get(tid); ix=index.get(tid)
        if not ix:
            ix=next((index.get(alias) for alias,canonical in alias_to_canonical.items() if canonical==tid and index.get(alias)),None)
        primary=file_items[0] if file_items else None
        if primary:
            parsed=primary["parsed"]
            parsed_files=[x["parsed"] for x in file_items]
            if any(x["status"]=="UNREADABLE" for x in parsed_files):status="UNREADABLE"
            elif not db and not ix:status="ORPHANED_ROLLOUT"
            elif any(x["status"]=="PARTIAL" for x in parsed_files):status="PARTIAL"
            else:status="COMPLETE_WITHIN_OBSERVED_COVERAGE"
            repo_id,repo_label=_safe_repo(parsed["cwd"])
            starts=[x["timestamp_start"] for x in parsed_files if x["timestamp_start"]];ends=[x["timestamp_end"] for x in parsed_files if x["timestamp_end"]]
            conflicts=[{"sqlite_thread_id":x["parsed"].get("metadata_thread_id"),"header_thread_id":x["parsed"].get("header_thread_id"),"rollout_path":x["path"].relative_to(home).as_posix()} for x in file_items if x["parsed"].get("identity_conflict")]
            sessions.append({"thread_id":tid,"session_id":parsed["session_id"],"classification":status,"transcript_status":"UNREADABLE" if any(x["status"]=="UNREADABLE" for x in parsed_files) else "PARTIAL" if any(x["status"]=="PARTIAL" for x in parsed_files) else "READABLE","metadata_orphaned":not db and not ix,"rollout_paths":[f["path"].relative_to(home).as_posix() for f in file_items],"identity_conflicts":conflicts,"header_thread_ids":sorted({x["parsed"].get("header_thread_id") for x in file_items if x["parsed"].get("header_thread_id")}),"sqlite_metadata_present":bool(db),"session_index_present":bool(ix),"repository_id":repo_id,"repository_label":repo_label,"cwd_attributable":bool(parsed["cwd"]),"parent_thread_ids":sorted({p for x in parsed_files for p in x["parent_ids"]}),"record_count":sum(x["record_count"] for x in parsed_files),"parse_errors":[e for x in parsed_files for e in x["parse_errors"]],"truncated":any(x["truncated"] for x in parsed_files),"event_cap_reached":any(x["event_cap_reached"] for x in parsed_files),"file_changed_during_read":any(x["file_changed_during_read"] for x in parsed_files),"task_started_seen":any(x["task_started_seen"] for x in parsed_files),"terminal_marker_seen":any(x["terminal_seen"] for x in parsed_files),"timestamp_start":min(starts) if starts else (db.get("created_at") if db else None),"timestamp_end":max(ends) if ends else (db.get("updated_at") if db else None) or (ix.get("updated_at") if ix else None),"thread_source":db.get("source") if db and "source" in db else None,"coverage_caveat":"Classification describes observed readable artifacts only; no claim that Codex retained a complete conversation."})
        elif db or ix:
            dbpath=_normalize_rollout_path(db.get("rollout_path"),home) if db else None
            allowlisted=bool(dbpath and _allowlisted_rollout(dbpath,home))
            exists=dbpath.exists() if allowlisted and dbpath else False
            safe_ref=_event_ref(dbpath,home,"metadata",0) if allowlisted and dbpath else "outside_allowlist_not_checked" if dbpath else None
            sessions.append({"thread_id":tid,"session_id":tid,"classification":"METADATA_ONLY","rollout_paths":[safe_ref] if safe_ref else [],"sqlite_metadata_present":bool(db),"session_index_present":bool(ix),"repository_id":_safe_repo(db.get("cwd"))[0] if db else "unknown","repository_label":_safe_repo(db.get("cwd"))[1] if db else None,"cwd_attributable":bool(db and db.get("cwd")),"parent_thread_ids":[str(db["attached_thread_parent_id"])] if db and db.get("attached_thread_parent_id") else [],"record_count":0,"parse_errors":[],"truncated":False,"terminal_marker_seen":False,"timestamp_start":db.get("created_at") if db else None,"timestamp_end":db.get("updated_at") if db else ix.get("updated_at") if ix else None,"missing_rollout_file":(not exists) if allowlisted and dbpath else None,"coverage_caveat":"Metadata indicates a conversation; missing rollout does not establish that it never existed."})
    for row in unknown_files:
        sessions.append({"thread_id":"unknown","session_id":"unknown","classification":"UNKNOWN","rollout_paths":[row["path"].relative_to(home).as_posix()],"sqlite_metadata_present":False,"session_index_present":False,"repository_id":"unknown","repository_label":None,"cwd_attributable":False,"record_count":row["parsed"]["record_count"],"parse_errors":row["parsed"]["parse_errors"],"truncated":row["parsed"]["truncated"],"coverage_caveat":"No session/thread ID could be attributed."})
    # Promote explicit child relations from actual SQLite schema when present.
    edges=sqlite_meta.get("spawn_edges",[])
    edge_map=defaultdict(list)
    for e in edges:edge_map[str(e.get("child_thread_id"))].append(str(e.get("parent_thread_id")))
    for s in sessions:
        s["parent_thread_ids"]=sorted(set(s.get("parent_thread_ids",[])+edge_map.get(s["thread_id"],[])))
    return sessions,file_rows

def friction_and_patterns(file_rows:list[dict])->tuple[list[dict],list[dict]]:
    events=[]
    for row in file_rows:
        events.extend(row["parsed"]["events"])
    # Event IDs deduplicate duplicated source projections; keep first stable evidence ref.
    unique={e["event_id"]:e for e in events}
    events=sorted(unique.values(),key=lambda e:(e.get("timestamp") or "",e["event_id"]))
    grouped=defaultdict(list)
    for e in events:
        sig=e.get("command_signature") or e["event_type"]
        root_key=(e["event_type"],sig,e.get("repository_id","unknown"))
        grouped[root_key].append(e)
    patterns=[]
    cross_groups=defaultdict(list)
    for (category,sig,repo_id),hits in sorted(grouped.items()):
        cross_groups[(category,sig)].extend(hits)
    for (category,sig),hits in sorted(cross_groups.items()):
        repos=sorted({h.get("repository_id","unknown") for h in hits})
        labels=sorted({h.get("repository_label") for h in hits if h.get("repository_label")})
        sessions=sorted({h["thread_id"] for h in hits})
        if len(repos)>1:scope="GLOBAL"
        elif repos!=["unknown"]:scope="PROJECT"
        else:scope="UNKNOWN"
        patterns.append({"pattern_id":stable_id(category,sig),"category":category,"canonical_signature":stable_id(sig),"affected_session_ids":sessions,"supporting_evidence":[{"event_id":h["event_id"],"source_ref":h["event_ref"],"evidence_basis":h["evidence_basis"]} for h in hits],"repository_ids":repos,"repository_labels":labels,"observed_occurrence_count":len(hits),"independent_session_count":len(sessions),"root_cause_hypothesis":_hypothesis(category),"confidence":"low" if category=="user_correction" else "medium" if len(sessions)>=2 else "low","uncertainty":"Rollout data can be incomplete; heuristic signals do not independently establish root cause or avoidability.","scope":scope,"documentation_verification":"not_verified","proposed_prevention":_prevention(category),"expected_benefit":"reduce recurrence if human review confirms preventability","potential_negative_consequences":"Could suppress necessary iteration or overgeneralize; retain only after review."})
    return events,patterns

def _hypothesis(category:str)->str:
    return {"unsupported_flag":"A CLI option was rejected by observed tool output.","shell_path_incompatibility":"A command or path resolution failure phrase appeared in a tool result.","dependency_mismatch":"A dependency or version failure phrase appeared in a tool result.","verification_failure":"A test command produced an explicit failed-check marker.","mcp_failure":"A tool whose name contains MCP produced an unsuccessful output marker.","failed_tool_call":"A tool output contained an explicit unsuccessful status pattern.","command_retry":"The same command signature recurred after an unsuccessful output.","corrective_command":"A repeated command signature succeeded after an earlier failure.","repeated_file_inspection":"The same file inspection command signature recurred in one session.","reversal_command_observed":"A git restore/revert style command was observed; intent and necessity are unknown.","user_correction":"A user-authored message contained a phrase commonly used to correct prior work; human confirmation needed."}.get(category,"Observable friction signal; inspect the referenced event before inferring cause.")

def _prevention(category:str)->str:
    return {"unsupported_flag":"Check the installed CLI's own help or current official documentation before retrying the rejected option.","shell_path_incompatibility":"Check the active shell, operating system, and path before repeating a failed command.","dependency_mismatch":"Check repository dependency metadata and the documented supported version before changing dependencies.","verification_failure":"Diagnose the failed assertion before retrying; keep necessary verification intact.","mcp_failure":"Inspect the MCP failure and use an available authorized fallback.","failed_tool_call":"Inspect the tool result and choose an authorized fallback after a confirmed failure.","command_retry":"Check why the prior attempt failed before repeating it; retry only after a targeted correction.","corrective_command":"No instruction proposed from a recovered command alone.","repeated_file_inspection":"Reuse already inspected repository context when it is still current; do not suppress necessary verification.","reversal_command_observed":"Review the reason and affected diff after a rollback-style command; do not assume the action was unnecessary.","user_correction":"Review repeated corrections for a specific scope or interpretation failure before adding guidance."}.get(category,"No instruction proposed without human review.")

def run_audit(home:Path,sqlite_home:Path,out:Path,force:bool=False,project_root:Path|None=None)->dict:
    coverage,rollouts=discover(home,sqlite_home)
    db_meta=inspect_sqlite(sqlite_home/"state_5.sqlite",allowed_root=sqlite_home)
    db_meta["missing_rollouts"]=[]
    index_path=home/"session_index.jsonl" if _safe_source(home/"session_index.jsonl",home) else home/"__blocked_session_index__"
    sessions,file_rows=reconcile(home,rollouts,db_meta,index_path)
    events,patterns=friction_and_patterns(file_rows)
    # Read only the exact history JSONL when present; capture coverage and parse errors, never prompt text.
    history_path=home/"history"/"history.jsonl"; history_info={"status":"MISSING","record_count":0,"parse_errors":[]}
    if history_path.is_file() and _safe_source(history_path,home):
        history_info["status"]="READABLE"
        for n,_,err in _line_records(history_path):
            if err:history_info["parse_errors"].append({"line":n,"error":err})
            else:history_info["record_count"]+=1
    out.mkdir(parents=True,exist_ok=True)
    findings=out/"findings"; output=out/"output"; findings.mkdir(exist_ok=True);output.mkdir(exist_ok=True)
    targets=[findings/n for n in ("historical-source-coverage.json","historical-source-coverage.md","session-reconciliation.json","session-reconciliation.md","normalized-friction-events.jsonl","failure-patterns.json","provenance.json","friction-report.md")]+[output/n for n in ("AGENTS.md","CLAUDE.md","instruction-rationale.md","rejected-rules.md")]
    if not force and any(p.exists() for p in targets):raise FileExistsError("Refusing to overwrite: "+", ".join(str(p) for p in targets if p.exists()))
    # Redacted event records only; no raw message or tool output is serialized.
    with (findings/"normalized-friction-events.jsonl").open("w",encoding="utf-8",newline="\n") as f:
        for e in events:f.write(json.dumps(e,ensure_ascii=False,sort_keys=True)+"\n")
    (findings/"failure-patterns.json").write_text(json.dumps(patterns,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
    safe_db=_safe_source(sqlite_home/"state_5.sqlite",sqlite_home)
    rollout_manifest=[{"source_ref":str(f["path"].relative_to(home).as_posix()),"thread_id":f["parsed"]["thread_id"],"sha256":f["parsed"]["sha256"],"byte_count":f["path"].stat().st_size if f["path"].exists() else None,"record_count":f["parsed"]["record_count"],"parse_error_count":len(f["parsed"]["parse_errors"]),"file_changed_during_read":f["parsed"]["file_changed_during_read"],"status":f["parsed"]["status"]} for f in file_rows]
    safe_coverage=[]
    for item in coverage:
        entry=dict(item)
        candidate=Path(str(entry.get("candidate","")))
        try: entry["candidate"]="$CODEX_HOME/"+candidate.relative_to(home).as_posix()
        except ValueError:
            try: entry["candidate"]="$CODEX_SQLITE_HOME/"+candidate.relative_to(sqlite_home).as_posix()
            except ValueError: entry["candidate"]="configured-source"
        safe_coverage.append(entry)
    coverage_doc={"platform":"Windows","codex_home":"$CODEX_HOME","sqlite_home":"$CODEX_SQLITE_HOME" if sqlite_home!=home else "$CODEX_HOME","sources":safe_coverage,"rollout_count":len(rollouts),"rollout_manifest":rollout_manifest,"sqlite_schema_status":db_meta["status"],"sqlite_schema":[{"name":x["name"],"columns":x["columns"]} for x in db_meta["schema"]],"sqlite_snapshot_error":db_meta["error"],"sqlite_table_count":len(db_meta["schema"]),"sqlite_thread_metadata_rows":len(db_meta["threads"]),"sqlite_rows_truncated":db_meta["rows_truncated"],"sqlite_missing_rollout_references":len(db_meta["missing_rollouts"]),"session_index_record_count":sum(1 for _ in _line_records(index_path)) if index_path.is_file() else 0,"session_index_parse_errors":db_meta.get("session_index_errors",[]),"history_source":history_info,"documentation_state":"rollout event structures are implementation-specific and version-sensitive","sqlite_snapshot_note":"Opened read-only with query_only, inspected schema before bounded queries, and used a read transaction. A WAL database is read only when its existing shared-memory sidecar is present; otherwise the audit reports SNAPSHOT_UNAVAILABLE. The read transaction reflects SQLite's available snapshot and may be unavailable if locking or concurrent changes prevent a consistent read.","sqlite_snapshot_consistent":db_meta["status"]=="READ_ONLY_SCHEMA_AND_METADATA_READ","sqlite_home_config_note":"CODEX_HOME and CODEX_SQLITE_HOME were used when present. The allowlist excludes config.toml, so a separate configured sqlite_home value was not read or verified.","sources_read":[x["source_ref"] for x in rollout_manifest]+(["session_index.jsonl"] if index_path.is_file() else [])+(["state_5.sqlite"] if safe_db and (sqlite_home/"state_5.sqlite").is_file() else [])+(["history/history.jsonl"] if history_info["status"]=="READABLE" else [])}
    (findings/"historical-source-coverage.json").write_text(json.dumps(coverage_doc,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
    lines=["# Historical source coverage","","Effective Codex home: `$CODEX_HOME`",f"Rollout files discovered: {len(rollouts)}",f"SQLite metadata rows read: {len(db_meta['threads'])}",f"Sessions reconciled: {len(sessions)}",f"Friction events retained after redaction: {len(events)}","","| Source | Status | Records/files | Details |","|---|---|---:|---|"]
    for s in safe_coverage:lines.append(f"| `{s['source']}` | {s['status']} | {s.get('file_count',s.get('size_bytes','—'))} | {s.get('date_coverage') or s.get('candidate','')} |")
    lines += ["",f"SQLite snapshot status: {db_meta['status']}; schema tables inspected: {len(db_meta['schema'])}; thread rows read: {len(db_meta['threads'])}; missing rollout references: {len(db_meta['missing_rollouts'])}.",f"History log: {history_info['status']}, {history_info['record_count']} valid records.","", "A readable rollout is not proof of complete conversation retention. See session-level coverage classes.","OpenAI's Codex source describes rollout files as JSONL; event envelope details remain implementation-specific. The tool does not interpret model reasoning as evidence.",""]
    (findings/"historical-source-coverage.md").write_text("\n".join(lines),encoding="utf-8")
    fr=["# Historical friction report","",f"Analyzed {len(rollouts)} rollout files and reconciled {len(sessions)} threads/sessions.",f"Retained {len(events)} redacted friction events in the normalized dataset.","","## Event types",""]
    fr += [f"- {k}: {v}" for k,v in sorted(Counter(e["event_type"] for e in events).items())] or ["- No observable friction signals were extracted."]
    fr += ["","## Pattern scope",""]+[f"- {k}: {v}" for k,v in sorted(Counter(p["scope"] for p in patterns).items())]
    fr += ["","Event excerpts and tool outputs are omitted. Each retained event links to a rollout and ordinal in `normalized-friction-events.jsonl`. Model-generated descriptions were not used as independent verification.",""]
    (findings/"friction-report.md").write_text("\n".join(fr),encoding="utf-8")
    (findings/"session-reconciliation.json").write_text(json.dumps(sessions,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
    counts=Counter(s["classification"] for s in sessions)
    rec=["# Session reconciliation","",f"Sessions/threads reconciled: {len(sessions)}","",*[f"- {k}: {v}" for k,v in sorted(counts.items())],"","Readable transcript coverage is bounded by the observed file and its available metadata; no claim of complete historical retention is made.",""]
    (findings/"session-reconciliation.md").write_text("\n".join(rec),encoding="utf-8")
    (findings/"provenance.json").write_text(json.dumps({"codex_cli_version_observed":"0.169.0","evidence_source":"explicitly listed Windows Codex source families","event_count":len(events),"pattern_count":len(patterns),"session_count":len(sessions),"synthetic_fixture_findings_are_not_historical":True,"database_mode":"read-only; no migration or repair","run_determinism":"Deterministic for identical source bytes; fixture repeated-run determinism is tested. Live source files may append between audit runs.","unsupported_assumptions":["Codex rollout payload schemas vary by version; parser is best-effort.","Session metadata may refer to missing files; missing does not prove no conversation existed.","CLI/session index records are projections and model-generated labels are not treated as verification.","The configured sqlite_home value in config.toml was not inspected because config files are outside the allowed source list."],"documentation_sources":["https://github.com/openai/codex/blob/main/codex-rs/rollout/src/recorder.rs","https://github.com/openai/codex/blob/main/codex-rs/state/src/lib.rs","https://github.com/openai/codex/blob/main/codex-rs/config/src/config_toml.rs"]},indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")
    # Lexical correction markers are useful review evidence, but without
    # validated incident-level causes they must never become an instruction.
    correction_patterns=[]
    relevant=[p for p in patterns if p["independent_session_count"]>=2 and p["scope"] in ("GLOBAL","PROJECT") and p["category"] not in ("corrective_command","user_correction")]
    # Only cross-project evidence or a pattern in this repository may contribute rules.
    configured_root=project_root or next((p for p in Path(__file__).resolve().parents if (p/"pyproject.toml").is_file()),Path.cwd())
    project_root=os.path.normcase(os.path.normpath(str(configured_root.resolve())))
    relevant=[p for p in relevant if p["scope"]=="GLOBAL" or any(next((r["parsed"].get("cwd") for r in file_rows if r["parsed"]["thread_id"]==tid),None) and os.path.normcase(os.path.normpath(next(r["parsed"].get("cwd") for r in file_rows if r["parsed"]["thread_id"]==tid)))==project_root for tid in p["affected_session_ids"])]
    hist_notice="" if relevant or correction_patterns else "> No repeated, attributable historical pattern met the rule-inclusion threshold; no historical rule is proposed.\n\n"
    agents="# Codex project guidance candidate\n\n> Generated from local historical evidence. Review before adoption.\n\n"+hist_notice
    for p in relevant:
        agents+=f"- {p['proposed_prevention']} (observed in {p['independent_session_count']} independent session(s); pattern `{p['pattern_id']}`).\n"
    for p in correction_patterns:
        agents+=f"- When the user explicitly corrects prior work, reconcile the revised acceptance criteria and existing edits before continuing (lexical correction markers occurred in {p['independent_session_count']} sessions; shared cause not established; pattern `{p['pattern_id']}`).\n"
    claude="# Claude review and handoff candidate\n\n> Historical findings are listed only when their recurrence threshold was met. Review before adoption.\n\n## Required manual handoff (workflow baseline, not a historical finding)\n\nClaude specification → Human handoff → Codex implementation → Human handoff → Claude review. Do not assume automated cross-agent communication or shared memory.\n\n"
    if not relevant and not correction_patterns:claude+=hist_notice
    elif relevant:claude+="## Evidence-backed review focus\n\n"+"\n".join(f"- Check for recurrence of {p['category'].replace('_',' ')} (pattern `{p['pattern_id']}`; {p['independent_session_count']} sessions)." for p in relevant)+"\n\n"
    if correction_patterns:claude+="## Repeated user corrections (lexical signal; cause unverified)\n\n"+"\n".join(f"- Check whether corrections identify a revised acceptance condition and compare the implementation against it; marker frequency alone does not establish a shared failure cause (pattern `{p['pattern_id']}`, {p['independent_session_count']} sessions)." for p in correction_patterns)+"\n\n"
    claude+="## Review requirements (workflow baseline, not historical findings)\n\n- Verify version-sensitive behavior against current official documentation.\n- Review the actual diff independently for correctness, scope, security, and regressions.\n- Separate observed facts, inferences, and unverified claims; tie findings to source references.\n- Give targeted repair prompts with acceptance conditions.\n"
    (output/"AGENTS.md").write_text(agents,encoding="utf-8");(output/"CLAUDE.md").write_text(claude,encoding="utf-8")
    rationale="# Instruction rationale\n\nRules are included only for repeated, attributable patterns supported by multiple independent sessions. Project rules from unrelated repositories are excluded. Fixture evidence is excluded.\n\n"+("\n".join(f"- `{p['pattern_id']}` ({p['scope']}): {p['proposed_prevention']} Supported by {p['independent_session_count']} session(s); confidence {p['confidence']}." for p in relevant+correction_patterns) if relevant or correction_patterns else "No historical recommendation met the inclusion threshold; candidate files retain only clearly marked baseline workflow/safety wording.")+"\n"
    (output/"instruction-rationale.md").write_text(rationale,encoding="utf-8")
    accepted_ids={p["pattern_id"] for p in relevant+correction_patterns}
    rejected=[p for p in patterns if p["pattern_id"] not in accepted_ids]
    (output/"rejected-rules.md").write_text("# Rejected recommendations\n\n"+"\n".join(f"- `{p['pattern_id']}` ({p['category']}): not included; lexical correction markers do not establish a repeated root cause or actionable rule." if p["category"]=="user_correction" else f"- `{p['pattern_id']}` ({p['category']}): not included; fewer than two attributable independent sessions, scope mismatch, or event does not imply preventable friction." for p in rejected)+("\n" if rejected else "- None.\n"),encoding="utf-8")
    return {"coverage":coverage_doc,"sessions":sessions,"events":events,"patterns":patterns,"sqlite":db_meta,"history":history_info}
