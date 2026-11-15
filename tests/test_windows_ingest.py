import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from friction_lab.windows_ingest import (
    discover, friction_and_patterns, inspect_sqlite, parse_rollout, reconcile, resolve_home,
    resolve_sqlite_home, run_audit, _command_signature,
)

def write_jsonl(path, rows, final_newline=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw="".join(json.dumps(row)+"\n" for row in rows)
    if not final_newline: raw=raw.rstrip("\n")
    path.write_text(raw,encoding="utf-8")

class WindowsIngestTests(unittest.TestCase):
    def test_home_resolution_uses_env_then_windows_default(self):
        home,source=resolve_home({"CODEX_HOME":"D:/codex-data","USERPROFILE":"C:/Users/example"})
        self.assertEqual(home,Path("D:/codex-data").resolve());self.assertEqual(source,"CODEX_HOME")
        home,source=resolve_home({"USERPROFILE":"C:/Users/example"})
        self.assertEqual(home,Path("C:/Users/example/.codex").resolve())
        db,source=resolve_sqlite_home(home,{"CODEX_SQLITE_HOME":"D:/state"})
        self.assertEqual(db,Path("D:/state").resolve())

    def test_discovery_only_enumerates_allowlisted_locations(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"2025"/"01"/"02"/"rollout-a.jsonl"
            write_jsonl(p,[{"type":"session_meta","payload":{"id":"t"}}])
            (h/"other-private-data").mkdir()
            report,files=discover(h,h)
            self.assertEqual(files,[p]);self.assertEqual(next(x for x in report if x["source"]=="sessions")["file_count"],1)
            self.assertNotIn("other-private-data",json.dumps(report))

    def test_rollout_stream_detects_fail_retry_recovery_reinspection_and_correction(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"2025"/"01"/"02"/"rollout-a.jsonl"
            rows=[
                {"type":"session_meta","ordinal":0,"timestamp":"2025-01-02T00:00:00Z","payload":{"id":"thread-a","session_id":"session-a","cwd":"C:\\work\\repo"}},
                {"type":"response_item","ordinal":1,"payload":{"type":"custom_tool_call","name":"exec","call_id":"c1","input":"codex --not-real"}},
                {"type":"response_item","ordinal":2,"payload":{"type":"custom_tool_call_output","call_id":"c1","output":"error: unknown option --not-real; sk-abcdefghijklmnopqrstuvwxyz123456"}},
                {"type":"response_item","ordinal":3,"payload":{"type":"custom_tool_call","name":"exec","call_id":"c2","input":"codex --not-real"}},
                {"type":"response_item","ordinal":4,"payload":{"type":"custom_tool_call_output","call_id":"c2","output":"Exit code: 0"}},
                {"type":"response_item","ordinal":5,"payload":{"type":"custom_tool_call","name":"exec","call_id":"c3","input":"Get-Content .\\README.md"}},
                {"type":"response_item","ordinal":6,"payload":{"type":"custom_tool_call","name":"exec","call_id":"c4","input":"Get-Content .\\README.md"}},
                {"type":"response_item","ordinal":7,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"As I said, do not change the API"}]}},
                {"type":"response_item","ordinal":8,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Could you add a parser for this input?"}]}},
                {"type":"event_msg","ordinal":9,"payload":{"type":"task_complete"}},
            ]
            write_jsonl(p,rows)
            parsed=parse_rollout(p,h)
            types={e["event_type"] for e in parsed["events"]}
            self.assertTrue({"unsupported_flag","command_retry","corrective_command","repeated_file_inspection","user_correction"}<=types)
            self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456",json.dumps(parsed["events"]))
            self.assertEqual(parsed["thread_id"],"thread-a")
            self.assertTrue(parsed["terminal_seen"])
            self.assertEqual(sum(e["event_type"]=="user_correction" for e in parsed["events"]),1)

    def test_rollout_failure_taxonomy_and_source_event_identity(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-errors.jsonl"
            rows=[{"type":"session_meta","ordinal":0,"payload":{"id":"t","cwd":"C:\\repo"}}]
            cases=[("dependency_mismatch","exec","python -m pip show missing","No module named missing\nexit_code=1"),("shell_path_incompatibility","exec","missing-tool","missing-tool is not recognized as an internal command"),("verification_failure","exec","pytest","FAILED tests/test_x.py; AssertionError\nexit_code=1"),("mcp_failure","mcp__search.query","query","tool call failed")]
            ordinal=1
            for expected,tool,command,result in cases:
                call=f"c{ordinal}"
                rows.append({"type":"response_item","ordinal":ordinal,"payload":{"type":"custom_tool_call","id":f"item{ordinal}","name":tool,"call_id":call,"input":command}})
                rows.append({"type":"response_item","ordinal":ordinal+1,"payload":{"type":"custom_tool_call_output","id":f"out{ordinal}","call_id":call,"output":result}})
                ordinal+=2
            rows.append({"type":"response_item","ordinal":ordinal,"payload":{"type":"custom_tool_call","id":"revert","name":"exec","call_id":"revert","input":"git restore src\\app.py"}})
            write_jsonl(p,rows)
            parsed=parse_rollout(p,h);types={e["event_type"] for e in parsed["events"]}
            self.assertTrue(({x[0] for x in cases}|{"reversal_command_observed"})<=types)
            self.assertTrue(all(e.get("source_event_id") for e in parsed["events"]))

    def test_sqlite_schema_inspection_is_read_only_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"state_5.sqlite"
            c=sqlite3.connect(p)
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript("CREATE TABLE threads(id TEXT, rollout_path TEXT, cwd TEXT); INSERT INTO threads VALUES ('t1','missing.jsonl','C:/work');")
            c.commit()
            c.execute("INSERT INTO threads VALUES ('t2','missing2.jsonl','C:/work')");c.commit()
            protected=[p,Path(str(p)+"-wal"),Path(str(p)+"-shm"),Path(str(p)+"-journal")]
            before={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in protected if x.exists()}
            shm_before=Path(str(p)+"-shm").read_bytes()
            try:
                result=inspect_sqlite(p,max_rows=5)
                after={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in protected if x.exists()}
                self.assertTrue(Path(str(p)+"-wal").exists())
                self.assertTrue(Path(str(p)+"-shm").exists())
                self.assertEqual(before[str(p)],after[str(p)])
                self.assertEqual(before[str(p)+"-wal"],after[str(p)+"-wal"])
                self.assertIn(str(p)+"-shm",before);self.assertIn(str(p)+"-shm",after)
                shm_after=Path(str(p)+"-shm").read_bytes()
                self.assertEqual(len(shm_before),len(shm_after))
                # SQLite's WAL-index read marks are volatile coordination bytes;
                # the rest of the hashed shared-memory file must be unchanged.
                stable_before=hashlib.sha256(shm_before[:96]+shm_before[128:]).hexdigest()
                stable_after=hashlib.sha256(shm_after[:96]+shm_after[128:]).hexdigest()
                self.assertEqual(stable_before,stable_after)
                self.assertEqual(result["status"],"READ_ONLY_SCHEMA_AND_METADATA_READ")
                self.assertIn("threads",{x["name"] for x in result["schema"]})
                self.assertEqual([x["id"] for x in result["threads"]],["t1","t2"])
                self.assertEqual(result["threads"][0]["rollout_path"],"missing.jsonl")
            finally:c.close()

    def test_sqlite_refuses_wal_without_existing_shm_without_creating_sidecars(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"state_5.sqlite"
            c=sqlite3.connect(p);c.execute("CREATE TABLE threads(id TEXT,rollout_path TEXT)");c.commit();c.close()
            wal=Path(str(p)+"-wal");wal.write_bytes(b"fixture WAL marker")
            before={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (p,wal)}
            result=inspect_sqlite(p)
            after={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (p,wal)}
            self.assertEqual(result["status"],"SNAPSHOT_UNAVAILABLE")
            self.assertEqual(before,after)
            self.assertFalse(Path(str(p)+"-shm").exists())

    def test_threads_metadata_reference_missing_rollout_without_repair(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";dbpath=h/"state_5.sqlite";dbpath.parent.mkdir(parents=True)
            c=sqlite3.connect(dbpath)
            c.execute("CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT)")
            missing=h/"sessions"/"2025"/"01"/"02"/"rollout-missing.jsonl"
            c.execute("INSERT INTO threads VALUES(?,?,?)",("thread-missing",str(missing),"C:/repo"));c.commit();c.close()
            meta=inspect_sqlite(dbpath,allowed_root=h)
            sessions,_=reconcile(h,[],meta,h/"session_index.jsonl")
            self.assertEqual(sessions[0]["classification"],"METADATA_ONLY")
            self.assertTrue(sessions[0]["missing_rollout_file"])
            self.assertEqual(len(meta["missing_rollouts"]),1)
            self.assertFalse(missing.exists())

    def test_reconcile_metadata_only_orphan_and_corrupt_rollout(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";s=h/"sessions";s.mkdir(parents=True)
            good=s/"rollout-good.jsonl";write_jsonl(good,[{"type":"session_meta","payload":{"id":"orphan","cwd":"C:/repo"}}])
            bad=s/"rollout-bad.jsonl"
            bad.parent.mkdir(parents=True,exist_ok=True);bad.write_text('{broken',encoding='utf-8')
            db={"threads":[{"id":"meta-only","rollout_path":str(h/"missing.jsonl"),"cwd":"C:/repo"}],"spawn_edges":[],"missing_rollouts":[]}
            sessions,_=reconcile(h,[good,bad],db,h/"session_index.jsonl")
            byid={x["thread_id"]:x["classification"] for x in sessions}
            self.assertEqual(byid["meta-only"],"METADATA_ONLY")
            self.assertEqual(byid["orphan"],"ORPHANED_ROLLOUT")
            self.assertEqual(byid["unknown"],"UNKNOWN")

    def test_audit_repeated_run_is_deterministic_and_source_safe(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);h=base/".codex";p=h/"sessions"/"2025"/"01"/"02"/"rollout-a.jsonl"
            write_jsonl(p,[{"type":"session_meta","payload":{"id":"t","cwd":"C:/repo"}},{"type":"event_msg","payload":{"type":"task_complete"}}])
            hist=h/"history"/"history.jsonl"
            write_jsonl(hist,[{"text":"private prompt token=tok_test_sensitive_value_123456"}])
            db=h/"state_5.sqlite";c=sqlite3.connect(db);c.execute("CREATE TABLE notes(id INTEGER)");c.commit();c.close()
            source_hash=hashlib.sha256(p.read_bytes()).hexdigest()
            db_hash=hashlib.sha256(db.read_bytes()).hexdigest()
            history_hash=hashlib.sha256(hist.read_bytes()).hexdigest()
            out=base/"out"
            run_audit(h,h,out)
            first={str(x.relative_to(out)):x.read_bytes() for x in out.rglob("*") if x.is_file()}
            with self.assertRaises(FileExistsError):run_audit(h,h,out)
            run_audit(h,h,out,force=True)
            second={str(x.relative_to(out)):x.read_bytes() for x in out.rglob("*") if x.is_file()}
            self.assertEqual(first,second)
            self.assertTrue((out/"findings"/"historical-source-coverage.md").exists())
            self.assertTrue((out/"findings"/"session-reconciliation.json").exists())
            self.assertTrue((out/"findings"/"normalized-friction-events.jsonl").exists())
            self.assertEqual(source_hash,hashlib.sha256(p.read_bytes()).hexdigest())
            self.assertEqual(db_hash,hashlib.sha256(db.read_bytes()).hexdigest())
            self.assertEqual(history_hash,hashlib.sha256(hist.read_bytes()).hexdigest())
            artifact_text="".join(x.read_text(encoding="utf-8",errors="ignore") for x in out.rglob("*") if x.is_file())
            self.assertNotIn("tok_test_sensitive_value_123456",artifact_text)

    def test_duplicate_rollout_projection_is_deduplicated_by_event_identity(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";root=h/"sessions";p1=root/"2025"/"01"/"01"/"rollout-a.jsonl";p2=root/"2025"/"01"/"02"/"rollout-b.jsonl"
            rows=[{"type":"session_meta","ordinal":0,"payload":{"id":"same-thread","cwd":"C:/repo"}},{"type":"response_item","ordinal":1,"payload":{"type":"custom_tool_call","name":"exec","call_id":"c","input":"codex --bad"}},{"type":"response_item","ordinal":2,"payload":{"type":"custom_tool_call_output","call_id":"c","output":"unknown option --bad"}}]
            write_jsonl(p1,rows);write_jsonl(p2,rows)
            _,files=reconcile(h,[p1,p2],{"threads":[],"spawn_edges":[]},h/"session_index.jsonl")
            events,patterns=friction_and_patterns(files)
            self.assertEqual(len(events),1)
            self.assertEqual(len(patterns),1)

    def test_injected_user_context_is_not_counted_as_correction(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-injected.jsonl"
            text="# AGENTS.md instructions for C:\\repo\n<INSTRUCTIONS>Actually, do not change the API.\n</INSTRUCTIONS>\n\nPlease inspect the project."
            write_jsonl(p,[{"type":"session_meta","payload":{"id":"t"}},{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}}])
            self.assertNotIn("user_correction",{e["event_type"] for e in parse_rollout(p,h)["events"]})

    def test_user_correction_skips_large_tagged_and_heading_messages(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-context.jsonl"
            rows=[{"type":"session_meta","payload":{"id":"t"}}]
            for i,text in enumerate(("<user_context>Actually, do not change it</user_context>","# User request\nAs I said, keep the API","As I said, "+("x"*4100))):
                rows.append({"type":"response_item","ordinal":i+1,"payload":{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}})
            write_jsonl(p,rows)
            self.assertNotIn("user_correction",{e["event_type"] for e in parse_rollout(p,h)["events"]})

    def test_live_output_shapes_detect_nonzero_codes_and_inspection_path_errors(self):
        from friction_lab.windows_ingest import _failure_kind
        call={"command":"pytest","tool":"exec"}
        self.assertEqual(_failure_kind(call,[{"type":"input_text","text":"running tests"},{"type":"input_text","text":"exit_code=7"}]),"failed_tool_call")
        self.assertEqual(_failure_kind(call,[{"type":"input_text","text":"{\"output\":\"tests complete\",\"metadata\":{\"exit_code\":1}}"}]),"failed_tool_call")
        self.assertEqual(_failure_kind(call,[{"type":"input_text","text":"{\"exit_code\":2,\"output\":\"tests complete\"}"}]),"failed_tool_call")
        self.assertEqual(_failure_kind(call,'{"metadata":{"exit_code":3},"output":"tests complete"}'),"failed_tool_call")
        self.assertEqual(_failure_kind(call,'EXIT_CODE: 4'),"failed_tool_call")
        inspect={"command":"Get-Content .\\missing.txt","tool":"exec"}
        self.assertEqual(_failure_kind(inspect,[{"type":"input_text","text":"Get-Content : Cannot find path because it does not exist."}]),"failed_tool_call")
        self.assertIsNone(_failure_kind(inspect,[{"type":"input_text","text":"A document says: path not found; failed is just an example."}]))
        self.assertEqual(_failure_kind({"command":"cat missing.txt","tool":"exec"},[{"type":"input_text","text":"cat: missing.txt: No such file or directory"}]),"failed_tool_call")
        self.assertIsNone(_failure_kind(inspect,[{"type":"input_text","text":"path not found is an example from this file"}]))
        self.assertIsNone(_failure_kind({"command":"git status --short","tool":"exec"},"status: failed"))

    def test_dependency_and_verification_text_require_exit_or_status_evidence(self):
        from friction_lab.windows_ingest import _failure_kind
        self.assertIsNone(_failure_kind({"command":"const data = readFile()","tool":"exec"},"No module named missing; test failed"))
        self.assertEqual(_failure_kind({"command":"const data = readFile()","tool":"exec"},'{"output":"No module named missing","metadata":{"exit_code":1}}'),"dependency_mismatch")
        self.assertIsNone(_failure_kind({"command":"pytest","tool":"exec"},"test failed in captured file output"))
        self.assertEqual(_failure_kind({"command":"pytest","tool":"exec"},{"output":"test failed","status":"failed"}),"verification_failure")

    def test_inspection_exit_markers_in_file_data_are_ignored_and_evidence_is_labeled(self):
        from friction_lab.windows_ingest import _failure_kind, _failure_evidence_basis
        content='The file contains "exit_code": 1 and exit_code=7 as examples.'
        for command in ("Get-Content tests/x.py", "rg exit_code tests/x.py"):
            call={"command":command,"tool":"exec"}
            self.assertIsNone(_failure_kind(call,[{"type":"input_text","text":content}]))
        inspect={"command":"Get-Content tests/x.py","tool":"exec"}
        structured=[{"type":"input_text","text":"{\"output\":\"...\",\"metadata\":{\"exit_code\":1}}"}]
        self.assertEqual(_failure_kind(inspect,structured),"failed_tool_call")
        self.assertEqual(_failure_evidence_basis(inspect,structured),"structured exit/status")
        command={"command":"node -e 'run()'","tool":"exec"}
        text_marker="result text includes exit_code=7"
        self.assertEqual(_failure_kind(command,text_marker),"failed_tool_call")
        self.assertEqual(_failure_evidence_basis(command,text_marker),"text exit marker (lower confidence)")
        structured_noninspect=[{"type":"input_text","text":"{\"output\":\"...\",\"metadata\":{\"exit_code\":1}}"}]
        self.assertEqual(_failure_kind(command,structured_noninspect),"failed_tool_call")
        self.assertEqual(_failure_evidence_basis(command,structured_noninspect),"structured exit/status")

    def test_git_status_and_diff_are_not_file_inspection_events(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-git.jsonl"
            rows=[{"type":"session_meta","payload":{"id":"t"}}]
            for i,cmd in enumerate(("git status --short","git diff --stat"),1):
                rows.append({"type":"response_item","ordinal":i,"payload":{"type":"custom_tool_call","name":"exec","call_id":str(i),"input":cmd}})
            write_jsonl(p,rows)
            self.assertNotIn("repeated_file_inspection",{e["event_type"] for e in parse_rollout(p,h)["events"]})

    def test_rollout_identity_uses_sqlite_id_and_records_header_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-x.jsonl"
            write_jsonl(p,[{"type":"session_meta","payload":{"id":"header-id","cwd":"C:/repo"}}])
            meta={"threads":[{"id":"sqlite-id","rollout_path":str(p),"cwd":"C:/repo"}],"spawn_edges":[],"missing_rollouts":[]}
            sessions,_=reconcile(h,[p],meta,h/"session_index.jsonl")
            self.assertEqual(len(sessions),1)
            self.assertEqual(sessions[0]["thread_id"],"sqlite-id")
            self.assertEqual(sessions[0]["session_id"],"sqlite-id")
            self.assertEqual(sessions[0]["classification"],"COMPLETE_WITHIN_OBSERVED_COVERAGE")
            self.assertEqual(sessions[0]["identity_conflicts"][0]["header_thread_id"],"header-id")

    def test_inspection_output_text_is_not_a_failure_signal(self):
        with tempfile.TemporaryDirectory() as d:
            h=Path(d)/".codex";p=h/"sessions"/"rollout-read.jsonl"
            rows=[{"type":"session_meta","payload":{"id":"t"}},
                  {"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"read","input":"Get-Content report.txt"}},
                  {"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"read","output":"The word failed appears in this file. Exception and traceback are examples."}}]
            write_jsonl(p,rows)
            self.assertNotIn("failed_tool_call",{e["event_type"] for e in parse_rollout(p,h)["events"]})

    def test_forward_slash_user_paths_are_redacted(self):
        signature=_command_signature("Get-Content C:/Users/click/private.txt /Users/click/notes.txt")
        self.assertNotIn("click",signature)
        self.assertNotIn("private.txt",signature)

    def test_report_redacts_user_home_paths_and_has_stable_project_root(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);h=base/".codex";p=h/"sessions"/"rollout-a.jsonl"
            write_jsonl(p,[{"type":"session_meta","payload":{"id":"t","cwd":"C:/Users/click/project"}}])
            run_audit(h,h,base/"out",project_root=base/"project")
            text="".join(x.read_text(encoding="utf-8",errors="ignore") for x in (base/"out").rglob("*") if x.is_file())
            self.assertNotIn("C:/Users/click",text)
            self.assertNotIn("C:\\Users\\click",text)
            self.assertIn("$CODEX_HOME",text)

if __name__=="__main__":unittest.main()
