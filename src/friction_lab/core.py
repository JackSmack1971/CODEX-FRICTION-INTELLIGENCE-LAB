"""Bounded, deterministic transcript ingestion and friction reporting."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

MAX_LINE_BYTES = 2_000_000
SECRET = re.compile(r"(?i)(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|(?:(?:api[_-]?key|password|token|secret)\s*[:=]\s*)[^\s,;]{6,})")
RULES = [
    ("command_execution", re.compile(r"unknown (?:option|flag)|unrecognized arguments|unknown argument", re.I), "Confirm command options from its local help or official documentation before retrying.", "ENVIRONMENT"),
    ("shell_environment", re.compile(r"not recognized as (?:an internal|the name)|command not found|is not recognized", re.I), "Check the active shell and platform before choosing command syntax.", "ENVIRONMENT"),
    ("tool_mcp_failure", re.compile(r"mcp.{0,30}(?:error|failed|timeout)|tool call failed", re.I), "Record the tool failure and use an available, authorized fallback.", "WORKFLOW"),
    ("dependency_api", re.compile(r"module not found|no module named|cannot find module|package .* not found", re.I), "Verify dependency and API availability from project metadata and authoritative documentation.", "GLOBAL"),
    ("scope_drift", re.compile(r"out of scope|unrelated file|scope drift", re.I), "Compare planned edits with the user-approved scope before changing files.", "GLOBAL"),
    ("verification", re.compile(r"test failed|assertionerror|verification failed", re.I), None, "GLOBAL"),
    ("git_state", re.compile(r"not a git repository|working tree .*dirty|merge conflict", re.I), "Inspect repository state before source-control operations.", "GLOBAL"),
]
TAXONOMY = ["command_execution", "shell_environment", "tool_mcp_failure", "missing_context", "incorrect_assumption", "dependency_api", "verification", "git_state", "scope_drift", "multi_agent", "handoff", "documentation_control"]

def stable_id(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()[:20]

def redact(text: str) -> str:
    return SECRET.sub("[REDACTED]", text)

def iter_jsonl(path: Path) -> Iterator[tuple[int, dict | None, str | None]]:
    """Stream line records, skipping unsafe-sized/malformed rows without aborting."""
    with path.open("rb") as stream:
        for line_no, raw in enumerate(stream, 1):
            if len(raw) > MAX_LINE_BYTES:
                yield line_no, None, "line exceeds 2 MB limit"
                continue
            try:
                row = json.loads(raw)
                if isinstance(row, dict):
                    yield line_no, row, None
                else:
                    yield line_no, None, "record is not an object"
            except (json.JSONDecodeError, UnicodeDecodeError):
                yield line_no, None, "malformed JSON"

def normalize(path: Path, repo: str = "unknown", source_type: str = "execution_trace") -> tuple[list[dict], list[dict]]:
    events, errors = [], []
    for line, row, error in iter_jsonl(path):
        if error:
            errors.append({"line": line, "error": error})
            continue
        assert row is not None
        # Deliberately consume visible event fields only; never infer hidden reasoning.
        kind = str(row.get("type", row.get("kind", "")))
        payload = row.get("payload", row)
        if not isinstance(payload, dict):
            continue
        # Codex rollout JSONL is an implementation-specific adapter, not a stable public contract.
        if kind in {"response_item", "event_msg"}:
            payload = payload.get("item", payload.get("message", payload))
            if not isinstance(payload, dict):
                continue
        tool = payload.get("tool_name", payload.get("name", ""))
        command = payload.get("command", payload.get("cmd", ""))
        content = payload.get("content", payload.get("text", payload.get("output", "")))
        if isinstance(content, list):
            content = " ".join(str(x.get("text", "")) for x in content if isinstance(x, dict))
        event = {
            "event_id": stable_id(str(path.resolve()), str(line), json.dumps(row, sort_keys=True, default=str)),
            "source_id": stable_id(str(path.resolve())), "source_ref": f"{path.name}#L{line}",
            "source_type": source_type, "session_id": str(row.get("session_id", payload.get("session_id", "unknown"))),
            "task_id": str(row.get("task_id", payload.get("task_id", "unknown"))),
            "repository": repo, "timestamp": row.get("timestamp", row.get("ts")), "time_precision": "source-provided" if row.get("timestamp", row.get("ts")) else "unknown",
            "actor": str(payload.get("role", payload.get("actor", "unknown"))), "tool": redact(str(tool))[:120],
            "command": redact(str(command))[:500], "outcome": str(payload.get("status", payload.get("outcome", "unknown"))),
            "text": redact(str(content))[:1000],
        }
        events.append(event)
    return events, errors

def classify(events: list[dict]) -> list[dict]:
    patterns: dict[str, list[dict]] = defaultdict(list)
    # Repeated summaries of one task/session do not create independent occurrences.
    seen_incidents: set[tuple[str, str, str]] = set()
    for e in events:
        evidence = " ".join((e["command"], e["text"], e["outcome"]))
        category, instruction, scope = None, None, "GLOBAL"
        for name, regex, advice, rule_scope in RULES:
            if regex.search(evidence):
                category, instruction, scope = name, advice, rule_scope
                break
        if category is None:
            continue
        if category == "verification":
            # A single failed check is normal iteration absent evidence of redundant retries.
            if not re.search(r"retry|again|repeated", evidence, re.I):
                continue
        incident = (category, e["repository"], e["task_id"] if e["task_id"] != "unknown" else e["session_id"])
        if incident in seen_incidents:
            continue
        seen_incidents.add(incident)
        # Keep repositories separated until evidence supports a shared root cause.
        patterns[f"{category}\0{e['repository']}"].append({**e, "category": category, "instruction": instruction, "scope": scope})
    out = []
    for _, hits in sorted(patterns.items()):
        category = hits[0]["category"]
        scope = hits[0]["scope"]
        repos = sorted({h["repository"] for h in hits})
        occurrences = len(hits)
        out.append({
            "pattern_id": stable_id(category, *sorted(h["event_id"] for h in hits)), "category": category,
            "affected_task_ids": sorted({h["task_id"] for h in hits}),
            "supporting_evidence": [{"event_id": h["event_id"], "source_ref": h["source_ref"], "source_type": h["source_type"]} for h in hits],
            "repositories": repos, "observed_occurrence_count": occurrences,
            "root_cause_hypothesis": f"Recurring {category.replace('_', ' ')} event; heuristic classification only; root cause requires human review.",
            "confidence": "medium" if occurrences > 1 else "low", "uncertainty": "Observed event text is not independent root-cause verification; unknown task IDs reduce deduplication confidence.",
            "proposed_prevention": hits[0]["instruction"] or "Review this event for avoidability; no instruction proposed from this evidence alone.",
            "scope": scope if scope != "GLOBAL" else ("PROJECT" if repos != ["unknown"] else scope),
            "documentation_verification": "not_verified", "expected_benefit": "fewer repeated failures if the hypothesis is confirmed",
            "potential_negative_consequences": "Overgeneralization may add unnecessary process; verify scope and recurrence before adoption.",
        })
    return out

def write_reports(events: list[dict], patterns: list[dict], errors: list[dict], out: Path, historical: bool, provenance: dict) -> None:
    findings, output = out / "findings", out / "output"
    findings.mkdir(parents=True, exist_ok=True); output.mkdir(parents=True, exist_ok=True)
    (findings / "failure-patterns.json").write_text(json.dumps(patterns, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    provenance.update({"event_count": len(events), "pattern_count": len(patterns), "parse_errors": errors, "historical_analysis": historical, "synthetic_fixture_findings_are_not_user_history": True})
    (findings / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = ["# Friction report", "", f"Evidence events: {len(events)}. Patterns: {len(patterns)}.", "", "Historical evidence was not read unless a source was explicitly configured and authorized.", "Synthetic fixture results, if used, are not findings about the user's history.", "", "## Findings", ""]
    if patterns:
        for p in patterns:
            rows += [f"### {p['category']} ({p['observed_occurrence_count']} incident(s); {p['confidence']} confidence)", "", p["root_cause_hypothesis"], "", f"Scope: {p['scope']}. Documentation: {p['documentation_verification']}.", f"Prevention proposal: {p['proposed_prevention']}", "Evidence: " + ", ".join(x["source_ref"] for x in p["supporting_evidence"]), ""]
    else:
        rows += ["No friction patterns were established from the supplied corpus.", "", "Coverage limitation: no authorized historical Codex records were analyzed; generated instructions are baseline templates, not historically optimized.", ""]
    if errors: rows += ["## Skipped malformed records", "", *(f"- Line {e['line']}: {e['error']}" for e in errors), ""]
    rows += ["## Limitations", "", "Heuristic classification does not independently verify root causes. Rollout JSONL interpretation is implementation-specific and may not cover all Codex versions. Necessary iteration is not classified as friction solely because a command failed.", ""]
    (findings / "friction-report.md").write_text("\n".join(rows), encoding="utf-8")
    agents = """# Codex project guidance candidate\n\n> Baseline template, not historically optimized. Review and merge manually; generated outside the owner-controlled seed file.\n\n- Inspect repository instructions, structure, and current source-control state before editing.\n- Keep changes within the user's approved scope; confirm before expanding it.\n- Check the active operating system, shell, and runtime before selecting commands.\n- Verify unfamiliar CLI flags and dependencies using local help or authoritative current documentation.\n- Select verification that covers the changed behavior; report exact commands and observed outcomes. Do not weaken security or verification requirements to save time.\n- Preserve unrelated work and never modify historical execution records.\n- Delegate only bounded independent work with explicit inputs, outputs, and review of returned changes.\n"""
    claude = """# Claude review and handoff candidate\n\n> Baseline template, not historically optimized. Review and merge manually; generated outside the owner-controlled seed file.\n\n## Manual handoff\n\nClaude specification → Human handoff → Codex implementation → Human handoff → Claude review. Do not assume automated cross-agent communication or shared memory.\n\n## Specification and review\n\n- Verify version-sensitive behavior against current official documentation and cite the source.\n- Give Codex a bounded implementation prompt with scope, acceptance criteria, verification commands, and stop conditions. Resolve material ambiguity before implementation.\n- Review Codex's actual diff independently for correctness, scope drift, security, and regressions.\n- Separate observed facts, inferences, and unverified claims. Tie findings to files, lines, and reproducible evidence.\n- Provide targeted repair prompts that identify the finding and its acceptance condition.\n"""
    (output / "AGENTS.md").write_text(agents, encoding="utf-8")
    (output / "CLAUDE.md").write_text(claude, encoding="utf-8")
    included = [p for p in patterns if historical and p["observed_occurrence_count"] > 1 and p["proposed_prevention"].startswith("Confirm")]
    rationale = "# Instruction rationale\n\nGenerated instructions are baseline templates because no authorized historical corpus was provided. Fixture classifications are excluded from instruction evidence.\n\n"
    if included: rationale += "Evidence-supported proposals:\n" + "\n".join(f"- {p['category']}: {p['proposed_prevention']} ({p['observed_occurrence_count']} deduplicated incidents)." for p in included) + "\n"
    else: rationale += "No historical-evidence-based rules were included.\n"
    (output / "instruction-rationale.md").write_text(rationale, encoding="utf-8")
    (output / "rejected-rules.md").write_text("# Rejected rules\n\n- No synthetic fixture finding was promoted into candidate instructions.\n- A failed verification without retry evidence was treated as ordinary engineering iteration, not friction.\n- Similar messages from different projects are not merged into one root cause.\n- Unverified root causes and documentation claims were not presented as facts.\n", encoding="utf-8")

def analyze(paths: Iterable[Path], out: Path, historical: bool = True, repos: dict[str, str] | None = None, source_type: str = "execution_trace") -> None:
    events, errors = [], []
    for path in paths:
        ev, err = normalize(path, (repos or {}).get(str(path), "unknown"), source_type)
        events.extend(ev); errors.extend({"source": path.name, **x} for x in err)
    patterns = classify(events)
    sources = []
    for p in paths:
        digest = hashlib.sha256(); count = 0
        with p.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""): digest.update(chunk)
        for _ in iter_jsonl(p): count += 1
        sources.append({"name": p.name, "type": source_type, "sha256": digest.hexdigest(), "record_count": count})
    provenance = {"schema_version": 1, "sources": sources, "codex_cli_version_observed": "0.169.0", "documentation_sources": ["https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide", "https://developers.openai.com/api/docs/guides/agents-api/overview", "https://developers.openai.com/api/docs/guides/agents-api/environments/security"], "coverage_note": "No local historical records have been read by the default run."}
    write_reports(events, patterns, errors, out, historical, provenance)
