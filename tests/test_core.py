import json
import tempfile
import unittest
from pathlib import Path

from friction_lab.core import analyze, classify, normalize, redact, stable_id

ROOT = Path(__file__).resolve().parents[1]

class CoreTests(unittest.TestCase):
    def test_redaction_and_stable_ids(self):
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", redact("key=sk-abcdefghijklmnopqrstuvwxyz123456"))
        self.assertEqual(stable_id("a", "b"), stable_id("a", "b"))

    def test_malformed_lines_are_skipped_and_reported(self):
        events, errors = normalize(ROOT / "fixtures" / "windows-trace.jsonl")
        self.assertTrue(events)
        self.assertTrue(any(e["error"] == "malformed JSON" for e in errors))

    def test_duplicate_events_same_task_count_once_and_repos_remain_separate(self):
        events = []
        for file in ("windows-trace.jsonl", "linux-trace.jsonl", "unrelated-project.jsonl"):
            events += normalize(ROOT / "fixtures" / file, file)[0]
        patterns = classify(events)
        commands = [p for p in patterns if p["category"] == "command_execution"]
        self.assertEqual(len(commands), 3)
        self.assertTrue(all(p["observed_occurrence_count"] == 1 for p in commands))
        self.assertTrue(all(len(p["repositories"]) == 1 for p in commands))

    def test_ordinary_failed_check_not_automatically_friction(self):
        event = {"event_id":"1","repository":"r","task_id":"t","session_id":"s","command":"pytest","text":"","outcome":"test failed","source_ref":"x","source_type":"execution_trace"}
        self.assertEqual(classify([event]), [])

    def test_reports_are_deterministic_and_templates_do_not_include_fixture_claims(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            sources = [ROOT / "fixtures" / "windows-trace.jsonl"]
            analyze(sources, out, historical=False)
            first = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            analyze(sources, out, historical=False)
            second = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            self.assertEqual(first, second)
            rationale = (out / "output" / "instruction-rationale.md").read_text()
            self.assertIn("No historical-evidence-based rules", rationale)
            self.assertNotIn("unsupported-option", (out / "output" / "AGENTS.md").read_text())
            prov = json.loads((out / "findings" / "provenance.json").read_text())
            self.assertFalse(prov["historical_analysis"])

    def test_source_output_contains_no_credential(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); analyze([ROOT / "fixtures" / "windows-trace.jsonl"], out, historical=False)
            all_text = "".join(p.read_text(errors="ignore") for p in out.rglob("*") if p.is_file())
            self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", all_text)

if __name__ == "__main__": unittest.main()
