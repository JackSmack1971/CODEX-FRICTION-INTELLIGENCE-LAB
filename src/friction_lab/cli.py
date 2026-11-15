from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from .core import analyze
from .windows_ingest import resolve_home, resolve_sqlite_home, discover, run_audit

def main() -> None:
    parser = argparse.ArgumentParser(prog="friction-lab", description="Analyze explicitly authorized Codex execution evidence.")
    sub = parser.add_subparsers(dest="action", required=True)
    dry = sub.add_parser("discover", help="Report metadata for explicitly configured sources")
    dry.add_argument("--source", action="append", default=[], metavar="PATH", help="candidate source path; metadata only")
    run = sub.add_parser("analyze", help="Analyze JSONL sources; requires --authorize for each source")
    run.add_argument("--source", action="append", default=[], metavar="PATH")
    run.add_argument("--authorize", action="append", default=[], metavar="PATH", help="explicitly authorize reading this exact source")
    run.add_argument("--out", type=Path, default=Path("."))
    run.add_argument("--force", action="store_true", help="allow replacing the generated report/candidate files")
    run.add_argument("--repo", default="unknown", help="repository label for supplied evidence")
    run.add_argument("--source-type", default="execution_trace", choices=["codex_session", "diagnostic_log", "memory_summary", "execution_trace", "git_test", "user_correction"])
    run.add_argument("--fixtures", action="store_true", help="use bundled synthetic fixture set (not user history)")
    win = sub.add_parser("audit-windows", help="discover exact Windows Codex sources; ingestion requires --read-history")
    win.add_argument("--codex-home", type=Path, help="override CODEX_HOME resolution for this run")
    win.add_argument("--sqlite-home", type=Path, help="override CODEX_SQLITE_HOME resolution for this run")
    win.add_argument("--project-root", type=Path, help="repository root used for project-specific evidence matching")
    win.add_argument("--read-history", action="store_true", help="authorize reading only the named Codex history sources")
    win.add_argument("--out", type=Path, default=Path("."))
    win.add_argument("--force", action="store_true", help="replace only the Windows audit output files")
    args = parser.parse_args()
    if args.action == "audit-windows":
        home, _ = resolve_home()
        if args.codex_home: home=args.codex_home.expanduser().resolve()
        sqlite_home, _ = resolve_sqlite_home(home)
        if args.sqlite_home: sqlite_home=args.sqlite_home.expanduser().resolve()
        if not args.read_history:
            coverage, _ = discover(home, sqlite_home)
            print(json.dumps({"effective_codex_home":str(home),"effective_sqlite_home":str(sqlite_home),"metadata_only":True,"sources":coverage},indent=2))
            return
        try:
            report=run_audit(home,sqlite_home,args.out,args.force,args.project_root)
        except FileExistsError as e:
            parser.error(str(e))
        print(json.dumps({"event_count":len(report['events']),"pattern_count":len(report['patterns']),"session_count":len(report['sessions']),"output":str(args.out.resolve())},indent=2))
        return
    if args.action == "discover":
        print(json.dumps([{"candidate": str(Path(p)), "record_type": "jsonl (candidate)", "accessible": Path(p).is_file() and os.access(p, os.R_OK), "record_count": None, "date_coverage": None, "parser_support": "JSONL normalized trace and best-effort Codex rollout events", "authorization_required": True} for p in args.source], indent=2))
        return
    if args.fixtures:
        if args.source: parser.error("--fixtures cannot be combined with --source")
        paths = sorted((Path(__file__).resolve().parents[2] / "fixtures").glob("*.jsonl"))
        _check_outputs(args.out, args.force)
        fixture_repos = {str(p): p.stem.replace("-trace", "") for p in paths}
        analyze(paths, args.out, historical=False, repos=fixture_repos, source_type="execution_trace")
        print(f"Analyzed {len(paths)} synthetic fixture files; no user history read.")
        return
    if not args.source:
        _check_outputs(args.out, args.force)
        analyze([], args.out, historical=False)
        print("No sources supplied; wrote baseline templates and empty evidence reports.")
        return
    allowed = {str(Path(p).resolve()) for p in args.authorize}
    unauthorized = [p for p in args.source if str(Path(p).resolve()) not in allowed]
    if unauthorized: parser.error("source read refused without exact --authorize PATH: " + ", ".join(unauthorized))
    missing = [p for p in args.source if not Path(p).is_file()]
    if missing: parser.error("source missing or inaccessible: " + ", ".join(missing))
    _check_outputs(args.out, args.force)
    analyze([Path(p) for p in args.source], args.out, historical=True, repos={str(Path(p)): args.repo for p in args.source}, source_type=args.source_type)
    print(f"Analyzed {len(args.source)} explicitly authorized source(s).")

def _check_outputs(out: Path, force: bool) -> None:
    targets = [out / "findings" / x for x in ("friction-report.md", "failure-patterns.json", "provenance.json")] + [out / "output" / x for x in ("AGENTS.md", "CLAUDE.md", "instruction-rationale.md", "rejected-rules.md")]
    existing = [str(p) for p in targets if p.exists()]
    if existing and not force:
        raise SystemExit("Refusing to overwrite existing generated output; choose another --out or pass --force: " + ", ".join(existing))

if __name__ == "__main__": main()
