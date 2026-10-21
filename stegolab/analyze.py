"""Isolated worker child entry point, called only by the job supervisor."""
import argparse
import json
import sys
from pathlib import Path

from .analysis.engine import analyze_job, atomic_json, utc_now


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("job_dir", type=Path)
    parser.add_argument("mode", choices=("quick", "deep"))
    args = parser.parse_args()
    try:
        action_file = args.job_dir / 'action.json'
        if action_file.exists():
            from .labs.actions import run_action
            try:
                report = run_action(args.job_dir, json.loads(action_file.read_text()))
            finally:
                action_file.unlink(missing_ok=True)
                (args.job_dir / 'supplied-wordlist.txt').unlink(missing_ok=True)
        else:
            report = analyze_job(args.job_dir, args.mode)
        return 0 if report["status"] == "completed" else 1
    except Exception as exc:
        # A malformed input may crash an optional decoder; supervisor also records
        # process termination. Never print evidence data or environment secrets.
        try:
            atomic_json(args.job_dir / "report.json", {"schema_version": "1.0", "job_id": args.job_dir.name, "mode": args.mode, "status": "failed", "file": {}, "started_at": utc_now(), "completed_at": utc_now(), "analyzers": [], "findings": [], "artifacts": [], "recommendations": [], "errors": [f"{type(exc).__name__}: {str(exc)[:1000]}"]})
        except OSError:
            pass
        print(f"Analysis failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
