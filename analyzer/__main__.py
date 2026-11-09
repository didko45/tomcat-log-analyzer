"""Command-line entry point: python -m analyzer <log files>."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .masking import Masker, mask_entry
from .parser import LogEntry, group_entries, parse_lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tomcat-log-analyzer",
        description="Group Tomcat log errors by root cause and optionally ask Claude for a diagnosis.",
    )
    parser.add_argument("logs", nargs="+", type=Path, help="catalina.out or other JULI log files")
    parser.add_argument("--min-level", default="WARNING", choices=["SEVERE", "WARNING", "INFO"])
    parser.add_argument(
        "--show-masked", type=int, default=0, metavar="N",
        help="print the masked example of the top N groups (what would be sent for analysis)",
    )
    parser.add_argument(
        "--analyze", type=int, default=0, metavar="N",
        help="send the top N groups (masked) to Claude for root-cause analysis; needs ANTHROPIC_API_KEY",
    )
    parser.add_argument("--report", type=Path, metavar="PATH", help="write a masked Markdown report")
    args = parser.parse_args(argv)

    entries: List[LogEntry] = []
    for path in args.logs:
        with path.open(encoding="utf-8", errors="replace") as handle:
            entries.extend(parse_lines(handle, min_level=args.min_level))

    groups = group_entries(entries)
    print(f"{len(entries)} entries in {len(groups)} groups\n")
    print(f"{'COUNT':>5}  {'LEVEL':<8} {'FIRST SEEN':<19}  {'LAST SEEN':<19}  SIGNATURE")
    for group in groups:
        print(
            f"{group.count:>5}  {group.level:<8} "
            f"{group.first_seen:%Y-%m-%d %H:%M:%S}  {group.last_seen:%Y-%m-%d %H:%M:%S}  "
            f"{group.signature}"
        )

    if args.show_masked:
        masker = Masker()
        for group in groups[: args.show_masked]:
            print(f"\n--- {group.signature} (x{group.count}) ---")
            print(mask_entry(group.example, masker))

    findings, summary, model = None, "", None
    if args.analyze and groups:
        from .ai import DEFAULT_MODEL, analyze

        model = DEFAULT_MODEL
        findings, summary = analyze(groups[: args.analyze])
        print(f"\n=== Analysis by {model} ===")
        for index, finding in enumerate(findings, start=1):
            group = finding.group
            print(f"\n[{index}] {group.signature}")
            print(f"    {group.level}, x{group.count}, confidence: {finding.confidence}")
            print(f"    Likely cause: {finding.likely_cause}")
            if finding.first_checks:
                print("    Check first:")
                for check in finding.first_checks:
                    print(f"      - {check}")
            if finding.related_to:
                print(f"    Related to groups: {', '.join(str(n) for n in finding.related_to)}")
        if summary:
            print(f"\nSummary: {summary}")

    if args.report:
        from .report import render_markdown

        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            render_markdown(groups, [p.name for p in args.logs], findings, summary, model),
            encoding="utf-8",
        )
        print(f"\nReport written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
