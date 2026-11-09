"""Command-line entry point: python -m analyzer <log files>."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .parser import LogEntry, group_entries, parse_lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tomcat-log-analyzer",
        description="Group Tomcat log errors by root cause.",
    )
    parser.add_argument("logs", nargs="+", type=Path, help="catalina.out or other JULI log files")
    parser.add_argument("--min-level", default="WARNING", choices=["SEVERE", "WARNING", "INFO"])
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
