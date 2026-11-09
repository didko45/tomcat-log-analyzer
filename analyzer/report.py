"""Render the analysis as a Markdown incident report."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence

from .ai import Finding
from .masking import Masker
from .parser import ErrorGroup


def _cell(text: str) -> str:
    """Make text safe for a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(
    groups: Sequence[ErrorGroup],
    sources: Sequence[str],
    findings: Optional[List[Finding]] = None,
    summary: str = "",
    model: Optional[str] = None,
) -> str:
    masker = Masker()
    total = sum(group.count for group in groups)
    lines = [
        "# Tomcat log analysis",
        "",
        f"Generated {datetime.now():%Y-%m-%d %H:%M} from {', '.join(sources)}: "
        f"{total} entries in {len(groups)} groups.",
        "",
    ]

    if summary:
        lines += ["## Summary", "", masker.mask(summary), ""]

    lines += [
        "## Error groups",
        "",
        "| # | Level | Count | First seen | Last seen | Signature |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for index, group in enumerate(groups, start=1):
        lines.append(
            f"| {index} | {group.level} | {group.count} | {group.first_seen:%Y-%m-%d %H:%M:%S} | "
            f"{group.last_seen:%Y-%m-%d %H:%M:%S} | {_cell(masker.mask(group.signature))} |"
        )
    lines.append("")

    if findings:
        lines += ["## Findings", ""]
        for index, finding in enumerate(findings, start=1):
            lines += [
                f"### {index}. {masker.mask(finding.group.signature)}",
                "",
                f"**Confidence:** {finding.confidence}",
                "",
                f"**Likely cause:** {finding.likely_cause}",
                "",
            ]
            if finding.first_checks:
                lines += ["**Check first:**", ""]
                lines += [f"- {check}" for check in finding.first_checks]
                lines.append("")
            if finding.related_to:
                related = ", ".join(str(number) for number in finding.related_to)
                lines += [f"**Related to groups:** {related}", ""]
        lines += [
            "---",
            "",
            f"*Analysis by {model} on masked data. Treat findings as hypotheses to verify, not conclusions.*",
            "",
        ]
    return "\n".join(lines)
