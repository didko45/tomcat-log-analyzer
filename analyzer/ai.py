"""Ask Claude for likely root causes of grouped Tomcat errors."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, List, Sequence, Tuple

from .masking import Masker, mask_entry
from .parser import ErrorGroup

DEFAULT_MODEL = os.environ.get("ANALYZER_MODEL", "claude-haiku-5-5")

SYSTEM_PROMPT = """You are a senior production support engineer for Java applications on Apache Tomcat.
You receive groups of errors from Tomcat logs. Sensitive values are masked with placeholders such as <host-1>;
the same placeholder always refers to the same value.
For each group, explain the most likely root cause and what an on-call engineer should check first.
Point out when groups are probably related to each other.
Be specific to Tomcat, the JVM and the libraries in the stack trace. Do not state facts the log does not support.
Report your diagnosis with the report_findings tool."""

# The API enforces this schema, so the reply arrives as a dict instead of free text to parse.
FINDINGS_TOOL = {
    "name": "report_findings",
    "description": "Report the diagnosis for each error group and an overall summary.",
    "input_schema": {
        "type": "object",
        "properties": {
            "groups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "Group number from the input"},
                        "likely_cause": {"type": "string"},
                        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                        "first_checks": {"type": "array", "items": {"type": "string"}},
                        "related_to": {"type": "array", "items": {"type": "integer"}},
                    },
                    "required": ["id", "likely_cause", "confidence", "first_checks"],
                },
            },
            "summary": {"type": "string"},
        },
        "required": ["groups", "summary"],
    },
}


@dataclass
class Finding:
    group: ErrorGroup
    likely_cause: str
    confidence: str
    first_checks: List[str] = field(default_factory=list)
    related_to: List[int] = field(default_factory=list)


def build_prompt(groups: Sequence[ErrorGroup], masker: Masker) -> str:
    """Describe each group with masked data only."""
    parts = []
    for index, group in enumerate(groups, start=1):
        parts.append(
            f"### Group {index}\n"
            f"Level: {group.level}\n"
            f"Occurrences: {group.count} between {group.first_seen:%Y-%m-%d %H:%M:%S} "
            f"and {group.last_seen:%Y-%m-%d %H:%M:%S}\n"
            f"Signature: {masker.mask(group.signature)}\n"
            f"Example:\n{mask_entry(group.example, masker)}\n"
        )
    return "\n".join(parts)


def analyze(
    groups: Sequence[ErrorGroup],
    client: Any = None,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4000,
) -> Tuple[List[Finding], str]:
    """Send masked groups to Claude and return one finding per group plus a summary."""
    if client is None:
        from anthropic import Anthropic  # imported here so tests run without the SDK

        client = Anthropic()  # reads ANTHROPIC_API_KEY from the environment

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=[FINDINGS_TOOL],
        tool_choice={"type": "tool", "name": FINDINGS_TOOL["name"]},
        messages=[{"role": "user", "content": build_prompt(groups, Masker())}],
    )

    if getattr(response, "stop_reason", None) == "max_tokens":
        raise RuntimeError(
            f"The reply was cut off at max_tokens={max_tokens}. Analyze fewer groups or raise the limit."
        )

    data = next(
        (
            block.input
            for block in response.content
            if getattr(block, "type", "") == "tool_use" and block.name == FINDINGS_TOOL["name"]
        ),
        None,
    )
    if data is None:
        raise RuntimeError("The model did not return findings.")

    by_id = {item.get("id"): item for item in data.get("groups", [])}
    findings = []
    for index, group in enumerate(groups, start=1):
        item = by_id.get(index, {})
        findings.append(
            Finding(
                group=group,
                likely_cause=item.get("likely_cause", "No analysis returned for this group."),
                confidence=item.get("confidence", "unknown"),
                first_checks=list(item.get("first_checks", [])),
                related_to=list(item.get("related_to", [])),
            )
        )
    return findings, data.get("summary", "")
