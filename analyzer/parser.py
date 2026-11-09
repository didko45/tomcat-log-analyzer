"""Parse Tomcat (JULI OneLineFormatter) logs and group errors by signature."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

ENTRY_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST)\s+"
    r"\[(?P<thread>[^\]]*)\]\s+"
    r"(?P<logger>\S+)\s+"
    r"(?P<message>.*)$"
)
EXCEPTION_RE = re.compile(
    r"^(?:Caused by:\s+)?"
    r"(?P<cls>(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*(?:Exception|Error|Throwable))"
    r"(?::\s*(?P<msg>.*))?$"
)
FRAME_RE = re.compile(r"^\s+at\s+(?P<frame>[^\s(]+)")
NUMBER_RE = re.compile(r"\d+")

TS_FORMAT = "%d-%b-%Y %H:%M:%S.%f"
LEVEL_RANK = {
    "FINEST": 0, "FINER": 0, "FINE": 0,
    "CONFIG": 1, "INFO": 1,
    "WARNING": 2,
    "SEVERE": 3,
}


def normalize(text: str) -> str:
    """Replace numbers so that messages differing only in IDs or sizes group together."""
    return NUMBER_RE.sub("<n>", text)


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    thread: str
    logger: str
    message: str
    trace: List[str] = field(default_factory=list)

    def root_cause(self) -> Optional[Tuple[str, Optional[str]]]:
        """Return (exception class, first frame) of the deepest 'Caused by', if any."""
        root_index: Optional[int] = None
        root_class: Optional[str] = None
        for index, line in enumerate(self.trace):
            match = EXCEPTION_RE.match(line)
            if match:
                root_index, root_class = index, match.group("cls")
        if root_class is None or root_index is None:
            return None
        for line in self.trace[root_index + 1:]:
            frame = FRAME_RE.match(line)
            if frame:
                return root_class, frame.group("frame")
        return root_class, None

    @property
    def signature(self) -> str:
        cause = self.root_cause()
        if cause:
            exception_class, frame = cause
            return f"{exception_class} at {frame}" if frame else exception_class
        return f"{self.logger}: {normalize(self.message)}"


@dataclass
class ErrorGroup:
    signature: str
    level: str
    count: int
    first_seen: datetime
    last_seen: datetime
    example: LogEntry


def parse_lines(lines: Iterable[str], min_level: str = "WARNING") -> Iterator[LogEntry]:
    """Yield log entries at or above min_level, with their stack trace lines attached."""
    threshold = LEVEL_RANK[min_level]
    current: Optional[LogEntry] = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        match = ENTRY_RE.match(line)
        if match:
            if current is not None and LEVEL_RANK[current.level] >= threshold:
                yield current
            current = LogEntry(
                timestamp=datetime.strptime(match.group("ts"), TS_FORMAT),
                level=match.group("level"),
                thread=match.group("thread"),
                logger=match.group("logger"),
                message=match.group("message"),
            )
        elif current is not None and line.strip():
            current.trace.append(line)
    if current is not None and LEVEL_RANK[current.level] >= threshold:
        yield current


def group_entries(entries: Iterable[LogEntry]) -> List[ErrorGroup]:
    """Group entries by signature; most severe first, then most frequent."""
    groups: Dict[str, ErrorGroup] = {}
    for entry in entries:
        group = groups.get(entry.signature)
        if group is None:
            groups[entry.signature] = ErrorGroup(
                signature=entry.signature,
                level=entry.level,
                count=1,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
                example=entry,
            )
            continue
        group.count += 1
        group.first_seen = min(group.first_seen, entry.timestamp)
        group.last_seen = max(group.last_seen, entry.timestamp)
        if LEVEL_RANK[entry.level] > LEVEL_RANK[group.level]:
            group.level = entry.level
    return sorted(groups.values(), key=lambda g: (-LEVEL_RANK[g.level], -g.count))
