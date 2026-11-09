"""Mask sensitive data before log excerpts leave the machine."""
from __future__ import annotations

import re
from typing import Dict

from .parser import LogEntry

SECRET_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)=([^&\s;\"']+)")
URL_RE = re.compile(r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?:(?P<cred>[^@/\s]+)@)?(?P<host>[^:/\s?#\[\]]+)")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PARAM_RE = re.compile(r"(?i)\b(user(?:name)?)=([^&\s;\"']+)")
USER_QUOTED_RE = re.compile(r'(?i)\b(user\s+)"([^"]+)"')


class Masker:
    """Replace sensitive values with stable placeholders such as <host-1>.

    The same value always gets the same placeholder within one Masker, so the
    analysis can still tell that two errors involve the same host or user.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, Dict[str, str]] = {}

    def _token(self, kind: str, value: str) -> str:
        values = self._seen.setdefault(kind, {})
        if value not in values:
            values[value] = f"<{kind}-{len(values) + 1}>"
        return values[value]

    def _mask_url(self, match: re.Match) -> str:
        credentials = "<redacted>@" if match.group("cred") else ""
        return f"{match.group('scheme')}{credentials}{self._token('host', match.group('host'))}"

    def mask(self, text: str) -> str:
        text = SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
        text = URL_RE.sub(self._mask_url, text)
        text = EMAIL_RE.sub(lambda m: self._token("email", m.group(0)), text)
        text = IPV4_RE.sub(lambda m: self._token("ip", m.group(0)), text)
        text = USER_PARAM_RE.sub(lambda m: f"{m.group(1)}={self._token('user', m.group(2))}", text)
        text = USER_QUOTED_RE.sub(lambda m: f'{m.group(1)}"{self._token("user", m.group(2))}"', text)
        return text


def mask_entry(entry: LogEntry, masker: Masker) -> str:
    """Return the entry header and stack trace as masked text."""
    lines = [f"{entry.level} [{entry.thread}] {entry.logger} {entry.message}", *entry.trace]
    return "\n".join(masker.mask(line) for line in lines)
