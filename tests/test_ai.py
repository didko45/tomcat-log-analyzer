from types import SimpleNamespace

import pytest

from analyzer.ai import analyze
from analyzer.parser import group_entries, parse_lines

LOG = """09-Nov-2026 08:00:05.000 SEVERE [main] org.apache.tomcat.jdbc.pool.ConnectionPool.init Unable to create initial connections of pool for jdbc:postgresql://db01.prod.internal:5432/orders?user=app_user&password=S3cr3tPass
org.postgresql.util.PSQLException: FATAL: password authentication failed for user "app_user"
\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:693)
"""

FINDINGS = {
    "groups": [{
        "id": 1,
        "likely_cause": "Wrong database password for <user-1>.",
        "confidence": "high",
        "first_checks": ["Check the datasource password", "Check recent credential rotation"],
        "related_to": [],
    }],
    "summary": "Database credentials are wrong.",
}


class FakeClient:
    """Stands in for anthropic.Anthropic: records the request, returns a canned tool call."""

    def __init__(self, findings=FINDINGS, stop_reason="tool_use"):
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)
        self._findings = findings
        self._stop_reason = stop_reason

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        block = SimpleNamespace(type="tool_use", name="report_findings", input=self._findings)
        return SimpleNamespace(content=[block], stop_reason=self._stop_reason)


def groups():
    return group_entries(parse_lines(LOG.splitlines(keepends=True)))


def test_no_secrets_leave_the_machine():
    client = FakeClient()
    analyze(groups(), client=client)
    sent = client.requests[0]["messages"][0]["content"]
    for secret in ["S3cr3tPass", "db01.prod.internal", "app_user"]:
        assert secret not in sent


def test_model_is_forced_to_use_the_findings_tool():
    client = FakeClient()
    analyze(groups(), client=client)
    assert client.requests[0]["tool_choice"] == {"type": "tool", "name": "report_findings"}


def test_tool_input_is_mapped_to_findings():
    findings, summary = analyze(groups(), client=FakeClient())
    assert findings[0].confidence == "high"
    assert findings[0].first_checks[0] == "Check the datasource password"
    assert summary == "Database credentials are wrong."


def test_truncated_reply_gives_a_clear_error():
    with pytest.raises(RuntimeError, match="cut off"):
        analyze(groups(), client=FakeClient(stop_reason="max_tokens"))
