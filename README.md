# tomcat-log-analyzer

[![CI](https://github.com/didko45/tomcat-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/didko45/tomcat-log-analyzer/actions/workflows/ci.yml)

Groups Tomcat log errors by root cause, masks sensitive data, and asks Claude for the likely cause and what an on-call engineer should check first.

## Example

```
13 entries in 5 groups

COUNT  LEVEL    SIGNATURE
    6  SEVERE   org.apache.tomcat.jdbc.pool.PoolExhaustedException at ...ConnectionPool.borrowConnection
    2  SEVERE   java.lang.OutOfMemoryError at java.base/java.util.Arrays.copyOf
    1  SEVERE   org.postgresql.util.PSQLException at ...ConnectionFactoryImpl.doAuthentication
    3  WARNING  javax.net.ssl.SSLHandshakeException at java.base/sun.security.ssl.Alert.createSSLException
    1  WARNING  ...WebappClassLoaderBase.clearReferencesThreads: The web application [ROOT] appears to ...

[3] org.postgresql.util.PSQLException (SEVERE, x1, confidence: high)
    Likely cause: Database credentials for <user-1> are wrong or have changed. The password is also
    present in the logged JDBC URL, which is a security concern.
    Check first:
      - Verify the DataSource credentials match the current PostgreSQL role for <user-1>.
      - Check whether the password was recently rotated on all instances.
      - Remove credentials from the JDBC URL and rotate the password if it was exposed in logs.
```

## How it works

```
catalina.out ─► parse ─► group by root cause ─► mask ─► Claude (tool use) ─► Markdown report
```

1. **Parse**: reads JULI `OneLineFormatter` logs and attaches stack trace lines to their entry.
2. **Group**: two errors are the same when their deepest `Caused by` and its first frame match; numbers in messages are ignored, so 6 pool timeouts from different threads become one group.
3. **Mask**: hides secrets, hosts, users, emails and IPs with stable placeholders (`<host-1>`), so related errors can still be linked without revealing the values.
4. **Analyze**: sends the top groups in one request so the model can spot relations between them. The reply is forced through a tool with a JSON schema instead of parsing free text.
5. **Report**: writes a masked Markdown report for tickets or hand-over.

## Privacy by design

| Data | Sent as |
| --- | --- |
| `password=...`, `token=...`, `api_key=...` | `<redacted>` |
| Hosts in URLs (`jdbc:`, `https:`) | `<host-N>` |
| Users (`user=...`, `for user "..."`) | `<user-N>` |
| Email addresses | `<email-N>` |
| IPv4 addresses | `<ip-N>` |

- A test asserts that no secret from the sample reaches the API request.
- Java class names are deliberately not treated as host names.
- CI never sees an API key: tests use a fake client and the smoke test runs without `--analyze`.

## Usage

### Local (Python 3.10+)

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...   # only needed for --analyze

python -m analyzer catalina.out                            # group errors
python -m analyzer catalina.out --show-masked 3            # preview what would be sent
python
