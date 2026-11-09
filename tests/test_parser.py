from analyzer.parser import group_entries, parse_lines

POOL_ERROR = """09-Nov-2026 08:05:12.481 SEVERE [http-nio-8080-exec-3] org.apache.catalina.core.StandardWrapperValve.invoke Servlet.service() threw exception
org.springframework.jdbc.CannotGetJdbcConnectionException: Failed to obtain JDBC Connection
\tat org.springframework.jdbc.datasource.DataSourceUtils.getConnection(DataSourceUtils.java:84)
Caused by: org.apache.tomcat.jdbc.pool.PoolExhaustedException: [http-nio-8080-exec-3] Timeout: Pool empty.
\tat org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection(ConnectionPool.java:723)
"""

INFO_LINE = "09-Nov-2026 08:00:00.000 INFO [main] org.apache.catalina.startup.Catalina.start Server startup in [4120] milliseconds\n"


def parse(text, min_level="WARNING"):
    return list(parse_lines(text.splitlines(keepends=True), min_level=min_level))


def test_stack_trace_lines_belong_to_their_entry():
    entries = parse(POOL_ERROR)
    assert len(entries) == 1
    assert len(entries[0].trace) == 4


def test_signature_uses_deepest_caused_by():
    entry = parse(POOL_ERROR)[0]
    assert entry.signature == (
        "org.apache.tomcat.jdbc.pool.PoolExhaustedException "
        "at org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection"
    )


def test_info_is_filtered_by_default():
    assert len(parse(INFO_LINE + POOL_ERROR)) == 1
    assert len(parse(INFO_LINE + POOL_ERROR, min_level="INFO")) == 2


def test_messages_differing_only_in_numbers_group_together():
    text = (
        "09-Nov-2026 08:00:01.000 WARNING [main] com.example.Cache.evict Evicted 120 entries in 35 ms\n"
        "09-Nov-2026 08:00:02.000 WARNING [main] com.example.Cache.evict Evicted 7 entries in 4 ms\n"
    )
    groups = group_entries(parse(text))
    assert len(groups) == 1
    assert groups[0].count == 2


def test_groups_sorted_by_severity_then_count():
    text = (
        "09-Nov-2026 08:00:01.000 WARNING [main] com.example.A.run warning one\n"
        "09-Nov-2026 08:00:02.000 WARNING [main] com.example.A.run warning one\n"
        + POOL_ERROR
    )
    groups = group_entries(parse(text))
    assert [g.level for g in groups] == ["SEVERE", "WARNING"]
