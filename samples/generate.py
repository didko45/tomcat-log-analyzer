"""Generate a sample Tomcat catalina.out with typical production failures.

All hosts, users and secrets are fake; they exist to exercise masking.
"""
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

START = datetime(2026, 11, 9, 8, 0, 0)
OUT = Path(__file__).with_name("catalina.out")


def ts(seconds: int) -> str:
    return (START + timedelta(seconds=seconds)).strftime("%d-%b-%Y %H:%M:%S") + ".000"


def info(sec: int, logger_and_message: str) -> List[str]:
    return [f"{ts(sec)} INFO [main] {logger_and_message}"]


def db_auth_failure(sec: int) -> List[str]:
    return [
        f"{ts(sec)} SEVERE [main] org.apache.tomcat.jdbc.pool.ConnectionPool.init Unable to create initial "
        "connections of pool for jdbc:postgresql://db01.prod.internal:5432/orders?user=app_user&password=S3cr3tPass",
        'org.postgresql.util.PSQLException: FATAL: password authentication failed for user "app_user"',
        "\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:693)",
        "\tat org.postgresql.core.v3.ConnectionFactoryImpl.openConnectionImpl(ConnectionFactoryImpl.java:203)",
    ]


def thread_leak(sec: int) -> List[str]:
    return [
        f"{ts(sec)} WARNING [main] org.apache.catalina.loader.WebappClassLoaderBase.clearReferencesThreads "
        "The web application [ROOT] appears to have started a thread named [pool-2-thread-1] but has failed "
        "to stop it. This is very likely to create a memory leak."
    ]


def pool_exhausted(sec: int, worker: int) -> List[str]:
    thread = f"http-nio-8080-exec-{worker}"
    return [
        f"{ts(sec)} SEVERE [{thread}] org.apache.catalina.core.StandardWrapperValve.invoke "
        "Servlet.service() for servlet [orders] in context with path [] threw exception",
        "org.springframework.jdbc.CannotGetJdbcConnectionException: Failed to obtain JDBC Connection",
        "\tat org.springframework.jdbc.datasource.DataSourceUtils.getConnection(DataSourceUtils.java:84)",
        "\tat com.example.orders.OrderRepository.findAll(OrderRepository.java:42)",
        f"Caused by: org.apache.tomcat.jdbc.pool.PoolExhaustedException: [{thread}] Timeout: Pool empty. "
        "Unable to fetch a connection in 30 seconds, none available[size:20; busy:20; idle:0; lastwait:30000].",
        "\tat org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection(ConnectionPool.java:723)",
        "\tat org.apache.tomcat.jdbc.pool.ConnectionPool.getConnection(ConnectionPool.java:198)",
    ]


def ssl_failure(sec: int, worker: int) -> List[str]:
    return [
        f"{ts(sec)} WARNING [http-nio-8080-exec-{worker}] com.example.payments.PaymentClient.charge "
        "Payment gateway call to https://pay.partner-bank.example:443/v2/charge failed for customer "
        "john.doe@example.com from 10.20.30.40",
        "javax.net.ssl.SSLHandshakeException: PKIX path building failed: "
        "unable to find valid certification path to requested target",
        "\tat java.base/sun.security.ssl.Alert.createSSLException(Alert.java:130)",
        "\tat com.example.payments.PaymentClient.charge(PaymentClient.java:57)",
    ]


def out_of_memory(sec: int, worker: int) -> List[str]:
    return [
        f"{ts(sec)} SEVERE [http-nio-8080-exec-{worker}] org.apache.catalina.core.StandardWrapperValve.invoke "
        "Servlet.service() for servlet [reports] in context with path [] threw exception",
        "java.lang.OutOfMemoryError: Java heap space",
        "\tat java.base/java.util.Arrays.copyOf(Arrays.java:3537)",
        "\tat com.example.reports.ReportBuilder.render(ReportBuilder.java:118)",
    ]


def main() -> None:
    lines: List[str] = []
    lines += info(0, "org.apache.catalina.startup.Catalina.start Server startup in [4120] milliseconds")
    lines += db_auth_failure(5)
    lines += thread_leak(30)
    for sec, worker in [(300, 3), (312, 7), (318, 12), (330, 3), (347, 15), (361, 21)]:
        lines += pool_exhausted(sec, worker)
    for sec, worker in [(420, 4), (480, 9), (540, 4)]:
        lines += ssl_failure(sec, worker)
    lines += out_of_memory(900, 11)
    lines += out_of_memory(960, 2)
    lines += info(1000, "org.apache.catalina.core.StandardServer.await A valid shutdown command was "
                        "received via the shutdown port. Stopping the Server instance.")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {OUT}")


if __name__ == "__main__":
    main()
