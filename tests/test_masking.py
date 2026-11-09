from analyzer.masking import Masker


def test_jdbc_url_password_host_and_user_are_hidden():
    text = "jdbc:postgresql://db01.prod.internal:5432/orders?user=app_user&password=S3cr3tPass"
    assert Masker().mask(text) == "jdbc:postgresql://<host-1>:5432/orders?user=<user-1>&password=<redacted>"


def test_email_and_ip_are_hidden():
    text = "failed for customer john.doe@example.com from 10.20.30.40"
    assert Masker().mask(text) == "failed for customer <email-1> from <ip-1>"


def test_same_value_keeps_the_same_placeholder():
    masker = Masker()
    assert masker.mask("from 10.0.0.1") == "from <ip-1>"
    assert masker.mask("to 10.0.0.2 and 10.0.0.1") == "to <ip-2> and <ip-1>"


def test_quoted_user_matches_user_parameter():
    masker = Masker()
    masker.mask("user=app_user")
    assert masker.mask('failed for user "app_user"') == 'failed for user "<user-1>"'


def test_java_class_names_are_not_mistaken_for_hosts():
    line = "\tat org.apache.tomcat.jdbc.pool.ConnectionPool.borrowConnection(ConnectionPool.java:723)"
    assert Masker().mask(line) == line
