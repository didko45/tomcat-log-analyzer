from analyzer.parser import group_entries, parse_lines
from analyzer.report import render_markdown

LOG = (
    "09-Nov-2026 08:00:01.000 WARNING [main] com.example.Pay.call Call to https://pay.bank.example/x "
    "failed for john.doe@example.com | retry\n"
)


def test_report_masks_data_and_escapes_table_cells():
    report = render_markdown(group_entries(parse_lines(LOG.splitlines(keepends=True))), ["catalina.out"])
    assert "pay.bank.example" not in report
    assert "john.doe@example.com" not in report
    assert "\\| retry" in report
    assert "1 entries in 1 groups" in report
