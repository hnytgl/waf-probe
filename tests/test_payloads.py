import pytest

from waf_probe.payloads import categories, select_payloads


def test_categories_are_available():
    assert "sqli" in categories()
    assert "xss" in categories()


def test_select_payloads_filters_by_category():
    payloads = select_payloads("sqli,xss")
    assert payloads
    assert {payload.category for payload in payloads} == {"sqli", "xss"}


def test_select_payloads_rejects_unknown_category():
    with pytest.raises(ValueError):
        select_payloads("unknown")
