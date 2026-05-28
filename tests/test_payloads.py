import pytest

from waf_probe.payloads import categories, select_payloads


def test_categories_are_available():
    assert "sqli" in categories()
    assert "xss" in categories()
    assert "sensitive-file" in categories()
    assert "admin-path" in categories()


def test_select_payloads_filters_by_category():
    payloads = select_payloads("sqli,xss")
    assert payloads
    assert {payload.category for payload in payloads} == {"sqli", "xss"}


def test_select_payloads_rejects_unknown_category():
    with pytest.raises(ValueError):
        select_payloads("unknown")


def test_rule_set_has_broad_coverage():
    expected = {
        "api-docs",
        "backup-file",
        "crlf-injection",
        "deserialization",
        "framework-debug",
        "graphql",
        "ldap-injection",
        "log-file",
        "nosql",
        "xxe",
    }
    assert expected.issubset(set(categories()))
