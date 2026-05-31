import pytest

from waf_probe.payloads import MIN_PAYLOADS_PER_CATEGORY, categories, select_payloads


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


def test_sqli_payloads_have_broad_variants():
    payloads = select_payloads("sqli")
    names = {payload.name for payload in payloads}

    assert len(payloads) >= MIN_PAYLOADS_PER_CATEGORY
    assert {
        "url_encoded_or_true",
        "double_url_encoded_or_true",
        "comment_split_union",
        "inline_comment_or",
        "mysql_if_sleep",
        "mssql_waitfor",
        "postgres_sleep",
        "oracle_dual",
        "json_quote_or",
    }.issubset(names)


def test_payload_names_are_unique():
    payloads = select_payloads(None)
    names = [payload.name for payload in payloads]

    assert len(names) == len(set(names))


def test_every_category_has_minimum_payload_count():
    for category in categories():
        payloads = select_payloads(category)
        assert len(payloads) >= MIN_PAYLOADS_PER_CATEGORY, category
