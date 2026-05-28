from waf_probe.prober import add_query_param, length_changed


def test_add_query_param_preserves_existing_params():
    url = add_query_param("https://example.com/search?a=1", "q", "' OR '1'='1")
    assert url.startswith("https://example.com/search?a=1&q=")
    assert "%27+OR+%271%27%3D%271" in url


def test_length_changed_ignores_small_relative_changes():
    assert not length_changed(1000, 1100)


def test_length_changed_flags_large_relative_changes():
    assert length_changed(1000, 1500)
