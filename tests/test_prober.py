from waf_probe.prober import add_query_param, append_path_probe, length_changed


def test_add_query_param_preserves_existing_params():
    url = add_query_param("https://example.com/search?a=1", "q", "' OR '1'='1")
    assert url.startswith("https://example.com/search?a=1&q=")
    assert "%27+OR+%271%27%3D%271" in url


def test_length_changed_ignores_small_relative_changes():
    assert not length_changed(1000, 1100)


def test_length_changed_flags_large_relative_changes():
    assert length_changed(1000, 1500)


def test_append_path_probe_adds_encoded_path_segment():
    url = append_path_probe("https://example.com/base?x=1", ".git/config")
    assert url == "https://example.com/base/.git/config?x=1"


def test_append_path_probe_preserves_trailing_slash():
    url = append_path_probe("https://example.com", "admin/")
    assert url == "https://example.com/admin/"
