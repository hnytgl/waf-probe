from waf_probe.payloads import Payload
from waf_probe.prober import HttpSample, WafProber, add_query_param, append_path_probe, length_changed


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


def test_classify_includes_payload_value():
    payload = Payload("xss", "script_tag", "<script>alert(1)</script>", "Script tag XSS signature.")
    prober = WafProber("https://example.com")
    sample = HttpSample(status_code=200, length=1000, elapsed_ms=10)

    result = prober._classify(payload, sample, sample)

    assert result.verdict == "passed"
    assert result.payload == "script_tag"
    assert result.payload_value == "<script>alert(1)</script>"


def test_run_reports_progress():
    payload = Payload("xss", "script_tag", "<script>alert(1)</script>", "Script tag XSS signature.")
    prober = WafProber("https://example.com")
    sample = HttpSample(status_code=200, length=1000, elapsed_ms=10)
    messages: list[str] = []

    prober._request = lambda payload_arg: sample

    prober.run([payload], progress=messages.append)

    assert any("baseline request" in message for message in messages)
    assert any("Probe 1/1" in message for message in messages)
    assert any("Result 1/1" in message for message in messages)
