from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Mapping
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests

from .payloads import Payload


BLOCK_STATUSES = {401, 403, 406, 418, 429, 451, 501, 503}
WAF_MARKERS = (
    "access denied",
    "blocked",
    "forbidden",
    "not acceptable",
    "request rejected",
    "security policy",
    "web application firewall",
    "waf",
    "mod_security",
    "modsecurity",
    "cloudflare",
    "akamai",
    "incapsula",
    "imperva",
    "sucuri",
    "barracuda",
    "wordfence",
    "fortinet",
    "f5",
    "big-ip",
    "aws waf",
    "request blocked",
    "malicious request",
    "attack detected",
    "bot detection",
)


@dataclass(frozen=True)
class HttpSample:
    status_code: int | None
    length: int
    elapsed_ms: int
    error: str | None = None
    marker: str | None = None


@dataclass(frozen=True)
class ProbeResult:
    category: str
    payload: str
    location: str
    verdict: str
    status_code: int | None
    length: int
    elapsed_ms: int
    notes: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProbeReport:
    target: str
    baseline: HttpSample
    results: list[ProbeResult]

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "baseline": asdict(self.baseline),
                "results": [item.to_dict() for item in self.results],
            },
            ensure_ascii=False,
            indent=2,
        )

    @property
    def has_findings(self) -> bool:
        return any(result.verdict in {"blocked", "suspicious"} for result in self.results)


class WafProber:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        location: str = "query",
        param: str = "waf_probe",
        headers: Mapping[str, str] | None = None,
        timeout: float = 8.0,
        retries: int = 1,
        delay: float = 0.0,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.location = location
        self.param = param
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.verify_tls = verify_tls
        self.session = requests.Session()

    def run(self, payloads: list[Payload]) -> ProbeReport:
        baseline = self._request(None)
        results = []
        for payload in payloads:
            if self.delay > 0:
                time.sleep(self.delay)
            sample = self._request(payload)
            results.append(self._classify(payload, baseline, sample))
        return ProbeReport(target=self.url, baseline=baseline, results=results)

    def _request(self, payload: Payload | None) -> HttpSample:
        request_kwargs = self._build_request(payload)
        last_error = None
        for _ in range(max(self.retries, 1)):
            start = time.perf_counter()
            try:
                response = self.session.request(
                    self.method,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=False,
                    **request_kwargs,
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                text = response.text[:4096].lower()
                marker = next((item for item in WAF_MARKERS if item in text), None)
                return HttpSample(
                    status_code=response.status_code,
                    length=len(response.content),
                    elapsed_ms=elapsed_ms,
                    marker=marker,
                )
            except requests.RequestException as exc:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                last_error = HttpSample(status_code=None, length=0, elapsed_ms=elapsed_ms, error=str(exc))
        return last_error or HttpSample(status_code=None, length=0, elapsed_ms=0, error="request failed")

    def _build_request(self, payload: Payload | None) -> dict[str, object]:
        headers = dict(self.headers)
        data = None
        cookies = None
        url = self.url
        value = "baseline" if payload is None else payload.value

        if self.location == "query":
            url = add_query_param(self.url, self.param, value)
        elif self.location == "body":
            data = {self.param: value}
        elif self.location == "header":
            headers[self.param] = value
        elif self.location == "cookie":
            cookies = {self.param: value}
        elif self.location == "user-agent":
            headers["User-Agent"] = value
        elif self.location == "path":
            url = self.url if payload is None else append_path_probe(self.url, value)
        else:
            raise ValueError(f"unsupported location: {self.location}")

        return {"url": url, "headers": headers, "data": data, "cookies": cookies}

    def _classify(self, payload: Payload, baseline: HttpSample, sample: HttpSample) -> ProbeResult:
        verdict = "passed"
        notes = "similar to baseline"

        if sample.error:
            verdict = "blocked"
            notes = f"request error: {sample.error}"
        elif sample.status_code in BLOCK_STATUSES:
            verdict = "blocked"
            notes = "blocking status"
        elif sample.marker:
            verdict = "blocked"
            notes = f"WAF marker: {sample.marker}"
        elif baseline.status_code is not None and sample.status_code != baseline.status_code:
            verdict = "suspicious"
            notes = f"status changed from {baseline.status_code} to {sample.status_code}"
        elif length_changed(baseline.length, sample.length):
            verdict = "suspicious"
            notes = f"response length changed from {baseline.length} to {sample.length}"

        return ProbeResult(
            category=payload.category,
            payload=payload.name,
            location=self.location,
            verdict=verdict,
            status_code=sample.status_code,
            length=sample.length,
            elapsed_ms=sample.elapsed_ms,
            notes=notes,
        )


def add_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def append_path_probe(url: str, value: str) -> str:
    parts = urlsplit(url)
    base_path = parts.path
    if not base_path.endswith("/"):
        base_path = f"{base_path}/"
    encoded_segments = [quote(segment, safe="%") for segment in value.split("/") if segment]
    path = base_path + "/".join(encoded_segments)
    if value.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def length_changed(baseline: int, current: int) -> bool:
    if baseline == current:
        return False
    if baseline < 100:
        return abs(current - baseline) > 50
    return abs(current - baseline) / max(baseline, 1) > 0.35
