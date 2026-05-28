from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    category: str
    name: str
    value: str
    description: str


PAYLOADS: tuple[Payload, ...] = (
    Payload("sqli", "classic_or_true", "' OR '1'='1", "Classic SQL injection signature."),
    Payload("sqli", "union_select", "' UNION SELECT NULL--", "UNION SELECT SQL injection signature."),
    Payload("xss", "script_tag", "<script>alert(1)</script>", "Script tag XSS signature."),
    Payload("xss", "event_handler", "\" onmouseover=\"alert(1)", "HTML event-handler XSS signature."),
    Payload("path-traversal", "dot_dot_etc_passwd", "../../../../../etc/passwd", "Unix path traversal signature."),
    Payload("path-traversal", "windows_ini", "..\\..\\..\\windows\\win.ini", "Windows path traversal signature."),
    Payload("cmd-injection", "shell_separator", "test;id", "Shell command separator signature."),
    Payload("cmd-injection", "subshell", "$(id)", "Shell subshell signature."),
    Payload("template-injection", "jinja_math", "{{7*7}}", "Template expression signature."),
    Payload("template-injection", "erb_math", "<%= 7*7 %>", "ERB expression signature."),
    Payload("ssrf", "loopback_url", "http://127.0.0.1:80/", "Loopback URL signature."),
    Payload("ssrf", "metadata_url", "http://169.254.169.254/latest/meta-data/", "Cloud metadata URL signature."),
    Payload("scanner", "sqlmap_ua", "sqlmap/1.7 waf-probe", "Scanner User-Agent signature."),
    Payload("scanner", "nikto_ua", "Nikto/2.5 waf-probe", "Scanner User-Agent signature."),
    Payload("file-upload", "double_extension", "probe.php.jpg", "Suspicious double extension signature."),
    Payload("file-upload", "webshell_name", "cmd.jsp", "Suspicious server-side script filename signature."),
)


def categories() -> list[str]:
    return sorted({payload.category for payload in PAYLOADS})


def select_payloads(category_filter: str | None) -> list[Payload]:
    if not category_filter:
        return list(PAYLOADS)

    wanted = {item.strip().lower() for item in category_filter.split(",") if item.strip()}
    unknown = wanted.difference(categories())
    if unknown:
        joined = ", ".join(sorted(unknown))
        available = ", ".join(categories())
        raise ValueError(f"unknown categories: {joined}. Available: {available}")

    return [payload for payload in PAYLOADS if payload.category in wanted]
