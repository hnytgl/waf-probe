from __future__ import annotations

from dataclasses import dataclass
from html import escape
from urllib.parse import quote


@dataclass(frozen=True)
class Payload:
    category: str
    name: str
    value: str
    description: str


MIN_PAYLOADS_PER_CATEGORY = 50


BASE_PAYLOADS: tuple[Payload, ...] = (
    Payload("sqli", "classic_or_true", "' OR '1'='1", "Classic SQL injection signature."),
    Payload("sqli", "classic_or_true_double_quote", '" OR "1"="1', "Double-quote boolean SQL injection signature."),
    Payload("sqli", "classic_or_true_numeric", "1 OR 1=1", "Numeric boolean SQL injection signature."),
    Payload("sqli", "classic_and_false", "' AND '1'='2", "Boolean false SQL injection signature."),
    Payload("sqli", "or_true_comment_dash", "' OR 1=1--", "Boolean SQL injection with dash comment."),
    Payload("sqli", "or_true_comment_hash", "' OR 1=1#", "Boolean SQL injection with hash comment."),
    Payload("sqli", "or_true_comment_block", "' OR 1=1/*", "Boolean SQL injection with block comment opener."),
    Payload("sqli", "mixed_case_or_true", "' oR '1'='1", "Mixed-case boolean SQL injection signature."),
    Payload("sqli", "inline_comment_or", "'/**/OR/**/'1'='1", "Inline-comment SQL keyword splitting signature."),
    Payload("sqli", "tab_separated_or", "'\tOR\t'1'='1", "Tab-separated SQL keyword signature."),
    Payload("sqli", "newline_separated_or", "'\nOR\n'1'='1", "Newline-separated SQL keyword signature."),
    Payload("sqli", "url_encoded_or_true", "%27%20OR%20%271%27%3D%271", "URL-encoded boolean SQL injection signature."),
    Payload("sqli", "double_url_encoded_or_true", "%2527%2520OR%2520%25271%2527%253D%25271", "Double URL-encoded boolean SQL injection signature."),
    Payload("sqli", "plus_encoded_or_true", "'+OR+'1'='1", "Plus-separated encoded SQL injection signature."),
    Payload("sqli", "union_select", "' UNION SELECT NULL--", "UNION SELECT SQL injection signature."),
    Payload("sqli", "union_select_two_columns", "' UNION SELECT NULL,NULL--", "UNION SELECT two-column SQL injection signature."),
    Payload("sqli", "union_all_select", "' UNION ALL SELECT NULL--", "UNION ALL SELECT SQL injection signature."),
    Payload("sqli", "mixed_case_union", "' UnIoN SeLeCt NULL--", "Mixed-case UNION SELECT signature."),
    Payload("sqli", "comment_split_union", "' UNI/**/ON SEL/**/ECT NULL--", "Comment-split UNION SELECT signature."),
    Payload("sqli", "order_by_probe", "' ORDER BY 1--", "ORDER BY column-count probing signature."),
    Payload("sqli", "group_by_probe", "' GROUP BY 1--", "GROUP BY probing signature."),
    Payload("sqli", "stacked_query", "'; SELECT 1--", "Stacked query SQL injection signature."),
    Payload("sqli", "stacked_drop_probe", "'; DROP TABLE waf_probe--", "Stacked-query DDL keyword signature."),
    Payload("sqli", "semicolon_comment", "1;--", "Semicolon and SQL comment signature."),
    Payload("sqli", "mysql_version_comment", "/*!50000SELECT*/ 1", "MySQL versioned comment signature."),
    Payload("sqli", "mysql_concat", "CONCAT(CHAR(119),CHAR(97),CHAR(102))", "MySQL string function signature."),
    Payload("sqli", "mysql_information_schema", "information_schema.tables", "MySQL metadata table signature."),
    Payload("sqli", "mysql_sleep", "SLEEP(1)", "Time-based SQL function signature."),
    Payload("sqli", "mysql_benchmark", "BENCHMARK(100000,MD5(1))", "MySQL BENCHMARK time-like signature."),
    Payload("sqli", "mysql_if_sleep", "IF(1=1,SLEEP(1),0)", "MySQL conditional sleep signature."),
    Payload("sqli", "mssql_waitfor", "WAITFOR DELAY '0:0:1'", "MSSQL time-based SQL signature."),
    Payload("sqli", "mssql_union_version", "' UNION SELECT @@version--", "MSSQL version disclosure signature."),
    Payload("sqli", "mssql_xp_cmdshell", "xp_cmdshell", "MSSQL dangerous procedure keyword signature."),
    Payload("sqli", "postgres_sleep", "pg_sleep(1)", "PostgreSQL time-based function signature."),
    Payload("sqli", "postgres_cast_error", "CAST('waf' AS INT)", "PostgreSQL cast-error signature."),
    Payload("sqli", "oracle_sleep", "DBMS_LOCK.SLEEP(1)", "Oracle sleep function signature."),
    Payload("sqli", "oracle_dual", "' UNION SELECT NULL FROM dual--", "Oracle dual-table UNION signature."),
    Payload("sqli", "sqlite_version", "sqlite_version()", "SQLite version function signature."),
    Payload("sqli", "json_quote_or", "{\"id\":\"1' OR '1'='1\"}", "JSON string carrying SQL injection signature."),
    Payload("sqli", "array_param_or", "id[]=1&id[]=' OR '1'='1", "Array-style parameter SQL injection signature."),
    Payload("xss", "script_tag", "<script>alert(1)</script>", "Script tag XSS signature."),
    Payload("xss", "event_handler", "\" onmouseover=\"alert(1)", "HTML event-handler XSS signature."),
    Payload("xss", "svg_onload", "<svg onload=alert(1)>", "SVG event XSS signature."),
    Payload("xss", "javascript_url", "javascript:alert(1)", "JavaScript URL XSS signature."),
    Payload("xss", "html_entity", "&#x3c;script&#x3e;alert(1)", "HTML entity encoded XSS signature."),
    Payload("path-traversal", "dot_dot_etc_passwd", "../../../../../etc/passwd", "Unix path traversal signature."),
    Payload("path-traversal", "windows_ini", "..\\..\\..\\windows\\win.ini", "Windows path traversal signature."),
    Payload("path-traversal", "encoded_dot_dot", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal signature."),
    Payload("path-traversal", "double_encoded_dot_dot", "%252e%252e%252fetc%252fpasswd", "Double URL-encoded traversal signature."),
    Payload("cmd-injection", "shell_separator", "test;id", "Shell command separator signature."),
    Payload("cmd-injection", "subshell", "$(id)", "Shell subshell signature."),
    Payload("cmd-injection", "pipe_operator", "test|id", "Shell pipe operator signature."),
    Payload("cmd-injection", "backticks", "`id`", "Shell backtick substitution signature."),
    Payload("template-injection", "jinja_math", "{{7*7}}", "Template expression signature."),
    Payload("template-injection", "erb_math", "<%= 7*7 %>", "ERB expression signature."),
    Payload("template-injection", "freemarker_math", "${7*7}", "FreeMarker-style template expression signature."),
    Payload("template-injection", "velocity_ref", "#set($x=7*7)", "Velocity-style template expression signature."),
    Payload("ssrf", "loopback_url", "http://127.0.0.1:80/", "Loopback URL signature."),
    Payload("ssrf", "metadata_url", "http://169.254.169.254/latest/meta-data/", "Cloud metadata URL signature."),
    Payload("ssrf", "ipv6_loopback", "http://[::1]/", "IPv6 loopback URL signature."),
    Payload("ssrf", "file_scheme", "file:///etc/passwd", "Local file URL scheme signature."),
    Payload("ssrf", "gopher_scheme", "gopher://127.0.0.1:6379/_PING", "Non-HTTP URL scheme signature."),
    Payload("nosql", "mongo_ne", '{"$ne": null}', "MongoDB operator injection signature."),
    Payload("nosql", "mongo_where", '{"$where":"return true"}', "MongoDB where-clause signature."),
    Payload("ldap-injection", "ldap_wildcard", "*)(uid=*", "LDAP wildcard injection signature."),
    Payload("ldap-injection", "ldap_or_filter", "(|(uid=*)(mail=*))", "LDAP OR-filter signature."),
    Payload("xpath-injection", "xpath_or_true", "' or '1'='1", "XPath boolean injection signature."),
    Payload("xpath-injection", "xpath_count", "count(/)", "XPath function signature."),
    Payload("xxe", "doctype_entity", '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "XXE doctype signature."),
    Payload("xxe", "external_dtd", '<!DOCTYPE x SYSTEM "http://127.0.0.1/xxe.dtd">', "External DTD signature."),
    Payload("graphql", "introspection_query", "{__schema{types{name}}}", "GraphQL introspection signature."),
    Payload("graphql", "batched_query", '[{"query":"{__typename}"},{"query":"{__schema{types{name}}}"}]', "GraphQL batching signature."),
    Payload("crlf-injection", "set_cookie_split", "test%0d%0aSet-Cookie:%20waf_probe=1", "CRLF response splitting signature."),
    Payload("crlf-injection", "header_split", "test%0d%0aX-Waf-Probe:%201", "CRLF header injection signature."),
    Payload("open-redirect", "protocol_relative", "//example.com/", "Protocol-relative redirect signature."),
    Payload("open-redirect", "encoded_external", "https:%2f%2fexample.com%2f", "Encoded external redirect signature."),
    Payload("deserialization", "java_serialized", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "Java serialization magic signature."),
    Payload("deserialization", "php_object", 'O:8:"stdClass":0:{}', "PHP object serialization signature."),
    Payload("deserialization", "dotnet_type", '{"$type":"System.Windows.Data.ObjectDataProvider"}', ".NET type metadata signature."),
    Payload("jwt", "none_alg", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3YWZfcHJvYmUifQ.", "JWT none-algorithm signature."),
    Payload("jwt", "jku_header", "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xMjcuMC4wLjEvayJ9.e30.sig", "JWT remote key header signature."),
    Payload("prototype-pollution", "proto_param", "__proto__[polluted]=1", "Prototype pollution parameter signature."),
    Payload("prototype-pollution", "constructor_param", "constructor[prototype][polluted]=1", "Constructor prototype signature."),
    Payload("rfi-lfi", "remote_include", "http://example.com/probe.txt", "Remote file include URL signature."),
    Payload("rfi-lfi", "php_filter", "php://filter/convert.base64-encode/resource=index.php", "PHP stream wrapper signature."),
    Payload("scanner", "sqlmap_ua", "sqlmap/1.7 waf-probe", "Scanner User-Agent signature."),
    Payload("scanner", "nikto_ua", "Nikto/2.5 waf-probe", "Scanner User-Agent signature."),
    Payload("scanner", "acunetix_ua", "acunetix-wvs-test-for-some-inexistent-file", "Scanner fingerprint signature."),
    Payload("scanner", "nuclei_ua", "Nuclei - Open-source project", "Scanner fingerprint signature."),
    Payload("file-upload", "double_extension", "probe.php.jpg", "Suspicious double extension signature."),
    Payload("file-upload", "webshell_name", "cmd.jsp", "Suspicious server-side script filename signature."),
    Payload("file-upload", "asp_extension", "probe.asp;.jpg", "IIS-style suspicious extension signature."),
    Payload("file-upload", "htaccess_name", ".htaccess", "Apache configuration filename signature."),
    Payload("sensitive-file", "env_file", ".env", "Environment file path signature."),
    Payload("sensitive-file", "git_config", ".git/config", "Git metadata path signature."),
    Payload("sensitive-file", "svn_entries", ".svn/entries", "SVN metadata path signature."),
    Payload("sensitive-file", "docker_compose", "docker-compose.yml", "Docker Compose file path signature."),
    Payload("sensitive-file", "kube_config", ".kube/config", "Kubernetes config path signature."),
    Payload("sensitive-file", "aws_credentials", ".aws/credentials", "AWS credentials path signature."),
    Payload("backup-file", "index_php_bak", "index.php.bak", "Common backup file path signature."),
    Payload("backup-file", "config_old", "config.php.old", "Common old config path signature."),
    Payload("backup-file", "site_zip", "www.zip", "Common archive backup path signature."),
    Payload("backup-file", "db_sql", "backup.sql", "Common database dump path signature."),
    Payload("admin-path", "admin", "admin/", "Common admin directory path signature."),
    Payload("admin-path", "phpmyadmin", "phpmyadmin/", "Common database admin path signature."),
    Payload("admin-path", "wp_admin", "wp-admin/", "WordPress admin path signature."),
    Payload("admin-path", "manager_html", "manager/html", "Tomcat manager path signature."),
    Payload("api-docs", "swagger_json", "swagger.json", "Swagger JSON path signature."),
    Payload("api-docs", "openapi_json", "openapi.json", "OpenAPI JSON path signature."),
    Payload("api-docs", "graphql_console", "graphql", "GraphQL endpoint path signature."),
    Payload("framework-debug", "actuator_env", "actuator/env", "Spring Actuator environment path signature."),
    Payload("framework-debug", "actuator_heapdump", "actuator/heapdump", "Spring Actuator heapdump path signature."),
    Payload("framework-debug", "laravel_debug", "_ignition/execute-solution", "Laravel Ignition path signature."),
    Payload("framework-debug", "django_admin", "admin/login/", "Django admin path signature."),
    Payload("log-file", "access_log", "access.log", "Access log path signature."),
    Payload("log-file", "error_log", "error.log", "Error log path signature."),
    Payload("log-file", "debug_log", "debug.log", "Debug log path signature."),
)


EXTRA_SEEDS: dict[str, tuple[str, ...]] = {
    "admin-path": (
        "administrator/",
        "admin/login",
        "admin.php",
        "backend/",
        "controlpanel/",
        "cpanel/",
        "dashboard/",
        "manage/",
        "management/",
        "operator/",
        "sysadmin/",
        "webadmin/",
    ),
    "api-docs": (
        "api-docs",
        "api/docs",
        "api/swagger",
        "docs/api",
        "redoc",
        "swagger-ui/",
        "swagger-ui.html",
        "swagger/index.html",
        "v1/swagger.json",
        "v3/api-docs/swagger-config",
    ),
    "backup-file": (
        "backup.zip",
        "backup.tar.gz",
        "db.sql",
        "dump.sql",
        "site.tar",
        "site.tar.gz",
        "source.zip",
        "wwwroot.zip",
        "www.bak",
        "web.rar",
    ),
    "cmd-injection": (
        "test&&id",
        "test||id",
        "test%26%26id",
        "test%7Cid",
        "test\nid",
        "test$(whoami)",
        "test`whoami`",
        "test;whoami",
        "test|whoami",
        "${IFS}id",
    ),
    "crlf-injection": (
        "test%0aX-Waf-Probe:%201",
        "test%0dX-Waf-Probe:%201",
        "test%0d%0aLocation:%20https://example.com/",
        "test%0d%0aContent-Length:%200",
        "test%250d%250aX-Waf-Probe:%201",
        "test\r\nX-Waf-Probe: 1",
    ),
    "deserialization": (
        "ac ed 00 05",
        "H4sIAAAAAAAA",
        "O:4:\"Test\":0:{}",
        "a:1:{s:4:\"test\";s:4:\"waf\";}",
        '{"@type":"java.lang.AutoCloseable"}',
        '{"$type":"System.Configuration.Install.AssemblyInstaller"}',
        "rO0ABXQABHdhZg==",
    ),
    "file-upload": (
        "probe.php",
        "probe.phtml",
        "probe.php5",
        "probe.jspx",
        "probe.aspx",
        "probe.ashx",
        "shell.php;.jpg",
        "waf_probe.svg",
        "probe.jpg.php",
        "probe%00.php",
    ),
    "framework-debug": (
        ".env",
        "_debugbar/open",
        "_profiler/phpinfo",
        "actuator",
        "actuator/beans",
        "debug/default/view",
        "server-status",
        "telescope/requests",
        "trace",
        "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ),
    "graphql": (
        "{__typename}",
        "{__schema{queryType{name}}}",
        "query IntrospectionQuery{__schema{types{name}}}",
        '[{"query":"{__typename}"}]',
        '{"query":"{__schema{types{name}}}"}',
        "mutation{__typename}",
    ),
    "jwt": (
        "eyJhbGciOiJub25lIn0.e30.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid",
        "Bearer eyJhbGciOiJub25lIn0.e30.",
        '{"alg":"none"}',
        '{"jku":"http://127.0.0.1/jwks.json"}',
        '{"kid":"../../../../etc/passwd"}',
    ),
    "ldap-injection": (
        "*",
        "*)(&(uid=*))",
        "admin*",
        ")(uid=*))(|(uid=*",
        "*)%00",
        "(cn=*)",
    ),
    "log-file": (
        "app.log",
        "application.log",
        "audit.log",
        "catalina.out",
        "debug.log",
        "laravel.log",
        "nginx/access.log",
        "nginx/error.log",
        "server.log",
        "web.log",
    ),
    "nosql": (
        '{"$gt":""}',
        '{"$regex":".*"}',
        '{"username":{"$ne":null}}',
        '{"password":{"$exists":true}}',
        "[$ne]=1",
        "password[$regex]=.*",
    ),
    "open-redirect": (
        "https://example.com/",
        "http://example.com/",
        "/\\example.com",
        "///example.com",
        "%2f%2fexample.com",
        "https://example.com%2f",
    ),
    "path-traversal": (
        "../etc/passwd",
        "....//....//etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "..%5c..%5cwindows%5cwin.ini",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/proc/self/environ",
    ),
    "prototype-pollution": (
        "__proto__.polluted=1",
        "__proto__[toString]=1",
        "constructor.prototype.polluted=1",
        "constructor[prototype][toString]=1",
        '{"__proto__":{"polluted":true}}',
        '{"constructor":{"prototype":{"polluted":true}}}',
    ),
    "rfi-lfi": (
        "http://127.0.0.1/probe.txt",
        "https://example.com/probe.txt",
        "file:///c:/windows/win.ini",
        "php://input",
        "data://text/plain,waf_probe",
        "expect://id",
    ),
    "scanner": (
        "Mozilla/5.0 sqlmap",
        "masscan/1.3",
        "Nmap Scripting Engine",
        "wpscan waf-probe",
        "dirbuster",
        "gobuster",
        "ffuf",
        "httpx",
    ),
    "sensitive-file": (
        ".env.local",
        ".env.production",
        ".git/HEAD",
        ".npmrc",
        ".ssh/id_rsa",
        "config.php",
        "id_rsa",
        "secrets.yml",
        "settings.py",
        "web.config",
    ),
    "ssrf": (
        "http://localhost/",
        "http://0.0.0.0/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
    ),
    "template-injection": (
        "${{7*7}}",
        "${jndi:ldap://127.0.0.1/a}",
        "{{config}}",
        "{{request.application.__globals__}}",
        "<#assign x=7*7>${x}",
        "#{7*7}",
    ),
    "xpath-injection": (
        "' or count(/*)>0 or 'a'='b",
        "' or string-length(name(/*))>0 or 'a'='b",
        "'] | //* | //foo['",
        "1 or 1=1",
        "')) or (('1'='1",
        "count(//user)",
    ),
    "xss": (
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    ),
    "xxe": (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/xxe.dtd">%xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "waf">]>',
        '<!ENTITY xxe SYSTEM "file:///etc/hosts">',
        '<!DOCTYPE foo SYSTEM "http://127.0.0.1/probe.dtd">',
    ),
}


def _safe_name(value: str) -> str:
    cleaned = "".join(char.lower() if char.isalnum() else "_" for char in value)
    cleaned = "_".join(part for part in cleaned.split("_") if part)
    return cleaned[:42] or "payload"


def _alternating_case(value: str) -> str:
    output: list[str] = []
    upper = True
    for char in value:
        if char.isalpha():
            output.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            output.append(char)
    return "".join(output)


def _variants(value: str) -> tuple[tuple[str, str], ...]:
    return (
        ("raw", value),
        ("upper", value.upper()),
        ("lower", value.lower()),
        ("mixed", _alternating_case(value)),
        ("url", quote(value, safe="")),
        ("double_url", quote(quote(value, safe=""), safe="")),
        ("plus_space", value.replace(" ", "+")),
        ("tab_space", value.replace(" ", "\t")),
        ("newline_space", value.replace(" ", "\n")),
        ("comment_space", value.replace(" ", "/**/")),
        ("json", '{"probe":"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"}'),
        ("array", "probe[]=" + quote(value, safe="")),
        ("wrapped", f"waf_probe:{value}:waf_probe"),
        ("quoted", f"'{value}'"),
        ("double_quoted", f'"{value}"'),
        ("html", escape(value)),
    )


def _supplemental_payloads(payloads: tuple[Payload, ...], minimum: int) -> tuple[Payload, ...]:
    by_category: dict[str, list[Payload]] = {}
    for payload in payloads:
        by_category.setdefault(payload.category, []).append(payload)

    generated: list[Payload] = []
    existing_names = {payload.name for payload in payloads}
    for category, category_payloads in sorted(by_category.items()):
        seeds = [payload.value for payload in category_payloads]
        seeds.extend(EXTRA_SEEDS.get(category, ()))

        seed_index = 0
        while len(category_payloads) < minimum:
            seed = seeds[seed_index % len(seeds)]
            for variant_name, variant_value in _variants(seed):
                name = f"{_safe_name(category)}_auto_{_safe_name(seed)}_{variant_name}"
                if name in existing_names:
                    continue
                existing_names.add(name)
                payload = Payload(
                    category,
                    name,
                    variant_value,
                    f"Generated {category} WAF signature variant based on {seed!r}.",
                )
                category_payloads.append(payload)
                generated.append(payload)
                if len(category_payloads) >= minimum:
                    break
            seed_index += 1
    return tuple(generated)


PAYLOADS: tuple[Payload, ...] = BASE_PAYLOADS + _supplemental_payloads(BASE_PAYLOADS, MIN_PAYLOADS_PER_CATEGORY)


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
