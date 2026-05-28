# waf-probe

`waf-probe` is a defensive WAF rule probe. It sends low-volume, non-destructive
test strings to a target you own or are authorized to test, then compares each
probe with a baseline response to estimate whether a WAF, CDN, reverse proxy, or
security gateway is active.

It does not exploit vulnerabilities, bypass protections, brute-force paths, or
run load tests.

## Features

- Baseline comparison for status code, response length, response markers, and
  request errors.
- Table and JSON output.
- Probe locations:
  - Query parameter
  - POST/PUT/PATCH body field
  - Header
  - Cookie
  - User-Agent
  - URL path
- Broad rule coverage, including common and less common categories:
  - SQL injection
  - XSS
  - Path traversal
  - Command injection
  - Template injection
  - SSRF
  - NoSQL injection
  - LDAP injection
  - XPath injection
  - XXE
  - GraphQL introspection and batching
  - CRLF/header splitting
  - Open redirect
  - Deserialization signatures
  - JWT abuse signatures
  - Prototype pollution
  - Remote/local file include signatures
  - Scanner User-Agent fingerprints
  - Suspicious upload filenames
  - Sensitive file paths
  - Backup file paths
  - Admin directory paths
  - API documentation paths
  - Framework debug paths
  - Log file paths

## Install

```bash
python -m pip install .
```

Editable development install:

```bash
python -m pip install -e .
```

## Usage

Probe a query parameter:

```bash
waf-probe https://example.com/search --param q
```

Probe a POST form field:

```bash
waf-probe https://example.com/login --method POST --location body --param username
```

Probe a custom header:

```bash
waf-probe https://example.com/ --location header --param X-Waf-Probe
```

Probe User-Agent rules:

```bash
waf-probe https://example.com/ --location user-agent --categories scanner
```

Probe sensitive file and directory path rules:

```bash
waf-probe https://example.com/ --location path --categories sensitive-file,backup-file,admin-path,api-docs,framework-debug,log-file
```

Output JSON:

```bash
waf-probe https://example.com/search --param q --json
```

Use a small delay between probes:

```bash
waf-probe https://example.com/search --param q --delay 0.5
```

## Rule Categories

Show all available categories:

```bash
waf-probe https://example.com/ --categories does-not-exist
```

The command will print the valid category list. You can then run a subset:

```bash
waf-probe https://example.com/search --param q --categories sqli,xss,graphql,xxe
```

## Verdicts

Each probe is classified as:

- `blocked`: Strong blocking signal, such as a blocking HTTP status, WAF marker,
  request timeout, or connection reset.
- `suspicious`: The response changed meaningfully compared with baseline.
- `passed`: No obvious blocking signal was observed.

Common blocking status codes include `401`, `403`, `406`, `418`, `429`, `451`,
`501`, and `503`.

## Example Output

```text
Target: https://example.com/search
Baseline: 200 12451 bytes 132 ms

Category            Payload                  Location    Status      HTTP   Notes
--------------------------------------------------------------------------------------------
sqli                classic_or_true          query       blocked     403    blocking status
xss                 script_tag               query       blocked     403    blocking status
path-traversal      dot_dot_etc_passwd       query       passed      200    similar to baseline
sensitive-file      git_config               path        blocked     403    blocking status
```

## Exit Codes

- `0`: The run completed and no obvious blocking signal was observed.
- `1`: At least one probe was classified as `blocked` or `suspicious`.
- `2`: Argument error, invalid category, or target access failure.

## Notes

- Path probing is intentionally simple and low-volume. It appends each selected
  payload to the supplied base URL and compares the result with the baseline.
- For production systems, use `--delay` and category filters to keep traffic
  predictable.
- Results are signals, not proof. Confirm important findings with your WAF logs.
