# waf-probe

`waf-probe` 是一个防御用途的 WAF 规则探测工具，用来检查目标站点前是否存在 WAF/网关拦截，以及常见规则类别是否可能生效。

> 只对你拥有或被授权测试的目标使用。工具只发送无破坏性的探测字符串，不执行漏洞利用、不绕过 WAF、不做压力测试。

## 功能

- 基线请求对比，判断探测请求是否被 WAF 拦截或改变。
- 覆盖常见 WAF 规则类别：
  - SQL 注入特征
  - XSS 特征
  - 路径穿越特征
  - 命令注入特征
  - 模板注入特征
  - SSRF 特征
  - 扫描器 User-Agent 特征
  - 可疑文件上传扩展名特征
- 支持探测位置：
  - Query 参数
  - POST 表单
  - Header
  - Cookie
- 支持表格和 JSON 输出。
- 支持自定义超时、重试、延时和自定义 Header。

## 安装

```bash
python -m pip install .
```

开发模式：

```bash
python -m pip install -e .
```

## 使用示例

探测 GET 参数：

```bash
waf-probe https://example.com/search --param q
```

探测 POST 表单：

```bash
waf-probe https://example.com/login --method POST --location body --param username
```

探测 Header：

```bash
waf-probe https://example.com/ --location header --param X-Waf-Probe
```

输出 JSON：

```bash
waf-probe https://example.com/search --param q --json
```

只测试指定类别：

```bash
waf-probe https://example.com/search --param q --categories sqli,xss,path-traversal
```

## 判定说明

工具会先发送一次基线请求，再逐条发送探测请求。若探测请求出现以下现象，会标记为 `blocked` 或 `suspicious`：

- HTTP 状态码变为 401、403、406、418、429、451、501、503 等常见拦截状态。
- 响应正文包含常见 WAF/拦截页关键词。
- 响应长度相比基线变化明显。
- 请求异常、超时或连接被重置。

输出中的 `blocked` 表示强拦截特征，`suspicious` 表示可能被改写、挑战或软拦截，`passed` 表示未观察到明显拦截。

## 示例输出

```text
Target: https://example.com/search
Baseline: 200 12451 bytes 132 ms

Category          Payload                    Location  Status      HTTP  Notes
sqli             classic_or_true            query     blocked     403   blocking status
xss              script_tag                  query     blocked     403   blocking status
path-traversal   dot_dot_etc_passwd          query     passed      200   similar to baseline
```

## 退出码

- `0`: 执行成功，未发现明显拦截或只发现正常通过。
- `1`: 至少一个类别出现 `blocked` 或 `suspicious`。
- `2`: 参数错误或目标无法访问。
