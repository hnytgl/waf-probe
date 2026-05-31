# waf-probe

`waf-probe` 是一个防御用途的 WAF 规则探测工具。它会向你拥有或已获得授权的目标发送低频、无破坏性的探测字符串，并把每次探测响应和基线响应进行对比，用来判断 WAF、CDN、反向代理或安全网关是否可能正在生效。

工具不会执行漏洞利用、不会绕过防护、不会爆破目录，也不会做压力测试。

## 功能

- 基线响应对比：状态码、响应长度、WAF 拦截关键词、请求异常。
- 支持表格输出和 JSON 输出。
- 支持多种探测位置：
  - Query 参数
  - POST/PUT/PATCH Body 字段
  - Header
  - Cookie
  - User-Agent
  - URL 路径
- 覆盖常见和不常见的 WAF 规则类别：
  - SQL 注入
  - XSS
  - 路径穿越
  - 命令注入
  - 模板注入
  - SSRF
  - NoSQL 注入
  - LDAP 注入
  - XPath 注入
  - XXE
  - GraphQL introspection 和批量查询
  - CRLF/Header Splitting
  - 开放重定向
  - 反序列化特征
  - JWT 滥用特征
  - 原型污染
  - 远程/本地文件包含特征
  - 扫描器 User-Agent 指纹
  - 可疑上传文件名
  - 敏感文件路径
  - 备份文件路径
  - 后台管理目录
  - API 文档路径
  - 框架调试路径
  - 日志文件路径

## 安装

```bash
python -m pip install .
```

开发模式安装：

```bash
python -m pip install -e .
```

## 使用方法

探测 Query 参数：

```bash
waf-probe https://example.com/search --param q
```

探测 POST 表单字段：

```bash
waf-probe https://example.com/login --method POST --location body --param username
```

探测自定义 Header：

```bash
waf-probe https://example.com/ --location header --param X-Waf-Probe
```

探测 User-Agent 规则：

```bash
waf-probe https://example.com/ --location user-agent --categories scanner
```

探测敏感文件和目录路径规则：

```bash
waf-probe https://example.com/ --location path --categories sensitive-file,backup-file,admin-path,api-docs,framework-debug,log-file
```

输出 JSON：

```bash
waf-probe https://example.com/search --param q --json
```

在探测请求之间增加延时：

```bash
waf-probe https://example.com/search --param q --delay 0.5
```

## 规则类别

可以通过传入一个不存在的类别查看当前支持的类别列表：

```bash
waf-probe https://example.com/ --categories does-not-exist
```

然后按需选择部分类别：

```bash
waf-probe https://example.com/search --param q --categories sqli,xss,graphql,xxe
```

常用目录/文件类探测：

```bash
waf-probe https://example.com/ --location path --categories sensitive-file,backup-file,admin-path
```

## 判定逻辑

每条探测结果会被标记为：

- `blocked`：强拦截信号，例如拦截状态码、WAF 页面关键词、请求超时、连接重置等。
- `suspicious`：响应相比基线出现明显变化，可能是软拦截、挑战页或网关改写。
- `passed`：没有观察到明显拦截信号。

常见拦截状态码包括 `401`、`403`、`406`、`418`、`429`、`451`、`501`、`503`。

## 示例输出

```text
Target: https://example.com/search
Baseline: 200 12451 bytes 132 ms

Category            Payload                  Payload Value                      Location    Status      HTTP   Notes
--------------------------------------------------------------------------------------------------------------------------------
sqli                classic_or_true                                             query       blocked     403    blocking status
xss                 script_tag                                                  query       blocked     403    blocking status
path-traversal      dot_dot_etc_passwd       ../../../../../etc/passwd          query       passed      200    similar to baseline
sensitive-file      git_config                                                  path        blocked     403    blocking status
```

## 退出码

- `0`：执行完成，未观察到明显拦截信号。
- `1`：至少一条探测结果为 `blocked` 或 `suspicious`。
- `2`：参数错误、类别无效或目标访问失败。

## 注意事项

- `--location path` 是低频路径规则验证，不是目录爆破。它会把所选类别中的每个路径追加到目标 URL 后面，并和基线响应对比。
- 在生产环境上测试时，建议使用 `--delay` 和 `--categories` 控制请求量。
- 探测结果只是信号，不等于最终结论。关键结果建议结合 WAF 日志、CDN 日志或应用网关日志确认。
