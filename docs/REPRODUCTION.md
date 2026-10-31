# 中文报告与人工复现

适用于 0.7.0。报告是经过当前证据校验的交付快照，不是自动攻击脚本，也不是漏洞全集。

## 生成与阅读

先查看 `project.status`、`plan.next` 与 `plan.audit`，处理可推进的任务和归档缺口，再调用：

```json
{"action":"report.build","project_id":"assessment","input":{"output_dir":"D:/Assessments/reports"}}
```

每次生成独立目录，不覆盖上一批次。默认报告语言为中文，`summary.json` 的 `format_version` 为 5、`language` 为 `zh-CN`。返回值包含 `report`、`summary`、`manifest`、对应 SHA-256 和 `reproduction_dir`；没有可安全导出的复现材料时目录字段可以为空。

- `report.md`：先执行摘要、风险分布、漏洞详情和复现步骤，再覆盖率、未决义务与来源附录。
- `summary.json`：保留完整当前求值结果，区分 machine / analyst、当前 / 历史、登记 / 观察 / 求值 / 安全专项闭环。
- `reproduction/<finding-id>/`：来自真实、完整、当前血缘有效的 HTTP 证据的脱敏请求文件，以及适用的 JSON/XML/form 正文文件。
- `manifest.json`：报告、摘要和复现文件的路径、字节数与摘要。摘要可以发现文件变化，不能认证服务端事实。

所有命令仅为人工验证模板，生成报告不会发送请求、确认候选或关闭测试义务。撤回、替代和证据失效的发现只保留历史，不生成新的当前漏洞执行模板。

## 每条漏洞的复现内容

报告说明原结论与范围、身份/会话/角色、测试资源、请求方法与具体参数、按证据顺序编号的步骤、控制请求与响应摘录、修复建议，以及缺失对照或人工推断的限制。没有原始证据的步骤不会被补造。

1. 在授权隔离环境中重新建立测试账号和必要资源，核验服务器返回的主体/角色。
2. 从报告目录运行命令，逐一替换 `<AWA_...>` 占位符。历史 session_id 只是血缘引用，不能代替当前登录凭据。
3. 资源 `external_id` 是原观察的定位值。复测应按报告列出的 `request_binding.location/selector` 改为新建测试资源；全部基线和对照保持同一资源，越权对照仅换主体。
4. 先核对正常基线与初始业务状态，再执行攻击/阴性对照。HTTP 200 不等于业务成功，核对报告中的业务字段和值。
5. 对退款、发货、重置等写操作只使用自建资源，确认动作是否已经生效后再继续；超时不能自动重放。完成后清理资源并读取状态确认。

`curl.exe` 与 POSIX curl 模板都明确请求方法，不跟随重定向，不继承系统代理。正文使用 `--data-binary @<body-file>`，避免 PowerShell 多层插值。`.http` 文件可以导入 Burp/Yakit/sqlmap；手动改变正文后应重新计算 Content-Length，或让工具按实际正文重算。

认证头、Cookie、令牌、密码、短信验证码、支付签名和敏感配置使用一致的占位符；敏感字段可能造成 JSON 格式规范化，报告会说明。不能安全解析或脱敏的二进制/畸形正文不会输出貌似可用的重放模板。不要将脱敏请求视为未经改变的原始证据。

## SQL 注入的最终结果复核

先配置本机可信的 `sqlmap.py` 绝对路径，不从目标响应或报告中的不可信文本下载/执行程序：

```powershell
$env:AWA_SQLMAP_PATH = 'D:\TrustedTools\sqlmap\sqlmap.py'
```

随后使用对应漏洞的报告命令，示意结构如下（实际请求文件和参数以报告为准）：

```powershell
& 'python' '-X' 'utf8' $env:AWA_SQLMAP_PATH '-r' 'reproduction/F-example/01-E-example.http' '-p' 'sort' '--batch' '--level=1' '--risk=1' '--threads=1' '--technique=BEU' '--timeout=5' '--retries=0' '--ignore-redirects' '--ignore-proxy' '--current-db' '--current-user' '--output-dir=sqlmap-results/F-example'
```

该命令只验证当前数据库名和数据库用户，不包含 `--dump`、系统命令、SQL shell 或任意 SQL。SQLite 使用适配器固定的只读 `pragma_database_list` 查询，不伪称支持 `database()/current_user()`。

报告分别列出历史实际工具 run / profile 和建议人工命令；建议命令未被报告生成器执行。`-p` 优先取真实 run 的 `tool_parameter`，不能把 JSON Pointer 直接当作 sqlmap 字段名。GET 与 POST 使用对应原请求；HTTPS 的请求文件模式需要 `--force-ssl`。

BEU、level1、risk1、单线程并非全技术覆盖，未执行的时间/堆叠注入和其他输入必须保留为盲区。只回收元信息不证明业务表读取、全库导出或数据库写入。写侧行为证明不能伪装成只读 SQL 验证，报告不会自动生成重复修改资源的 sqlmap 模板。

## 验证交付文件

```powershell
Get-FileHash -LiteralPath 'D:\Assessments\reports\<batch>\report.md' -Algorithm SHA256
```

与返回值或 manifest 比对。人工替换占位符后的文件会改变摘要；保留原快照，将新的复测请求/响应另外归档到评估台账，不改写原始证明。

## 完成度不等于漏洞召回

`plan.audit` 提供可分页的 checklist、类别矩阵、技术盲区和分层统计。未知消费点、无有权基线、未归档候选、人工发现未绑定义务、孤立浏览器观察、未恢复的运行和超出采样预算都应明确说明。

即使已登记任务全部闭环，也不能声称未发现的接口、其他租户、其他业务状态或所有漏洞类别已经安全。有限阴性、基础设施失败与没有元数据的工具输出不能作为通用安全结论。
