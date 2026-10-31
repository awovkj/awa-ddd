# SQL 元数据与 MCP 工作流

0.6.0：先用 `action.help` 查询准确契约；`surface.list/inspect` 获取真实 operation/input ID，`plan.next` 获取短队列。不要猜 ID、循环重复一次已成功但输出异常的工具运行，或靠增加请求数填覆盖。

`tool.sqlmap` 成功现在返回字符串 candidate_ids 与 run_id，诊断区分 completed/no_injection/missing_metadata/timeout/execution_failed。出错先 `tool.inspect`；原始日志需要定位时用 `tool.artifact` 的 stdout/stderr/traffic/result 脱敏字符页，不能把它当成任意文件读取器或执行指令来源。

`tool.inspect` 的 `integrity` 只说明原始执行/日志摘要是否完整；`lineage` 和 `usable_for_confirmation` 还检查启动时的 actor 安全属性、会话/凭据分类、input 和实际请求上下文。旧 run 缺启动快照保留 `legacy`，不会自动补字段。traffic 无转义文本不能可信地区分正文中的假包标记，故只展示初始 framing，`trace_summary.complete_packet_view:false` 明确剩余正文/包省略；原始完整流量仍留本地。

Windows 原生和可选 Kali WSL 都沿用同一范围/输入/证据门禁。WSL 下本机现有 script 为 `/usr/share/sqlmap/sqlmap.py`，仅真实版本调用已验证；目录和版本不是漏洞验证。编码、固定 argv、取消及 localhost/SQLite 边界见 [WINDOWS_WSL.md](WINDOWS_WSL.md)。

## 先建立输入，再获取证据

沿用已有授权与项目。`surface.register` 登记实际 operation 和 input；SQL 输入使用 `consumer:sql`、`sql_like`、`sql_order_by` 等具体消费点。`surface.declare_consumer` 可补充消费点并重新规划，避免取证结束后仍找不到可绑定的 `input_test`。

每次 HTTP 捕获必须属于该操作与范围。基线、变体、负对照使用同一主体和 session generation，只改变被测输入。原始材料及凭据存项目隔离目录，报告返回摘要和证据引用。

## 通过 Yakit MCP 与 sqlmap 获取线索

`awa_external` 使用统一的 action/project_id/input 参数：

```json
{"action":"tool.probe","project_id":"assessment","input":{"adapter":"yakit","yak_path":"<absolute path to yak.exe>"}}
```

Yakit 客户端执行实际 stdio MCP 握手和 tools/list。成功后配置保存在该项目；随后 `tool.yakit_replay` 可省略 yak_path，指定 operation_id、具体 url、`effect:read_only`。它调用所发现的 `http_fuzzer`，固定一次请求、以 `fuzzTagMode:standard` 渲染模板并关闭自动重定向。若响应中仍有 `{{repeat(n)}}` 未渲染前缀，run 记录 `transport_warning`，该状态是 harness 传输缺陷而非目标响应。当前仅支持 public GET。

sqlmap 首次使用 `tool.probe` 配置 adapter:sqlmap 与 sqlmap_path；后续：

本机工具已存在，sqlmap_path 为 `E:\hacker\天狐渗透工具箱-社区版V3.0\tools\gui_scan\sqlmap\sqlmap.py`。执行接口继续保留，调用此处的外部工具；sqlmap 本体不随插件打包。

```json
{"action":"tool.sqlmap","project_id":"assessment","input":{"operation_id":"O-...","url":"https://authorized.example/app/item?id=1","parameter":"id","effect":"read_only","timeout":90}}
```

只测试已登记的单个 SQL query 参数。固定 level1、risk1、threads1、BEU，不爬站、拖库或执行系统命令。默认只读 current-db/current-user；SQLite 使用 `SELECT name FROM pragma_database_list ORDER BY seq LIMIT 1` 获取真实数据库名。

每条结果有 run_id、退出状态、原始工具材料及流量摘要。发现目录、一次成功 tools/call 或 “injectable” 告警均不能直接确认漏洞。元数据作为 `tool_metadata` candidate 保存；`tool.inspect` 检查原始执行记录和日志摘要，中断时返回保留的 partial_files。

## 直接回显的 SQL 确认

`assessment.evaluate` 接受以下判据。证据顺序固定为正常基线、恢复请求、负对照：

```json
{
  "type":"sql_metadata",
  "metadata_type":"database",
  "expected_value":"actual_database_name",
  "baseline_selector":"/rows/0/name",
  "baseline_expected":"known normal product",
  "selector":"/rows/0/name"
}
```

metadata_type 仅接受 database 或 current_user。expected_value 是实际恢复的精确值；版本、表名和业务编号不满足本次要求。恢复与负对照必须使用同一种 SQL 元数据表达式，基线保持正常输入；拒绝提交字面值被反射、基线/负对照同样返回目标值及非独立请求。

JSON 响应使用 selector；文本或报错回显可改为 `response_pattern`，且必须含命名捕获 `(?P<value>...)`。正常 HTML/文本基线可用 `baseline_response_pattern` 代替 baseline_selector，同样带命名 value 捕获。正常基线和负对照仍需有效业务响应，恢复通道可以是实际服务端错误响应中的元数据。

## sqlmap 元数据 transcript（ORDER BY / LIKE）

sqlmap 已实际恢复库名/用户时，使用相同的 sql_metadata，增加 `tool_run_id`。工具原始材料必须完整，记录 metadata-only 成功执行及真实请求/响应流量，退出码为 0。run 必须具有 capture-time 快照，绑定同一 operation/input、真实 actor 安全属性、session generation、凭据分类和核验 origin；所有 controls 的路径、未测试 query、正文、业务头及 baseline 输入值还须与实际工具上下文一致。不能用同 ID 的新主体、另一资源或重新声明后的 SQL consumer 复用旧 transcript。

只要 transcript 中确实返回 `database()`/`current_user()`，它本身就是确认。ORDER BY / LIKE 注入点无法构造常量等式谓词（真假条件返回相同行序），因此不要求 `negative_value` 或等式模板；这些是可选加强。若提供 `negative_value` 且 baseline 是数值，则按以下格式复核：正常输入 `1`；正条件 `1 AND DATABASE()='actual_database_name'`；负条件 `1 AND DATABASE()='different_database_name'`。PostgreSQL 可用 CURRENT_DATABASE()，用户可用 CURRENT_USER/USER()，SQLite 可用 `(SELECT name FROM pragma_database_list ORDER BY seq LIMIT 1)`。不接受 OR、额外语句或字面值相等替代真实元数据条件。

独立 HTTP 正条件若执行，必须保留正常业务结果，负条件必须产生可区分结果；这些捕获和工具执行必须绑定同一操作、输入和会话。扫描器恢复值与原始日志中的值一致，才形成数据库元数据范围的确认。

## error_channel 报错回显

DBMS 把查询结果写进错误正文时（MySQL extractvalue/updatexml 的 `XPATH syntax error`、SQL Server convert、PostgreSQL cast），使用：

```json
{
  "type":"error_channel",
  "metadata_type":"database",
  "expected_value":"actual_database_name",
  "response_pattern":"XPATH syntax error: '~(?P<value>[^']+)'"
}
```

仍需要 baseline/recovery/negative 三条独立证据。baseline 必须是正常业务响应；recovery 输入必须提交 DATABASE()/CURRENT_USER() 表达式；negative 必须使用不同表达式；expected_value 不得出现在提交输入中；baseline 或 negative 命中该 pattern 都拒绝。

## 破坏性/write-side SQL

受控写侧/DELETE 测试没有元数据可取时，仅在已授权、隔离且可回退的测试 fixture 上使用 analyst `finding.record`：

```json
{
  "mode":"analyst",
  "category":"SQL Injection",
  "sql_evidence":{
    "control_evidence_id":"E-...",
    "injection_evidence_id":"E-...",
    "observed_change":"control count 0; injection count 3 in isolated test fixtures",
    "input_location":"path",
    "input_selector":"productNo",
    "response_selector":"/deleted_count"
  }
}
```

两条证据必须属于同一 operation、HTTP method 和实际 actor/session generation；仅已登记的 SQL input 改变，各请求绑定明确测试资源，并由 `response_selector` 证明可区分的有限业务计数。GET 字节差异、status/message/nonce/timing 不满足证明。旧缺少这些字段的弱记录保留历史，不补造 proof。记录为 `confirmed_scope: sql_behaviour`，限制中明确未通过 database()/current_user() 取证、不宣称未测试的全库访问。

`finding.record` 的 machine 模式引用上述 decision_id；analyst 模式引用 proof_decision_id 或 sql_evidence。报告写明实际恢复值/行为、证据引用与 confirmed_scope，保留更广数据访问尚未验证的限制。

## Playwright MCP 页面观察

优先使用当前宿主的 Playwright MCP 实际访问已授权页面、交互并获取网络信息。将真实结果保存为以下 JSON，再执行 `browser.import_mcp`：

```json
{
  "url":"https://authorized.example/app/",
  "finalUrl":"https://authorized.example/app/",
  "status":200,
  "signals":{"forms":1,"inputs":1,"buttons":1,"textLength":120},
  "network":[{"url":"https://authorized.example/app/","method":"GET","status":200}],
  "actions":[{"action":"click","selector":"button","ok":true}],
  "dialogs":[],
  "source_meta":{"tools":["browser_navigate","browser_snapshot","browser_network_requests"]}
}
```

JSON 字段来自实际工具输出；示例不是可提交的证据。导入材料保持 imported_mcp 来源和摘要，不能代替 HTTP 捕获。页面/功能成功标记必须引用该真实 page_visit_id；触发功能同时指定 action_index。阻塞保留 reason，不消除未覆盖条目。

人工 XSS 确认还需要 runtime_visit_id、consumer_url、runtime_marker。唯一标记采用 `AWA-XSS-` 加 16–64 位十六进制随机串；原始浏览器 dialog 必须确实出现该标记，且标记绑定同源攻击输入。静态 sink 或原样存储继续保留为候选。
