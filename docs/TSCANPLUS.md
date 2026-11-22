# TscanPlus MCP：有限适配与证据边界

## 接入地址与核对记录

用户给出的 MCP 配置原样保存在 [examples/tscanplus-mcp.json](../examples/tscanplus-mcp.json)：

```json
{"mcpServers":{"tscanplus":{"url":"http://127.0.0.1:8088/mcp"}}}
```

这是配置示例，不自动写入任何宿主全局配置，不启动或停止共享的 TscanPlus 服务。`127.0.0.1:8088/mcp` 是控制端点，不是被评估目标；控制端点可用也不代表已经获得任何目标的扫描授权。

WSL 与 Windows 引擎可能处在不同网络命名空间；连接失败时不自动把 loopback 改写为 Windows 网关或远端地址。使用当前后端真正可访问的本地服务，必要时明确选择 native 后端；不通过地址改写绕过控制端点或目标范围限制。

历史开发验收曾在 2026-10-30 对这个控制端点执行 MCP `initialize`、`notifications/initialized` 和 `tools/list` 元数据核对，协商协议为 `2025-03-26`，当时实际目录包含 **25 个工具**。原本地材料不随仓库交付且旧副本已清理；仅保留当时目录文件的 SHA-256 记录，不将它当成当前服务目录或可用性证明：

```text
043a64b3460c043ed617d3c8be9a6db4e06cdc5ac31bdd2687dd984f01c51f1b
```

上述历史元数据核对没有调用扫描、`http_request` 或 `query_results`，没有查询扫描数据库，也没有清空远端项目。2026-10-31 补齐适配时另行核对了当前 **TscanPlus 3.5.4** 的空非默认项目查询结构；该结构核对阶段没有发出目标 HTTP 请求。

2026-11-21 在本机 loopback MCP 在线执行 `initialize`、`notifications/initialized` 和 `tools/list`，记录了 **TscanPlus 3.5.8**、协议 `2025-03-26`、**43 个远端工具**及目录 SHA-256：

```text
bec3c772f0bedd3f8d1b19fedd0c470ff44c1dbc0a727bcc89aba8c8435779d6
```

该次在线核对没有调用 scanner tools 或结果 API，目标请求数为 0；保存的元数据用于离线核对适配器边界。每次实际读取仍必须使用当前项目 `tool.probe` 保存并校验的目录、schema 和 SHA-256。不同版本、不同 loopback 服务或磁盘上的其他 Tscan 数据都不能替换该次 probe 的绑定。

当时的最终链路验收另经 Node 文件调用、Python 引擎和真实 MCP，对临时自建 loopback fixture 发出两个 GET：一个普通响应，一个 302 响应。幂等复用没有重复发包，302 不跟随，范围外 URL 在发包前拒绝；结果、摘要和 routes 仅读取专用空 namespace。没有执行扫描、POC、破解、凭据校验或远端数据写入工具，没有访问历史目标，也没有清空项目。旧本地验收目录已清理，不提供随仓库下载的原始材料；该历史说明不是当前检出的验收结果。发行时不携带这个共享服务或它的数据库；服务需要由用户另行维护。

## 本版实际适配的范围

当前 awa-ddd V1 工具目录为 75 个动作；远端目录中的工具数量不等于 awa-ddd 执行动作数量。下表描述源码中保留的适配器和门禁，**不是当前外部服务已经可用的声明**。当前验收状态是：主动 Tscan/Web discovery unavailable，3.5.8/43 来自 2026-11-21 的在线元数据核对，本轮最终没有在线结果 API、主动请求或扫描验收。依赖当前可访问外部服务的动作须在实际运行环境重新 probe 并核对绑定。

| awa-ddd 动作 | 实际作用 | 不可当作什么 |
|---|---|---|
| `tool.probe`，`adapter:tscanplus` | 核对 loopback MCP 控制端点的实际目录并保存本项目配置 | 扫描、目标可达性或漏洞验证 |
| `tool.tscanplus_request` | 通过远端单次 `http_request` 执行受控 GET / HEAD，或已显式授权并绑定 fixture 的 POST | 通用扫描器、任意方法执行或自动确认的 HTTP 证据 |
| `tool.tscanplus_results` | 按记录的项目、允许的表及 instance 读取有限结果，解析成脱敏、范围核对、去重的候选 | 全库搜索、执行新扫描、确认 finding 或完整覆盖 |
| `tool.tscanplus_summary` | 读取已登记项目的 `project_summary`，只公开允许表的计数及 `has_assets` | 远端 prompt/hint 指令、完整资产覆盖或漏洞确认 |
| `tool.tscanplus_routes` | 只读 `route_candidates`，把范围内建议脱敏、去重后归档为未验证候选 | 执行建议工具、扩大授权或自动登记接口 |
| `tool.tscanplus_ingest` | 读取一次已有 `query_results` 或 `route_candidates`，保存 provider 收据，并将有界行写入统一 DiscoverySource / Snapshot / Item 来源账本 | 启动扫描、访问发现的 URL、把远端行自动登记为 operation 或把扫描线索当证明 |

这些是可在明确授权和可达服务下使用的有限适配路径。主动扫描能力保持机器的 `active_capability.available:false`；即使出现可达服务或新的 catalog，也不能由本文、历史目录摘要或远端提示文字把它改成 available。

其他远端工具，包括 `url_scan`、`ip_scan`、`tscan_scan`、目录/JS/子域扫描、POC、爆破、AK/JWT 和远端 finding/fact 写入工具，**没有通过本适配器执行**。目录中列出来不等于已接入，也不等于可安全自动调用。读取 routes 的建议不代表执行 `pwd_crack` / `poc_scan` / `dir_scan` / `js_scan` / `http_request`。

原因是这些工具的当前公开契约没有足够的重定向、出站路径与远端取消保证。尤其 `tscan_scan` 默认包含 `port,url,poc`，前一模块的全部结果会作为下一模块输入；这会把发现结果变成后续访问目标，不能冒充已经逐项通过 awa-ddd 的 scope、方法和测试资源门禁。

## 授权与远端项目

参考的上游 TscanPlus Skill 要求只对有明确书面授权的目标扫描。安装插件、探测工具目录或提供 MCP 地址本身不构成目标授权；开发者当时的本机资料路径不是 fresh clone 的依赖。

远端项目有容易破坏共享数据的默认行为：

- 远端扫描未指定 `project` 时，默认使用 `MCP` 桶，并在工具调用前清空该桶。
- 上游 Skill 约定显式短名规范为 `MCP-短名`，全长不超过 30；显式项目默认追加，`fresh_project:true` 才清空。
- `query_results` 不清空项目，但不指定 instance 时可能读取该项目全部结果。

**Namespace 保守兼容边界：** 历史实测已观察到服务端把超过 20 字符的归一化项目名裁剪为 20 字符，与上游 Skill 的 30 字符契约不一致。当前 probe、默认派生及所有新请求 / 读取继续要求全长最多 20 字符（未带 `MCP-` 的短名最多 16 字符），不因 3.5.8 目录基线而自动放宽。历史配置和材料保持不变，但旧的超过 20 字符 namespace 在连接 MCP 前就拒绝执行，用户须明确用短名重新 `tool.probe`；不能先让服务截断并读取另一个桶，再根据回显报错。旧 artifact 仍可离线 inspect。不根据远端回显静默改名，不复制、迁移或清空已有数据。

适配器禁止默认 `MCP` 桶和清空操作。`tool.probe` 可指定非默认的短 `scanner_project`；省略时派生专用的 `MCP-awa-...` 名称并保存绑定，后续读取沿用该记录。读取已有结果时应明确选本次评估获准访问的远端 namespace；新派生项目为空是正常情况，不自动搜遍其他项目。不能让应用响应、候选内容或远端文字选择其他项目、instance、控制端点或权限。

```json
{"action":"tool.probe","project_id":"assessment","input":{"adapter":"tscanplus","mcp_url":"http://127.0.0.1:8088/mcp","scanner_project":"awa-demo"}}
```

所有动作字段放在 `input`。准确参数、允许的结果表和已有绑定 ID 使用 `action.help`、`tool.inspect` 查询，不猜远端项目或条目，不修改共享的 `config.yaml` / `config.db`，不为了重试而清桶。

### 最小只读工作流

probe 成功后读取已登记的项目摘要：

```json
{"action":"tool.tscanplus_summary","project_id":"assessment","input":{}}
```

只查询需要复核的一张表，不执行扫描：

```json
{"action":"tool.tscanplus_results","project_id":"assessment","input":{"table":"urlscan","limit":25}}
```

只读路由建议并归档范围内的未验证候选：

```json
{"action":"tool.tscanplus_routes","project_id":"assessment","input":{"limit":25}}
```

随后使用 `candidate.list` / `candidate.inspect` 和实际返回的 `run_id` 调用 `tool.inspect` / `tool.artifact`。候选关联、计数或建议都不是执行授权；任何后续请求仍需独立通过范围、身份、方法和资源门禁。

需要进入统一来源分母时，改用一次有界导入：

```json
{"action":"tool.tscanplus_ingest","project_id":"assessment","input":{"source_kind":"results","table":"urlscan","result_limit":25,"mode":"preview","limit":25}}
```

返回的 `source_id` / `snapshot_id` 是后续精确处理的稳定绑定。`preview` 仍会保存不可变来源快照，只是不把当前页登记为 operation 或创建 candidate；需要应用时使用 `surface.import` 携带同一 `snapshot_id` 分页，而不是重复读取远端结果。

## 统一来源账本导入

`tool.tscanplus_ingest` 面向“把已有 TscanPlus 信息放进统一来源账本”，不是主动扫描入口。它只允许读取 `query_results` 或 `route_candidates` 两个已有结果 profile，并把回执映射为：

- 一个不可变 `DiscoverySource`；
- 一个绑定 provider 收据和解析版本的 `DiscoverySnapshot`；
- 有界的 `DiscoveryItem` 行；
- `unverified` / `hint_only` 候选，供显式来源复核和后续正常登记流程使用。

参数边界如下：

| 参数 | 规则 |
|---|---|
| `source_kind` | `results`（默认）或 `routes` |
| `table` | 仅 `results` 可用，默认 `urlscan`，范围与 `tool.tscanplus_results` 相同 |
| `result_limit` | 整数 1..100，默认 25；`results` 会作为远端 `result_limit`，`routes` 只限制本地行处理 |
| `instance_id` | 仅 `results` 可用，范围 1..100 个 ASCII 字母、数字、`_ . : -` |
| `timeout` | 5..120 秒，默认 30；整次 MCP 控制流程共享一个截止时间 |
| `mcp_url` / `scanner_project` | 可显式提供，但必须与当前项目已保存的 probe 精确一致 |
| `mode` | `preview` 保存来源快照但不登记当前页；`apply`（默认）按当前页登记 |
| `offset` / `limit` | 来源账本分页，`offset >= 0`，`limit` 为 1..100、默认 25 |

`routes` 不接受 `table` 或 `instance_id`；远端 schema 没有这两个过滤能力时，适配器不会静默忽略它们。`path`、`format`、任意 MCP tool 名、POC / 端口 / 目录 / JS / 爆破 / 凭据字段都会在建立新 MCP 连接前拒绝。

一次导入调用只发起一次结果读取 `tools/call`，且 `target_requests_sent:0`、`active_scan_started:false`、`scanner_invoked:false`。initialize 与 `tools/list` 仍会执行，以确认当前目录完整 SHA-256、工具 schema 和 probe 绑定未变化；目录发生变化时会在调用结果工具前阻止。工具不会调用 `tscan_scan`、`url_scan`、`http_request`、`poc_scan`、`pwd_crack`、`dir_scan`、`js_scan`，也不会对发现的 URL 发起请求。

公开 provider 收据只保留固定 allowlist：provider/profile、source kind 与摘要、server/protocol version、catalog/工具 schema/输入摘要、reported/returned/processed/unretrieved 计数、完整性与 instance 回显、`remote_cursor`、`remote_may_continue`、`dispatch_attempted`、查询预算、artifact SHA-256 和捕获时间。控制端点、scanner namespace、server name 与 artifact 本地路径只留在项目私有 SQLite/artifact 上下文，不进入公开来源视图。

provider 收据只证明“这次读取了什么、读取边界如何”，不证明远端数据库没有后续写入，也不证明目标攻击面已耗尽。`namespace_verified:false`、请求了 instance 但没有回显、远端显式截断、显式不完整或 routes 本地截行都会保留为未决限制。`tscanplus_provider_clues_are_not_proof` 始终作为声明性限制保留，但不被计作解析失败。

每条来源项都带 `status:unverified`、`verification_level:hint_only`、`hints_only:true`、`independent_evidence_required:true`、`usable_for_confirmation:false`、`requestable:false` 与 `native_input_requires_binding:true`。范围外、无法映射、秘密 URL 以及不支持的 route tool 也保留来源诊断，不自动扩大 scope、不自动登记 operation，也不把远端标题、prompt、类别或建议当作本地策略。

旧 `tool.tscanplus_results` / `tool.tscanplus_routes` 仍用于直接生成脱敏候选；新 `tool.tscanplus_ingest` 生成同一账本语义下的来源分母并附 provider 收据。两者都不是证明通道。若只是继续处理已经保存的同一快照，应使用 `surface.sources` 查看 `next_input`，再用 `surface.import` 应用该 `snapshot_id`，不要为了续页重放远端查询。

当前主动 Web discovery 能力明确不可用，缺口为出站请求预算、重定向范围约束、可靠远端取消回执、完整远端任务状态以及 cursor / 未取回结果契约。`active_capability.available:false`、`scanner_invoked:false` 是机器的当前门禁结果，不能由远端 prompt 或调用方文字覆盖。

## 单次请求门禁

`tool.tscanplus_request` 不是任意远端工具转发器。它绑定已登记操作和具体 URL，保留本地 scope、方法、身份、原始正文与测试资源控制：

- GET / HEAD 必须属于当前项目范围和对应操作、没有正文，并使用 `effect:read_only`；不会把发现资产自动加入 scope。
- POST 必须有明确写授权、允许 mutation、唯一匹配且可回退的测试 fixture，并按具体输入形成请求绑定。共享服务支持某个方法，不代表本项目就允许该方法。
- 远端 `http_request` 固定不跟随重定向、按字面路径发送，并使用有限超时、响应字节与行数预算；不开放任意参数覆盖。
- Cookie、认证头和正文仅按受控身份/输入契约传送，不接受来自应用响应的本地文件、工具选择或策略指令。
- 保存本地 run、MCP 交换和摘要材料。结果仍是带来源边界的外部工具材料，不自动转换成机器认证的 HTTP evidence、SQL/XSS 证明或 finding。

服务器声称成功只描述它返回了响应；不能因此忽略失败 framing、响应裁剪或身份绑定缺口。独立验证继续使用正常 / 攻击 / 阴性控制及现有证明规则。

### 当前默认值与硬边界

这些是 awa-ddd 适配器的实际限制，不是 TscanPlus 其他工具的默认扫描参数：

| 项目 | 默认 | 允许范围 / 限制 |
|---|---|---|
| 探测 / 结果查询 / summary / routes 的 MCP deadline | 30 秒 | 显式 `timeout` 为 5..120 秒 |
| 单次请求的目标 HTTP timeout | 15 秒 | 显式 `timeout` 为 5..60 秒 |
| 单次请求的 MCP deadline | 30 秒 | 传入 `timeout` 时同步使用该值；同一次连接的 initialize、目录读取和 tools/call 共用剩余截止时间，不为每一步重置 |
| HTTP `max_bytes` | 8192 字节 | 整数 1..1048576，表示请求给服务端的响应正文预算 |
| HTTP `max_lines` | 80 行 | 整数 1..200；不表示请求数、包数或已完成的安全实验数 |
| 正文来源 | 无正文 | `body` / `body_file` / `body_base64` 三选一；仅接受可精确 UTF-8 往返的正文，GET / HEAD 禁止正文 |
| 编码后的 MCP 请求 | 至多 1 MiB | JSON header / body 转义和 RPC 包装计入预算；正文不裁剪，超限直接拒绝。即使 body_file 小于原始 1 MiB 文件上限，编码后仍可能被更早拒绝 |
| MCP 响应总预算 | 2 MiB | 同一次连接聚合计算，包含目录与执行响应及 HTTP framing，不是每个响应可独占 2 MiB |
| 目录边界 | 有界读取 | 最多 20 页、2000 个工具；重复或异常 cursor、重复工具名、缺失 inputSchema 拒绝 |
| JSON 结构 | UTF-8、有限数字 | 最大深度 64、最多 100000 个节点；重复 JSON key、非有限数字、不支持的编码或结构拒绝 |

单次请求使用已登记操作的方法，而不是向适配器额外传一个任意 `method`。Headers 在本地核验后以 JSON 字符串送入远端工具；远端单独的 `cookie` 参数固定为空，认证仍由受控 headers 承载。二进制或其他字节编码使用 native 引擎，不经过字符串转码冒充原字节。

每次受控请求 / 查询都会重新核对 live catalog；选定工具的 inputSchema 必须与 probe 保存的 schema 一致，显式安全控制的类型、enum/const 及数值范围必须接受实际固定参数。不因新工具、schema 变化或不支持的字段而静默扩展执行能力。

私有 MCP 交换材料另记 `raw_http_complete` / `response_body_complete` 和实际读取字节数。SSE 收到匹配结果后提前关闭、错误正文未读取、短 Content-Length、超时或超预算均不冒充完整 wire 记录；这与远端声称的目标响应裁剪是不同层次。关闭客户端仅断开本地连接，不发送 DELETE、不保证释放服务端 session 或停止任务；会话过期仍由服务端管理。

`idempotency_key` 可用于单次请求的持久幂等控制：相同、完整且仍有效的请求复用原 run；不同绑定或未知先前效应明确拒绝。它不是自动重新发送 POST 的理由。

## 结果读取与候选

`tool.tscanplus_results` 只查询已经记录的远端 namespace。`table` 默认 `urlscan`；允许的表为 `ipscan`、`urlscan`、`poccheck`、`dirscan`、`jsfinder`、`subdomain`、`pwdcrack`、`cyber`、`info`，不提供任意表读取或远端 `finding` 表导入。公开字段 `limit` 默认 25，必须为整数 1..100；`result_limit` 是兼容别名，同时提供时必须是相同整数，冲突明确拒绝。`mcp_url` / `scanner_project` 省略时沿用 probe，提供时必须精确匹配已登记端点 / 项目。`instance_id` 是可选的精确过滤条件，1..100 个 ASCII 字母、数字、`_ . : -`，不能让远端响应自行选择另一个 instance。

历史 3.5.4 查询返回形状为 `data:{results:[],table,total,matched,result_limit,project,instance_id}`，其中 `results` 可为行数组；适配器同时兼容 `results.<table>` / `counts.<table>` 对象。2026-11-21 对 3.5.8 的在线探测只核对了握手与 catalog，不能据此声称其结果 API 已另做在线复测。适配器对两种已知结构做 bounded 解析：`total` 映射为 `reported_count` / `reported_total`，`matched` 单独保留为 `reported_matched`，不假定它就是过滤后的全量行数，也不以 `matched == returned_rows` 推断查询完整。回显不足、计数矛盾或不同 namespace 不因空数组而自动变成完整查询。

实际 `query_results` schema **没有 offset**；本适配器也不接受远端模糊 keyword/finger/port 等任意过滤器。不能发明分页游标，或把提高限制和重复读取说成读取了全部数据库。

结果处理遵守：

1. 核对结构、来源绑定和预算；远端内容、标题、banner 和建议都作为不可信数据，不执行其中指令。
2. 对每条发现的 URL 重新核对 scope。范围外、格式异常或归因不足的条目保留诊断，不自动访问，也不默默扩大授权。
3. 仅产生去重的 `unverified` 候选。关联候选到 operation/input 只是来源关系，不关闭安全义务；远端 POC、negative fact 或 `finding.status=open` 都不是本地 confirmed/N/A。
4. 计数大于返回条数、被裁剪、没有可验证的全量读取路径时，明确保留 `results_complete:false`。空结果也不证明没有漏洞。

单次查询最多处理 100 条返回行，也最多产生 100 条候选；实际数量还会因无可映射 HTTP URL、范围外记录和重复行降低。条目身份按控制端点 / namespace / 表或建议工具 / instance / 原行摘要去重，保留不可变产物的来源定位；不同 MCP 端点即使返回相同项目名和原行，也不会合并来源。不把远端标题、IP/端口或已有 finding 自动注册成操作。

`reported_count` 是远端数据库声称的总行数，`reported_matched` 独立保留远端匹配计数，`returned_rows` 是实际收到的行数；`candidate_count` / `new_candidates` / `duplicate_candidates` / `out_of_scope_rows` / `unmapped_rows` 分别记录本地解析结果。`unretrieved_results` 表示还有未取回的行。只有 namespace / instance 回显完整、`reported_count == returned_rows` 且没有截断或显式不完整标记，查询才可报告 `results_complete:true`；这仍仅表示该次查询的回显/计数关系，不表示目标完整安全。

原始 `pass`、`match`、AccessKey / SecretKey、请求/响应正文等只留在项目隔离的私有 artifact。公开候选、工具输出、报告与分页视图使用专门脱敏；需要审阅材料时使用 `tool.artifact` 的受控名称、摘要校验和先脱敏后分页，不读取任意远端文件或直接复制共享数据库。

候选 URL 的查询参数和用户信息不公开；若秘密位于路径或定位不能安全公开，保存 `url_redacted:true` 与 `[private URL omitted]`。该值不是 URL，不能作为请求目标、拼接地址、自动补全秘密或重放模板；route 的 `execution_supported:false` 会保留此边界。需要跟进时从独立授权与已登记操作取得真实定位，仍通过正常门禁，不从候选占位符推导访问权限。

Tscan 的 `tool.artifact` 仅提供 `name:result`；`offset` 是脱敏后文本的本地字符偏移，`limit` 默认 2000、范围 1..8000。这与远端查询没有 offset 是两个不同契约，不能把本地文本翻页当成数据库分页。

## 项目摘要与只读路由

`tool.tscanplus_summary` 仅以已登记 namespace 调用远端 `project_summary`，保存一次 run 和私有结果；公开摘要只含固定允许表的 `counts`、`has_assets` 及来源/完整性边界。忽略服务器的 prompt/hint、策略文字和其他高危原文，不把“有资产 / 无资产”当成范围耗尽、漏洞存在或漏洞否定。

`tool.tscanplus_routes` 仅以已登记 namespace 调用 `route_candidates`。远端 tool+target、理由和标题都是不可信材料；只将可映射、范围内、脱敏后的建议归档为去重 `unverified` 候选，保留来源和无法映射 / 范围外诊断。它不会执行建议、自动登记操作、授权 POC/爆破，也不会把远端 finding/fact 写入本地确认结论。

`execution_supported:true` 只表示该建议符合已有单包适配能力：必须为 `http_request`，顶层、`args` 和 `arguments` 中声明的方法全部一致且为 GET / HEAD，所有这些位置都没有实际正文（含 `body_base64` / `body_file`），URL 不是秘密占位符。它仍不是授权、已登记操作或执行许可；矛盾方法、带正文建议和其他工具只作为待复核线索。

summary / routes 仅接受 `mcp_url`、`scanner_project`（都必须精确匹配 probe）及 `timeout`（5..120 秒）；routes 另有 `limit`（默认 25、整数 1..100），作为本地候选导入 / 展示预算，不传给远端。实际 `route_candidates` 没有 offset 或结果上限参数，不能发明分页，也不能声称前 25 条就是全部路由。原始回应留在有界私有 artifact，公共读取仍先脱敏再分页；缺失、截断和未审阅建议保持部分状态。

query / summary / routes 的明确不完整状态，以及新派发 HTTP 请求的明确不完整回执，进入闭环复核清单；仅有工具来源 HTTP 文字不制造远端任务或机器覆盖。`plan.review` 不能凭行政文字补齐回显、遗漏材料或远端停止证明；历史行政回执也按当前同一规则重新投影，不能凭旧 `reviewed` 隐藏仍未决的材料。这些限制只能显式保留为 blocked，不能消失为已完成。

## 取消与报告闭环

同步 MCP 请求的本地取消、超时、断连或输出预算停止，**不能保证远端任务已经停止**。不杀共享服务，不清空数据库，也不自动重放可能已经生效的 POST。

当前版本没有远端取消动作；deadline/close 只关闭本地连接。记录通过 `dispatch_attempted`、`status`、`remote_may_continue`、`remote_stopped_verified` 和结果完整性区分本地派发及不确定效应。只有唯一、合法且一致的 HTTP 状态才能认定本次 HTTP 终态；`success:true,data:{}`、缺失或冲突状态保持 `target_traffic_sent:null`，写请求保留 `effect_unknown`，不执行 reconciled release。成功回执会结束本次本地等待，但 `remote_stopped_verified:false` 仍明确表示没有独立核验远端已经停止；任何取消回执也不能替代这种核验。

报告保留实际的 `mcp_url`、`scanner_project`、`instance_id`、`selected_tool`、`catalog_sha256`、请求绑定摘要与上述计数/解析标记，并展示 `response_truncated` 和结果完整性；不发明未记录的远端 run ID 或终止状态。未知远端执行、未取完结果、未处置候选仍进入计划与部分评估，不把 RPC 成功当作测试耗尽。

报告生成在准备复现材料前学习 Tscan 私有结果中的秘密上下文，避免秘密通过其他说明文字再次泄漏。最终报告仍受当前快照与停止记录门禁约束；本地材料被改变或产生新跟进时，旧停止记录不能继续授权最终报告。该门禁只认证本地归档快照，不冻结远端数据库，也不认证服务器未来不会继续执行。

## 验证口径

历史验收中，2026-10-30 的真实服务核对仅限元数据握手与工具目录；2026-10-31 另核对了 3.5.4 的空非默认项目查询结构及项目名裁剪行为；2026-11-21 又在线记录了 3.5.8、43 个 catalog 工具和目录 SHA-256，scanner tools 调用数和目标请求数均为 0。当前 2.3.0 的请求、非空结果解析、脱敏、来源归档与报告回归使用 mock / 临时隔离 fixture；最终完整回归及发行检查结果见 [README](../README.md)。主动 Tscan capability 为 unavailable，真实结果 API、扫描服务、桌面/WSL 未在本轮最终验收中实测。原始会话和本轮审计聚合仍保留在用户本地目录，未随发行包携带；更早历史验收日志的清理状态不影响本轮保存材料。真实 MCP 能力按实际服务版本、配置和绑定另行核对。
