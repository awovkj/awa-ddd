# 2026-11-21 升级：可靠执行、领域闭环与来源账本

日期：2026-11-21。基线版本：2.2.0，Git HEAD `3bbee45cf2464f6ff0a5ff4a96e0cfd090ebdea0`。本次为工作区实现与本地验收，完整路线见 [优化、升级与渐进重构方案](REFACTOR-PLAN-20261121.md)。

历史会话已有 Actuator mappings 材料，API 子集的 73 个 method/template 对中只有 13 个能与登记账本唯一对应，留下 60 个已知来源候选未登记。末态仍为 partial，四份报告均为 draft。本批修复让已保存来源进入分母，并让导入、冲突及解析缺口有可继续处理的精确交接；这些历史数字是审计事实，历史项目与会话材料未被改写或重新执行。

## 工作区实现范围

### 1. 测试基线与并发分类

- Windows 的 WSL 判断先按实际 OS/平台短路；native 元数据使用 `sys.getwindowsversion()` 或 `os.uname()`，平台查询不会受到全局 subprocess fixture 的副作用影响。
- `plan.next`、`http.preflight`、`assessment.prepare` 写入 SQLite 原子 advisory 记录，因此从 Node 纯读并发集合移除；旧 `.loop_guard` sidecar 只在首次读取时为计数提供兼容种子，不作为执行事实。`scenario.preflight` 与新 `surface.sources` 继续按实际只读行为分类。
- 宿主取消与超时 fixture 先确认真实请求已分派，再触发 ABORTED/ENGINE_TIMEOUT；检查只发一次请求、保守保存 unknown，并交接 `run.inspect/run.recover`。

产品 bridge 的启动/接收/分派阶段 IPC 回执、SQLite 原子 advisory 状态、部署源码指纹、可核对执行预算与 unknown-effect 恢复均已接入。重复查看任务页不再改变 readiness 或 preflight 动作状态。

### 2. 不可变来源与有界交接

新增四类账本实体：

| 实体 | 身份及职责 |
| --- | --- |
| DiscoverySource | 格式、规范化本地路径、去除 query 的 base URL 决定身份；指向最近一次导入的 snapshot |
| DiscoverySnapshot | Source ID、原字节 SHA-256、parser version 决定身份；保留 inventory、limitations、规范化 manifest 摘要与 item 清单 |
| DiscoveryItem | Snapshot ID、operation/candidate 类别、规范化 hint 决定身份；保存原始来源声明 |
| DiscoveryIngest | 精确 source item 到 operation/candidate 的交接回执；重复交接保持幂等 |

所有现有本地格式均返回相同 source envelope：OpenAPI、JavaScript、HAR、ARTEX、SARIF、assessment_hints，以及新 Actuator mappings。空结果仍保存字节摘要、格式、parser version、字节数与 limitations。单文件最多 8 MiB、单次解析最多 10,000 个 rows，项目最多保留 50,000 个 source items。

`surface.import mode:preview` 只保存来源实体和事件，完整保存解析器的有界结果；offset/limit 只控制展示。preview 不创建 operation、obligation、candidate、run、evidence、decision 或 finding。

`mode:apply` 每次只处置当前 `offset:offset+limit`，默认 25、最多 100 项。本次返回的 counts、operation_ids、candidate_ids 仅描述该页。未来仍有 pending 项时，`next_action:surface.import` 与 `next_input` 指向同一 snapshot 的下一批原始位置，并跳过已经交接的后续页；早先尚未交接的项继续由审计 checklist 定位。没有后续批次时返回 `surface.sources` 与 `next_input:null`。

精确 `snapshot_id + mode:apply` 不重新读取文件，也不允许同时传 path/format/base_url。文件内容后来变化或文件删除不会改变已经保存的快照。按文件重新导入时，字节或 parser version 变化创建新 snapshot，历史项和 pending 均保留。OpenAPI parser version 为 2，其余当前格式为 1。

保存的 manifest/item 缺失、摘要变化、身份或所属来源不一致会拒绝 apply；按原路径重新导入也先验证既有保存材料，不能通过重读绕过损坏。同字节、同 parser version 的合法保存材料若与新解析输出不一致，则返回 `source_snapshot_conflict`，要求更新解析器版本。

### 3. Actuator 与 OpenAPI 模板规则

Actuator 支持 Spring Boot `contexts.*.mappings.dispatcherServlets` 与 WebFlux `dispatcherHandlers` 中的结构化 `requestMappingConditions`。方法与 pattern 按显式笛卡尔积归一化，重复路由合并来源；不从 handler/predicate 自由文字猜测 GET 或路径。

只提取 params/headers 的输入名，兼容字符串条件和 `{name,value,negated}` 对象；不保存条件值、handler/predicate 内容，不推断 body、consumer 或访问策略。Actuator 必须有明确的绝对 base URL。

两个解析器共用严格路径分类：唯一、完整路径段的 ASCII `{var}` 可成为模板操作，并增加精确必填 path input；wildcard、regex、编码变量/通配符、重复变量、非法变量名及部分段模板保留为候选。简单模板和复杂候选都不能直接执行，公开结果保留真实输入绑定前提。OpenAPI 的媒体类型、请求体 schema、分支和 auth 声明继续保留。

Actuator 的 malformed context/mappings/dispatcher/group、缺少可用 dispatcher、非法或缺失方法与路径都会计入 unresolved。即使没有任何 rows，也不会显示“解析完整”。snapshot inventory 保留 mapping、handler identity、route、path template、method 和 unresolved 计数；它们仅说明这一份材料的清点状态。

### 4. 来源差集、完成判定与恢复

`surface.sources` 为只读分页入口，支持 source_id、snapshot_id、status、offset、limit 和绑定当前投影 generation 的 cursor。未指定 source 时列来源；指定 source 时默认其最新快照，指定 snapshot 则读取精确历史快照。`status:pending_import` 包含尚未交接的 candidate/conflict/rejected，不只匹配一个状态字符串。

指定当前 `snapshot_id` 和同一来源的 `compare_snapshot_id` 可比较已保存快照，独立返回 `comparison` 的 added/removed/changed/unchanged、精确 item ID、changed_fields 和分页偏移。比较只认证已保存的不可变材料，不重新读取源文件，不删除旧项，也不发送请求；不同来源的快照拒绝比较。来源投影在相关 operation/candidate/ingest 绑定变化时局部更新，新增或改变 snapshot 则重建来源投影。

主状态、audit、plan 页面、普通/compact next 和 draft report summary 公开相同 `source_inventory`：

| 字段 | 口径 |
| --- | --- |
| known_route_total / registered_route_total / known_not_registered_total | 已保存来源中的精确 `(URL, method)` 集与现账本差集；媒体类型或 operation variant 不重复增加 route 分母 |
| source_item_total / pending_import_total | 来源 profile/item 数和未交接数；item 保留媒体类型与输入声明差异 |
| historical_pending_total | 被较新快照省略、仍未完成交接的历史项 |
| needs_binding_total | 尚需真实 URL/资源或原生输入绑定的模板与候选 |
| conflict_total / rejected_total / candidate_total | 来源项的实时账本状态；保留来源和原始策略 |
| unresolved_total | 当前来源真实解析缺口、损坏/缺失材料；普通证据免责声明不虚构解析缺口 |
| site_wide_discovery_allowed | 固定 false；来源登记不提供全站完整性声明 |

`completion` 增加 unimported_source_items、source_conflict_total、source_unresolved_total。只有来源而没有操作时，状态为 partial，续接到 sources。审计清单按精确 snapshot 和最早未应用的原始 offset 生成 apply 模板；损坏、缺失或解析不完整的材料走只读检查。来源冲突已由现有候选证明门合法闭环时，不会仅因历史来源声明仍矛盾而永久阻断完成。

最新 snapshot 被删除后，sources 保留可读来源，输出 `snapshot_integrity:missing`、非零缺失提示及 `source_snapshot_missing`，不构造不存在的 snapshot handle。未知容器计一项 unresolved，未知 route/item 数不被捏造为完整分母。保存材料变化时输出 `snapshot_integrity:changed`。两类状态都维持 partial 与只读恢复提示。

### 5. 策略合并与公开契约

来源不能覆盖已登记的 auth、roles、ownership、state_scope 或 input consumer/test family/schema 策略；未知来源声明保留本地明确值，已知矛盾保留原 operation 并交接未验证 conflict candidate。scope 外 hint 保留 rejected 状态，导入全过程 `requests_sent:0`。

Python publication 与 Node 工具 schema 同时支持来源、快照、item、counts、完整性及 next_input。真实绑定 ID、digest、计数和动作模板在短秘密碰撞或脱敏上下文不可用时仍可恢复；路径、URL、selector 继续作为不可信 locator，不能因公开输出恢复为执行许可。preview 的公开输出失败会回滚本次离线来源写入。

Node 的展示上限仍为 24 KiB。import 截断的 `render_recovery` 用只读 sources 读取同一 snapshot 当前页，不能重放写入来补展示；源分页保留过滤条件和精确快照。当前 V1 动作数为 75；相对原 67 个动作新增 `execution.reconcile`、`plan.accept_partial`、`project.migrate`、`project.projection`、`project.rollback`、`report.artifact`、`surface.sources` 和 `tool.tscanplus_ingest`。V2 目录为 41 个动作，与 V1 共享 17 个，并集为 99 个；各模式数量不能相加当作独立动作数。常驻工具提示和随包 SKILL 继续低于既有 25,000 / 10,240 bytes 预算；细节通过本说明按需读取。

### 6. TscanPlus 既有结果只读接入

`tool.tscanplus_ingest` 已把 TscanPlus 已有结果接入统一来源账本。它只接受 `query_results` 和 `route_candidates` 两类只读 profile，结果条数限制为 1..100，并要求当前连接与保存的 probe、短 namespace、完整工具目录摘要和所选工具 schema 一致。每次调用先完成 `initialize` 与 `tools/list`；目录 SHA-256 与保存值不一致时，在 `tools/call` 前失败关闭。

远端读取前先把 `dispatch_attempted`、规范化请求 SHA-256 和 `remote_may_continue` 写入 durable run，再发出 IPC dispatch 回执，最后才调用远端。provider 回执保留协议版本、目录/schema/请求/artifact 摘要、返回与省略计数、截断、结果完整性、namespace/instance 回显和查询预算。来源不是所请求 namespace、instance 回显缺失、结果被截断、显式不完整或本地省略时，均进入来源限制和 completion 缺口，不会因计数相等或远端成功声明而变成完整。

结果行只映射为 `unverified`、`hint_only` 来源候选：`requestable:false`、`usable_for_confirmation:false`、`execution_supported:false`，route 推荐工具永不执行。公开 `surface.sources` 隐藏 provider 端点、服务器名、namespace、artifact 路径和私有伪来源路径，私有 SQLite 仍保留完整审计回执。`preview` 保存整份有界快照；后续按精确 `snapshot_id` 使用 `surface.sources`/`apply` 翻页时不再连接 provider，重复 apply 保持实体与候选幂等。

当前只开放“读取已有结果”。`active_capability.available` 固定为 false，并明确列出仍缺少的出站请求预算、重定向范围策略、可靠远端取消回执、完整远端任务状态和 cursor/未取回结果契约；报告同时固定 `scanner_invoked:false`、`target_requests_sent:0`，不把控制面读取解释为目标扫描。

### 7. 领域闭环、Campaign 隔离与统一完成判定

`awa_ddd/domain/taxonomy.py` 现在是测试族的唯一机器目录。V1 覆盖、V2 hypothesis、recipe、proof profile、Node 公开契约和报告矩阵必须使用同一族集合；未知族只保留为隔离材料，不能进入“已覆盖”。

Campaign 查询和写入强制绑定 campaign/universe。attempt、recipe、run、finding、proof receipt、gap、lease 与 checkpoint 不再从其他 campaign 借用当前事实；migration 遇到无法归属或 universe 冲突的历史记录时只写 quarantine，不自动塞入最新 campaign。Universe 转换继续携带 ownership、allowed roles、tenant 与 state scope，recipe 和证明消费时重新核对完整上下文。

`ApplicabilityReceipt`（AR）绑定精确 obligation/property、否定谓词、source/build、scope、材料 SHA-256 和证据依赖；普通响应或自由文字不能生成它，材料字节、build、scope 或依赖发生变化后旧 receipt 立即不再 current。`ReviewProofReceipt`（RPR）只接受已定义 family 的 typed reviewed detection，要求正/攻击/阴性控制、身份和 readback 完整；它明确标记 `machine_proof:false`，不能冒充机器确认。

`CompletionEvaluator` 是 V1/V2 共用的唯一完成对象。它同时核对范围、当前证明/适用性/review、source 完整性、material currency、checkpoint 和 frontier；输出稳定 `CompletionDecision`，供 status、next、checkpoint、finish、report 与宿主续接共同读取。bounded partial acceptance 是独立状态，永不赋予 exhausted authority、automatic stop 或 final report 权限。

上述 partial receipt 是持久、幂等且串行的**交付接受记录**。它不完成 campaign、不关闭剩余 ready/review/blocked/unresolved 工作、不生成停止授权、不授予最终报告，也不暂停正常宿主续接；相同 checkpoint、接受者和解释的重复调用只复用首个 receipt。

### 8. 增量读模型与兼容迁移

SQLite 增加分页和状态索引、generation 绑定的 `projection_store`、来源投影、ready queue 与稳定的 cursor。普通 `status/list/next/audit/sources` 读取可复用 advisory projection；证明消费、checkpoint、finalization 和正式报告仍执行强材料校验。可能授予完成权且缓存值接近 complete 的查询会强制重建，缓存不能单独授予 authority。

`project.projection mode:inspect|rebuild|compare` 全部离线。`compare` 将持久投影和当前强评估逐项比较；`rebuild` 只重建派生数据；三者都返回 `requests_sent:0`。投影有效的普通查询只解码当前 SQL 页，count 使用独立聚合；强重建成本另计。

`project.status` 与 `report.coverage` 的方法矩阵增加 `method_operation_offset`（默认 0）和 `method_operation_limit`（默认 10，1..100）。每个方法分别返回 `operations_total`、`operation_offset`、`operation_limit` 和 `operation_next_offset`；调用者按各方法的下一偏移继续读取，不能把第一页 operation ID 当成完整方法集合。SQL 使用 `json_remove` 与 `json_each` 提取当前 ID 窗口，内部强评估仍保留完整矩阵。`method_operation_ids_returned` 记录返回的 ID 数量，普通 next 的跟进预览最多 3 条，全部跟进计数和 audit 分页继续保留。

强评估在同一次调用内复用已读取的 operation、obligation 和 run 集合，并索引精确 input、auth replacement 与 browser page 关联，减少重复读取和嵌套查找。浏览器页面列表替换、增减时会重建关联索引；同一 operation ID 的 URL、query 或 method 变化会重新查找。该索引面向单次评估的页面集合，不是监视任意原地字段修改的长期缓存。

存储元数据仍为 `schema_version=1`。本批新增表、索引、投影和 ledger 使用 additive 初始化（`CREATE ... IF NOT EXISTS`，已有预算表只追加 `budget_unit` 列），不把 `schema_version` 提升为 2，也不改写旧 operation/evidence/decision/finding。需要改变领域投影或兼容视图时，另由显式 `project.migrate` 生成 `SMIG-*` 和私有备份，不能用 “schema_version 1 additive” 冒充完整数据迁移已验证。

性能边界必须按当前实现描述：warm 普通页只 hydrate 当前 SQL 窗口并复用 advisory projection；artifact locator 列表按 durable entity generation 缓存，目录内材料通过一次 `os.scandir` 批量读取当前文件元数据，少量同目录材料使用直接 metadata 检查。元数据统计不跨查询缓存，也不作为完成或证明权威。查询仍会核对全部保留材料的当前 metadata，强重建、强 compare、proof consumption、checkpoint/finalization 和正式报告仍运行全局强评估。`material_bytes_hashed` 与 `artifact_bytes_hashed` 累计实际读取字节；下一次强校验仍读取原材料，不复用真实性缓存。2,000 operations / 20,000 evidence / 500 pages 的测量结果和冷热条件在下文分别列出，不能据此宣称任意查询都与历史规模无关。

`project.migrate mode:dry_run` 使用稳定只读连接，零写入、零目标请求且重复结果字节稳定；`apply` 先核验全部引用 artifact，再在受控临时目录生成数据库快照、内容寻址私有材料备份和完整 manifest。所有复制与摘要成功、文件句柄关闭并通过 `fsync` 后，才用同目录原子 rename 发布正式 `SMIG-*` 目录；任何 copy、hash、manifest 或发布失败都不会留下看似正式的半成品。旧版可识别的 `.incomplete` 备份会改名保留为 `.interrupted-*` 后重试，未知或不匹配目录失败关闭且不删除。迁移绝不伪造 TestRun 或证明。旧 N/A 缺 receipt、旧自由文字 analyst 结论和未知 taxonomy 保持 legacy/unverified；campaign 归属不明的事实不会自动归给新 campaign。

`project.rollback ledger_id` 先验证 `SMIG` 与完整备份，再切到 `legacy_read_only` 兼容视图。迁移后产生的新事实继续保留，rollback 不删除、不覆盖也不重放请求。

### 9. 执行协调、双层 dispatch 与不确定效应

`execution_coordinator` 把实验 lease、单调 fence、请求/写预算、dispatch 去重和 reconciliation 放在同一 SQLite UnitOfWork 中。预算在真实 dispatch 前原子扣减；耗尽时不会创建 dispatch receipt。旧 worker 的唯一 `(lease, fence, action, run_id, request_hash)` 不能再次获取预算或提交同一次请求。

每次真实派发持久化 `DSP-*` dispatch receipt，并通过 nonce 和请求 SHA-256 绑定的 `startup -> accepted -> dispatch` IPC 阶段向宿主报告。调用方或远端 envelope 不能把尚未派发的请求改成 uncertain，也不能抹掉已有的 dispatch 证据。仅在启动阶段失败时可判定“未派发”；accept 后异常、超时、子进程退出或输出损坏均保守保留 unknown effect，禁止自动重放。

Browser 与 sqlmap 使用完整的两层 dispatch：

1. 外层 `provider_invocation` lease/budget 在启动 provider 前记录；
2. 内层每个真实 wire request 在发送前再次记录独立 request-slot dispatch；两层都保留同一 accepted-request hash、run/fence 和预算回执。

外部 provider 和 browser 只有在成功 terminal artifact 持久化后才释放 lease；异常、取消、超时、读取不完整或未知写入继续保留 lease/run。HTTP 只读失败也只有在精确 durable wire result 证明该次请求已结束时才可 reconciliation。`execution.reconcile` 只接收当前完整证据和精确 same-identity fixture readback，生成内容寻址 `REC-*`；它永远返回 `requests_replayed:0` 和 `requests_sent:0`。

### 10. 宿主续接、回执与报告发布

V1/V2 的 status、checkpoint、finish 和报告共享同一 `CompletionDecision`。V2 `campaign.finish reason:completed` 生成不可变 completion acceptance；`reason:partial_accepted` 保存 bounded delivery，但明确撤回 exhausted authority。V2 report draft 可独立交付，final 必须同时绑定 completed campaign、exhausted authority、current checkpoint、同一 `CompletionDecision` 和不可变 acceptance。

`plan.checkpoint` 在完整 frontier 时生成内容寻址 `FRC-*`；`plan.accept_partial` 针对当前 partial checkpoint 生成不可变 `CA-*`。CA 记录 acceptance identity 与解释，只表示“这份当前部分交付已接收”；它保持 `continue_required:true`、`can_claim_complete:false`、`automatic_stop_allowed:false`，不暂停正常宿主续接，也不触发目标请求。stale checkpoint、已可 finalize 或已耗尽快照均拒绝接受；同内容重复调用幂等。

Node 将 `plan.accept_partial` 作为串行、OFFLINE mutation：不在并发读集合、不在 target execution 集合，不提供网络 follow-up，也不把 acceptance 当成完成或停止信号。Python 端在项目事务内只读写本地账本和证据，返回 `requests_sent:0`。宿主 continuation 可以记录这次 bounded delivery，但当前 ready/review/blocked/unresolved 工作和 frontier 门禁继续生效。

报告发布统一使用脱敏后的临时批次和原子目录提交。manifest、report、matrix 和复现材料全部写入并自检后才发布；失败不会留下半成品正式目录。凭据和私有 capsule 不进入公开报告；新 provider receipt 与来源页只保留固定 allowlist，隐藏控制端点、namespace 和本地 artifact 路径。既有 Tscan run 检查与报告的绑定元数据仍按原契约脱敏公开，不把远端状态文字当作证明或停止回执。

公开输出中的关联 ID、摘要、枚举、布尔值和计数按字段契约恢复，ID 同时核对精确命名空间和实际账本；凭据恰好与这些控制值相同时，也能保留合法关联。可选字段与联合类型先选择匹配的 schema，再执行闭合字段清单，工具对象不会再触发类型恢复异常。普通文字及任意 JSON 容器保持脱敏结果，缺少脱敏上下文时仍隐藏内容；离线动作的零请求计数只接受整数 `0`。未变化的标量直接复用公开值，不为普通分页额外加载整类账本。

`report.artifact` 为 V1/V2 共用的离线只读动作。公开报告使用 `artifact://reports/<batch>/<file>` handle；读取前核对批次 manifest、文件长度和 SHA-256，按 Unicode 字符分页（默认 4,000、最多 8,000），用同一 handle 与 `next_offset` 继续读取。路径逃逸、编码分隔符、链接/reparse point、跨项目 manifest、未列入 manifest 或字节已变化的文件均拒绝。报告渲染截断时，宿主保留 handle 生成可用恢复输入；读取报告页不重新发布报告或触发目标请求。

## 使用与兼容变化

使用独立 awa-ddd 的 `awa_surface`，其余字段均放在 input。先保存已获准材料：

```json
{"action":"surface.import","project_id":"assessment","input":{"path":"D:/Assessments/discovery/mappings.json","format":"actuator_mappings","base_url":"https://authorized.example.invalid","mode":"preview","limit":25}}
```

检查返回的实际 snapshot，然后按保存的版本交接：

```json
{"action":"surface.import","project_id":"assessment","input":{"snapshot_id":"<实际 snapshot_id>","mode":"apply","offset":0,"limit":25}}
```

若有下一批，原样使用返回的 next_input。需要补读某页或检查剩余项时：

```json
{"action":"surface.sources","project_id":"assessment","input":{"snapshot_id":"<同一实际 snapshot_id>","status":"pending_import","limit":25}}
```

默认 mode 继续为 apply，已有小文件调用方式仍有效；超过默认页大小的调用现在必须跟随 next_input 才会交接全部材料。仅把 limit 当展示限制的旧调用者需要适配，不能将第一页成功当整份来源已导入。

这是新增实体的兼容存储变化，没有改写旧 operation/evidence/decision/finding。没有来源实体的旧项目沿用原停止门禁；新计数为零时不改变旧 checkpoint 的原始状态摘要。旧项目的历史材料需要显式重新导入才能进入新来源分母。

独立 Node/Python 源码版本字段统一为 2.3.0。wheel/sdist、npm 和安装发行物以本次冻结后的构建、fresh verification、pack 与最终字节核对记录为采用条件。dsh-purge 1.8.0 内嵌的 2.2.0 源码没有在本次自动同步，安装 profile、全局 MCP 配置和外部发行也未改变；下游集成仍需在其维护仓库执行明确的源码同步与验收。

## 验证状态

以下本地记录已核对当前核心源码、测试、runner 和日志字节。Python 全量与规模记录的核心 manifest 为 `6ecddc9d226b0b635e04ea77a9cd76b1e15181012f94f8433ae927d219005c35`（96 个运行时文件）；Python 测试 manifest 为 `dbe54e76d487ab19cc5bcf58bda4bcc7fb901c87a36379eb52abf4f184fc07e2`（113 个测试文件）。Node 全量和发行物还必须满足本次最终记录的采用条件；历史测试或同名旧包不能代替这些证据。

| 检查 | 2026-11-22 当前状态 |
| --- | --- |
| 完整 `npm.cmd run check` | 采用条件：本次 `full-node-result.json` 为 passed，exit 0，全部测试通过且 fail/cancelled/skipped/todo=0；包含语法、prompt budget、截断恢复与真实子进程 fixture。测试数及 run ID 以记录为准，记录须绑定冻结后的源码、文档、runner 和日志 |
| Python 全量 unittest | **1,708 tests，OK，skipped=1，exit 0，225.207 s**；唯一跳过为 Windows 不适用的 POSIX FIFO。记录 `PY-20261121T214610Z-520a689b9e40`，源码/测试前后哈希一致 |
| 2,000 operations / 20,000 evidence / 500 pages | **通过**；每个 warm/recommended 查询 25 次，全部 p95 < 500 ms，精确实体计数及清理通过。记录 `BENCH-20261121T214335Z-c95b217a358f`，query `4920862a1d614ad495d83596999919de`，网络请求/新增 proof 均为 0 |
| Wheel / SDist fresh install | 采用条件：本次 `fresh-install-verify.json` 为 passed；两种包安装后均为 2.3.0/75 动作，CLI/module、`report.artifact`、内置 JS AST、运行时资源及源码字节一致，私有测试不入包 |
| `npm run pack:check` | 采用条件：本次 `package-check.json` 为 passed/committed，归档成员精确且唯一，提取 smoke 通过，锁及 running marker 消失，源码/归档 SHA-256 与当前字节一致 |
| 真实 DSH 桌面重载、真实 WSL、其它 OS | **未在本轮最终验收中实测**；CI 工作流或历史日志不是本机实测证据 |
| 真实 TscanPlus 服务 | **主动能力 unavailable**；2026-11-21 的 loopback MCP metadata probe 在线确认了 3.5.8/43，但这只是元数据目录，最终没有验收在线结果 API、主动请求或扫描 |

定向测试使用合成来源、`.invalid` fixture、mock 或受控子进程，不连接历史目标。`dsh-purge 1.8.0` 内嵌的 2.2.0 仍与当前 2.3.0 候选源码隔离；同步、下游构建和重载属于维护仓库的独立发布动作，不会因本工作区升级自动发生。

本次基准环境为 Windows、Python 3.12.0、AMD64、16 个逻辑 CPU。夹具创建用时 12.311 s；查询计时排除进程启动、夹具创建、JSON 序列化和清理。warm 表使用已完成强重建后的 advisory projection，普通页 limit=10；recommended 页改为 limit=3。返回大小按完整 JSON 的 UTF-8 字节统计：

| 查询 | warm p95 (ms) | 最大返回 bytes | 最大解码记录数 | recommended p95 (ms) / bytes |
| --- | ---: | ---: | ---: | ---: |
| `project.status` | 114.388 | 10,047 | 1 | 108.959 / 10,046 |
| `plan.next` | 131.635 | 30,200 | 26 | 122.333 / 17,237 |
| `plan.next.compact` | 132.210 | 16,287 | 23 | 118.897 / 8,751 |
| `plan.audit` | 121.469 | 15,754 | 13 | 118.454 / 13,501 |
| `surface.sources` | 0.558 | 8,427 | 1 | — |
| `surface.recon` | 24.975 | 2,938 | 0 | — |
| SQL `page.list` | 0.081 | 2,568 | 10 | — |

四个普通 warm 查询每次仍检查 20,000 份材料 metadata（批量目录读取 1 次），本轮 hash 读取字节为 0；这只表明投影和材料索引复用，不能代替真实性核验。cold `project.projection` 强重建单次 32,040.948 ms，解码 116,504 条记录并读取/hash 20,546,700 bytes；cold `surface.recon` 单次 1,732.991 ms。这两项各只有一个样本，不报告稳定 p95，也不推断任意历史规模均有相同成本。

本地证据位于 `.validation/upgrade-20261122-final/`：`full-python-result.json`、`benchmark-run-result.json`、`query-benchmark.json`、`full-node-result.json`、`fresh-install-verify.json`、`release-gate-result.json` 和 `final-validation.json`，npm 记录位于 `.validation/package-check.json`。验收 runner 记录 run ID、命令、源码/测试/runner/日志 SHA-256；最终 verifier 把回归、规模、fresh 安装、gate、归档和当前文件逐字节绑定。**发行采用条件**是本次 `final-validation.json result:passed`、`source_and_archive_byte_bindings_verified:true`，且记录的包 SHA-256 与实际文件一致。验收日志和本机材料不随源码包发行，也不是 fresh clone 的运行依赖。

## 实施状态与剩余限制

| 路线阶段 | 工作区状态 | 仍需外部条件或后续验收 |
| --- | --- | --- |
| P0 | Windows runtime、并发分类、源码/加载指纹、可靠 IPC 和阶段超时已通过本地回归 | 真实 DSH 桌面版本重验另行执行 |
| P1a | 七种本地来源统一账本、差集、分页交接与旧项目兼容已通过本地回归 | 原 mappings 字节缺失，parser 使用合成 fixture；历史材料仍需显式重新导入 |
| P1b | 代码路径已落地：Tscan 已有 `query_results`/`route_candidates` 账本、provider receipt、目录漂移失败关闭和 clue-only 边界 | **主动 Tscan unavailable**；最终没有在线 3.5.8 结果或主动 discovery 验收 |
| P2 | taxonomy、campaign 隔离、AR/RPR、共享 CompletionEvaluator 与 V2 acceptance 已通过本地回归 | 真实多 campaign 业务状态和外部 provider 另验 |
| P3 | SQL 分页、cursor、advisory projection、ready queue、来源局部投影、inspect/rebuild/compare 与迁移通过本地回归和规模门槛 | 强重建仍全局，warm 仍核对全部材料 metadata；按变化材料局部强重算为后续方向 |
| P4 | UnitOfWork、CAS/lease/fence、原子预算、DSP/REC、Browser/sqlmap 双层 dispatch 与 unknown-effect 恢复通过本地故障 fixture | 真实服务故障注入另验；主动 Tscan 出站/取消/状态契约仍不达标 |
| P5 | V1/V2 continuation、AR/RPR/FRC/CA、原子报告、报告分页和迁移/回滚通过本地回归 | 包采用规则见上述最终记录；真实 desktop closing→steer 与下游同步另验 |
| P6 | 离线全量、规模和故障 fixture 已执行；Windows/Linux CI 定义已准备 | CI 矩阵未在本机实际执行；真实召回盲测、桌面、WSL、其它 OS 和外部服务另验 |

本地回归与规模结果支持采用上述实现范围；包的最终通过状态和哈希以冻结后的 `final-validation.json` 为准。P0 至 P6 中需要真实环境的项目继续按表中边界处理：主动 Tscan discovery 保持 unavailable，真实结果 API、桌面、WSL、其它 OS 与召回盲测没有本轮实测结果。`dsh-purge` 内嵌 2.2.0 不会自动升级；本次工作区升级未执行 commit、push、deploy 或修改用户 profile。
