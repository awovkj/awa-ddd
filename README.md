# awa-ddd

本工作区的 2.4.0 **候选版本**是 DeepSeek Harness（dsh）的原生、证据驱动安全评估插件。它将攻击面宇宙、假设、冻结测试配方、durable 执行、证据与多维覆盖存入本地 SQLite。默认 `assessmentModel:v1` 提供 10 组、75 个动作；`assessmentModel:v2` 注册 6 组、48 个 Campaign 动作（`awa_campaign/awa_recon/awa_test/awa_review/awa_report/awa_admin`），以“Universe → Hypothesis → TestRecipe → TestRun → Finding/CoverageClaim”驱动下一轮测试。模型沿用 dsh 运行时，不另接模型供应商。

2.4.0 针对证明与执行完整性完成专项加固：离线 verify 必须绑定原始 run/step/control/evidence，fixture 使用跨进程 CAS/fence 和真实读回，新增 6 个证据驱动 fixture 动作及公开 `campaign.review_frontier`；Campaign 使用原始 revision 防双交付，Universe 增量推进使旧完成授权失效，迁移支持原子 apply 与 rollback→reapply。自动写配方只派发单次攻击写，其余控制明确未观察。浏览器写默认关闭，外部工具仅接受管理员固定路径/摘要，TscanPlus 缺终态保持 unknown。公开响应查询/覆盖变量按组件编码，仓库不再跟踪评估 session、靶场和报告工件。详见 [2.4.0 加固说明](docs/UPGRADE-20261122-HARDENING.md)。

2.3.0 候选版本在既有固定 SRC 模式与版本化交换契约上，新增不可变多来源账本和预览/分批交接、TscanPlus 已有结果只读接入、可靠 IPC 派发回执、Campaign 隔离与执行预算、合法适用性/复核凭据、运行源码指纹和受控报告发布。外部命中仍只成候选，未知写入不会自动重放。Node 与 Python 源码中的版本字段均为 2.3.0；发行采用条件是冻结后构建、fresh install 和 pack 记录通过，并与当前源码及归档字节一致。详见 [优化与渐进重构方案](docs/REFACTOR-PLAN-20261121.md)、[来源账本升级说明](docs/UPGRADE-20261121-SOURCE-LEDGER.md)、[SRC 模式](docs/SRC-MODE.md) 与 [内置评估和兼容交换](docs/INTEGRATION-DSH-PURGE.md)。

2.3.0 的 2026-11-22 历史验证记录为 Python unittest **1,708 tests，OK，skipped=1**（Windows 不适用的 POSIX FIFO）。2,000 operations / 20,000 evidence / 500 pages、每个 warm 查询 25 次的规模夹具通过，status/next/compact next/audit 的 p95 为 **114–132 ms**；强投影重建单次 **32.0 s**。普通 warm 页仍核对全部 20,000 份材料的 metadata，强完成/证明校验仍为全局。`npm.cmd run check` 全量与发行检查采用冻结源码、文档、runner 和日志均绑定的本次记录。详细条件、证据路径和发行采用规则见 [验证状态](docs/UPGRADE-20261121-SOURCE-LEDGER.md#验证状态)；只有本次 `final-validation.json` 为 passed 且源码/归档哈希一致时，才能采用其对应发行物。

2026-11-21 的 2.3.0 重构还加入不可变来源快照、`surface.import` 预览与分批应用、只读 `surface.sources`、Actuator mappings 导入，以及主状态中的已知来源登记差集。完整方向见 [优化与渐进重构方案](docs/REFACTOR-PLAN-20261121.md)，实现范围、兼容变化与验证见 [来源账本升级说明](docs/UPGRADE-20261121-SOURCE-LEDGER.md)。

**dsh-purge 1.8.0 内嵌的仍是 awa-ddd 2.2.0 生产评估源码，位于其 `lib/redteam/assessment-engine/`，随自身源码和发行包提供。** 使用 dsh-purge 红队或 SRC 时，直接调用其 `redteam_assessment_status/start/import/run/review` 原生工具及 `redteam_src_report`；引擎从 dsh-purge 自己的安装目录运行，每个 engagement 使用独立的 `<靶标目录>/assessment` 工作区和固定内部 `project_id:assessment`。无需另装 awa-ddd，也无需配置外部包路径、共享工作区或外部项目 binding。独立 awa-ddd 2.4.0 候选源码的工具、SRC 和交换契约继续供独立调用者及旧资料使用。**下游 1.8.0 不会因本工作区升级而自动获得 2.4.0；同步必须由 dsh-purge 维护仓库显式执行并另行验收。**

dsh-purge 的随包核心保留 MIT 许可、版权和逐文件 SHA-256 来源清单；源码维护仅由维护者在 **dsh-purge 仓库根目录**显式运行 `scripts/sync-assessment-engine.mjs --source PATH`，运行时直接使用已经写入的源码。离线 `--check` 不需要本项目的外部 checkout。独立临时安装验收分别覆盖内置核心、原生生命周期与本项目的交换契约，详见 [维护与验证来源](docs/INTEGRATION-DSH-PURGE.md#源码维护许可与来源)。

2.0.2 增加 `plan.next compact`、`plan.why`、`assessment.batch` 与 `coverage_policy=subject` actor 去重；修复浏览器 `action`/`text` 兼容并保留 25 KB prompt budget。详见 [2.0.2 优化第一批](docs/UPGRADE-20261105.md)。

2.0.1 修复同页多次观察归档互相覆盖、query 的 default/null 重复及精确分支交接，新增 `semantic_progress_id` 区分真实闭环/前提改善与行政状态往返，保留任务失败上下文后推进下一可行页。存储 API 到 SPA 的 XSS 可以通过 `finding.record xss_consumption` 验证实际写入源、JSON 回读内容版本和 native 正常/攻击 viewer；`runtime.probe` 提供经检查的 sqlmap backend/路径模板。详见 [本轮升级与验证](docs/UPGRADE-20261104.md) 和 [原会话对照审计](docs/SESSION-20261104-460B14C4.md)。

2.0 的设计与评审对应见 [V2 架构](docs/V2-ARCHITECTURE.md)、[迁移与兼容](docs/V2-MIGRATION.md)、[验收与 R01–R21 映射](docs/V2-ACCEPTANCE.md)。核心约束：Universe 只声明有来源的已知范围；Hypothesis 身份不是 statement；Recipe 冻结且在 override 上只允许声明过的数据变量；durable run 的未知写进入 `effect_unknown` 而不自动重放；reviewed detection 与 machine proof 分栏；coverage 分为五维且所有百分比带分母；`partial_accepted` 交付不获得 exhausted authority、自动停止或最终报告权限，也不暂停正常宿主续接。旧的 `reporting.py` 通过 `reporting/__init__.py` 兼容 shim 保留全部导出。

此前 0.12.0 的取证、`assessment.prepare`、`finding.bind` 与独立安全属性复核仍保留，详见 [0.12.0 升级说明](docs/UPGRADE-20261103.md) 和 [会话取证](docs/SESSION-20261103-CFF22367.md)。

保留 0.11.0 的真实进展幂等交接、停滞检查点、精简常驻提示、`surface.recon` 信息画像、会话续期、页内恢复及单次调用复用。此前 729 条重复续接通知的修复依据见 [20261102 升级](docs/UPGRADE-20261102-LEAN.md) 和 [该会话取证](docs/SESSION-20261102-ADAAE1EF.md)。

保留 0.10.0 的精确参数矩阵、公平调度、判据帮助、检查点增量、前端消费点反查及离线评估提示导入；multipart/BOM、独立文件名对照和短字段脱敏等已有修复不混作本次新增。详见 [0.10.0 取证与实现](docs/UPGRADE-20261101.md)。

续接验收进一步补齐已有对照的离线复核、检查点受限投影、评估提示的显式证据绑定、JS 词法作用域及提取安装包 smoke；不把恢复解析预算当成新实验，不让同名局部 `fetch/location` 伪造网络或导航。详见 [20261102 续接闭环](docs/UPGRADE-20261102.md)。

保留 **exhaustion_only 评估完成/最终报告硬门禁**：`plan.finalize` 只接受严格 `reason:completed`。正常对话轮次结束或抑制重复提示不等于评估完成，未完成工作保留为 checkpoint/draft，不能伪造正式结项。保留持久化 checkpoint、来源绑定的 review、独立漏洞族义务、身份/资源和真实证据规则；历史统计不混作本次验收，见 [0.9.0](docs/UPGRADE-20261031.md) 与 [人工复现指南](docs/REPRODUCTION.md)。

保留先前的范围/身份/资源血缘、SQL 元数据与真实 XSS 运行时门禁、不可变 finding 修订、UTF-8 文件调用和 WSL 边界；不将更多请求或人工文字冒充完整覆盖。0.6.x 历史修复见 [20261029](docs/UPGRADE-20261029.md) 与 [模式 RPC 修复](docs/UPGRADE-20261030.md)。

## 主要能力

| 能力 | 当前行为 |
|---|---|
| dsh-purge 内置评估 | 1.8.0 从自身随包核心运行红队/SRC 的原生评估工具；每靶标固定内部上下文，保留来源账本、当前机器证明复核与直接证据停止 |
| 2.0 战役 | `assessmentModel:v2` 六组工具；Campaign 持久目标、Universe 快照、KnownCase 三轨、Hypothesis 稳定键、公平调度、五维覆盖矩阵；`partial_accepted` 与 exhausted authority 分离，保留继续和剩余工作门禁，且不授予停止或最终报告权限 |
| 原生接入 | 75 个动作与 Python help catalog 一致；精简常驻说明，统一 awa_project action.help 按需查完整契约；UTF-8 stdin、固定 argv、取消与独立截止时间 |
| 信息先行 | surface.recon 统筹当前授权站点、技术/框架提示、页面/API/功能/输入、歧义线索与收集缺口；零目标流量，复用未变化的信息基线并公开变化差量，不冒充全站发现或漏洞证明 |
| 开局与续接 | progress/frontier 状态幂等交接；同 PR 先取具体 ready/review 小页，真实复核/准备回执后推进游标；raw/CP/队列读取不算闭环，零工具重复通知有界；页内截断须恢复 |
| 项目与发现 | 多源离线 OpenAPI/JS AST/HAR/ARTEX/SARIF/assessment_hints/Actuator 导入；来源快照与项不可变，预览后按精确快照分批交接，主状态保留已知未登记、历史 pending、冲突及未解析数；JS 消费点与定义/评分保持线索口径 |
| 参数与调度 | 精确操作/位置/selector/分支/族矩阵；优先保留任务动作、前提与完整控制 ID；主任务和参数页独立恢复，参数页默认随主页最多 3 条；typed/variant 分开，coverage_first 保留公平性 |
| 证明准备与绑定 | assessment.prepare 按义务、发现或已有证据复核当前控制与缺字段，零请求、零新判定；finding.bind 校验真实当前证明后创建替代发现并保留原始证明与生命周期历史 |
| 身份与资源 | 服务端主体/角色核验、同 origin 和快照；禁止 subject/tenant/roles 同 Pointer 伪角色，过期有效同代会话只给显式续期候选，live 执行门禁不放宽 |
| 执行与恢复 | 共用 preflight 门禁；JSON 字段名/Pointer/数组、唯一 form/multipart/Cookie 输入对照；原字节 `body_file`、持久 checkpoint 和失败 run_id；真实 scenario 的读/写/读 `state_transition`；不自动重放 |
| 浏览器 | 必需 / 明显有益的测试必须调用 Playwright；优先实际宿主 MCP、保留 native 回退；公共运行时材料按凭据上下文脱敏，原证据保留私有；超时保留 run 续接，不重放未知写 |
| Yakit MCP | 真实 stdio MCP 握手、tools/list 与受控 HTTP 单包重放；保存目录、交换、执行结果、传输告警及摘要 |
| TscanPlus MCP | 保留 loopback Streamable HTTP 握手、目录和已有结果/route 账本适配代码；**当前主动 Tscan/Web discovery 能力 unavailable**。远端 3.5.8 的 43 个 catalog 工具不等于 43 个 awa-ddd 动作，也不等于已在线验收；截断与远端未决保留 partial |
| sqlmap | GET query 与受控 POST JSON/form 单参数，POST 必须写授权与精确可回退 fixture；方法/头/原字节/身份/资源 V2 血缘；元信息-only，partial/signal 留为未验证候选 |
| SQL 确认 | 元数据直接回显/真实 sqlmap transcript/DBMS error channel；写侧行为证明必须是受控 SQL 输入及真实有限业务计数差异，普通响应差异不算 SQLi |
| 人工复核 | SQL proof 不放宽；XSS 可把精确正常/攻击输入、同身份真实消费页及运行时证明绑定具体义务，仍标为 analyst；无弹窗访问不否定整类 XSS |
| 线索复核 | candidate.link 可显式绑定已有 proof_decision_ids 复核精确评估提示；普通 link、评分、方法猜测、同名代码 sink 不能收口；工件变化重新打开 |
| 判据与交付 | 8 种精确 oracle 帮助与控制顺序；multipart/BOM 在 preflight 拒绝，文件名/内容独立绑定；completed 族仍需当前有效证据；review 不关闭安全义务，最终交付仅 strict completed |
| 质量护栏 | `plan.next` / `assessment.prepare` 重复页给出有界提示，保持真实 readiness 与动作；`http.preflight` 24h 同签名提示、SQLite 原子 advisory 记录、报告脱敏自检与普通词回归；详见 [质量护栏](docs/QUALITY_GUARDS.md) |
| 公共输出 | 所有项目动作与错误共用私有凭据上下文脱敏；已知秘密不经 surface/preflight/步骤标签回流，真实控制字段按动作 schema 保留；已分派执行不因输出失败被回滚或自动重放 |
| Windows / Kali | 文件式 UTF-8 调用避免 PowerShell 多层插值；源码保留可选 WSL 执行后端及取消边界。本轮最终验收未运行真实桌面、真实 WSL 或其它操作系统，hosted CI 配置存在不等于这些环境已经实测 |

扫描器告警、工具目录、页面登记和请求数量都不会自动满足测试义务。SQL 弱证明、角色未知或身份/资源绑定变化保留历史，不能伪造迁移为已确认。新项目缺少 scope 时仅默认目标 URL 路径范围，不把 `/app` 静默扩大到整个 origin；存量显式 scope 不改写。

## 使用

以下插件配置和 `awa_*` 工具示例适用于**独立安装 awa-ddd 2.3.0**。dsh-purge 1.8.0 用户直接使用当前靶标的原生评估入口，按 [内置使用流程](docs/INTEGRATION-DSH-PURGE.md#dsh-purge-180-原生使用流程) 操作。独立插件和新版 dsh-purge 各自持有自己的项目数据；旧独立项目、路径设置及 binding 资料不自动成为新版 dsh-purge 的内部上下文。

需要 Node.js 22.19+、Python 3.10+；本地浏览器还需可用 playwright-core 与 Chromium。dsh SDK 作为宿主 peer dependency 提供，插件不携带第二份 SDK。

插件配置示例：

```yaml
- id: awa-ddd
  name: awa-ddd
  config:
    workspace: D:/Assessments/awa-ddd
    executionBackend: native
    pythonExecutable: python
    timeoutMs: 120000
    assessmentMode: src
```

`assessmentMode:src` 用于发现任务；省略时继续默认 assessment。`/src [on|off|status]` 选择本会话的新项目偏好，已持久化项目模式不会随 off 降级。源码/报告维护不因此启动目标测试。SRC 目标执行只允许有界只读 HTTP 与浏览器观察，禁止目标写入、主动外部工具和场景执行；已有直接证据后仅离线复核与报告。

默认评估目录为 `~/.dsh/awa-ddd-data`，位于插件包之外。工具统一接收 action、project_id、input；其余 action 字段（包括 limit/offset）必须放 input。帮助只在 **awa_project** 调用 `action.help`，不要发到其它组；它与 `runtime.probe` 无需 project_id。已有授权评估先看 `project.status` 和信息基线，收集后再 `plan.next`；源码/报告维护不进入目标评估流程。

## 先统一收集信息

不要边猜接口边反复发包。先用 **awa_surface** 检查当前范围内的收集入口：

```json
{"action":"surface.recon","project_id":"assessment","input":{"mode":"prepare","section":"collection","limit":10}}
```

统筹实际获准的正常页面、静态资源、API/功能流程、账号与资源前提，用现有 HTTP/真实 Playwright 和 OpenAPI/JS/HAR 导入保存材料，优先批量登记，再统一生成画像：

```json
{"action":"surface.recon","project_id":"assessment","input":{"mode":"aggregate","section":"overview","limit":10}}
```

按需分页读取 `technologies/functions/clues/collection`。指纹/框架/版本都标为带来源的 `hint`；功能区分登记、实际观察和未观察，歧义表单与未映射输入仍需复核。`baseline_reused:true` 时复用已有信息，真实新事实才补收集。两个模式都不发目标请求，aggregate 只保存非证明性的基线元数据；不自动采集外链、改范围、登记或执行线索，也不把基线变成安全/完成回执。

“一次做好”是一次统筹已授权、可获得的材料，不是未经范围/身份检查的一键全扫。缺失/截断/未知信息显式保留；DNS/TLS 等未采到的部署信息不编造，注册范围外未知攻击面不宣称已经耗尽。画像建立后，再用 `plan.next` 根据实际功能、输入消费点与身份/资源边界选择具体假设。

对于已经保存的 OpenAPI、JS、HAR、ARTEX、SARIF、评估提示或 Actuator mappings，先在 **awa_surface** 预览。Actuator 必须提供明确的 `base_url`：

```json
{"action":"surface.import","project_id":"assessment","input":{"path":"D:/Assessments/discovery/mappings.json","format":"actuator_mappings","base_url":"https://authorized.example.invalid","mode":"preview","limit":25}}
```

预览保存整个有界来源快照，返回 `source_id`、`snapshot_id`、本页明细及 `source_inventory`，不会登记 operation/candidate 或发送目标请求。用返回的真实 `snapshot_id` 交接已经检查的材料：

```json
{"action":"surface.import","project_id":"assessment","input":{"snapshot_id":"<preview 返回的实际快照 ID>","mode":"apply","offset":0,"limit":25}}
```

每次 apply 只写入所选页，默认 25 项、最多 100 项；有下一批时原样使用返回的 `next_input`。精确快照 apply 不再读取源文件，也不同时传 path/format/base_url。展示截断用 `surface.sources` 恢复读取当前页：

```json
{"action":"surface.sources","project_id":"assessment","input":{"snapshot_id":"<同一实际快照 ID>","status":"pending_import","offset":0,"limit":25}}
```

`known_not_registered_total` 表示已保存来源中的 method/URL 差集；媒体类型变体另算 item，来源计数不代表全站分母。`pending_import_total` 包含尚未交接的候选、冲突和拒绝项，新快照不删除历史 pending；`plan.audit` 给出历史快照及最早未应用位置的精确模板。简单整段 `{var}` 路径仍需真实 URL/资源绑定，复杂表达式进入候选。解析或完整性缺口维持 partial，来源登记不关闭安全测试。

先查看明确未测的参数，而不是重复接口基线：

```json
{"action":"plan.next","project_id":"assessment","input":{"limit":3,"parameter_status":"untested","parameter_offset":0,"parameter_limit":3}}
```

`parameter_coverage` 独立分页；`observed_unassessed` 和 `needs_controls` 不是已测。检查点 `parameter_delta` 区分新增 typed 闭环和仅观察到变体，首个/旧投影不伪造新增进展。验证码/SMS 参考 `session_continuity` 维护私有同源会话，不自动复用 Cookie 或猜测支付前提。JSONL/报告中的命令不会被源码升级自动重放。

```json
{"action":"action.help","input":{"name":"http.capture"}}
```

`project.status` 默认最多 10 条各类实体与 5 个 gap 示例；`plan.list/report.coverage/finding.list` 默认 25 条、最多 100 条。展示限制为 24 KiB；条目内部字段截断也会给 `render_recovery`，保留原过滤条件先读当前页，不能跳到正式 `next_offset`。单条仍超限则标 `retry_same_page:false/projection_limit:single_record`，按 detail_action 找精确查询或用文件式 CLI 读取完整已脱敏结果，不循环相同页。`plan.build.obligations` 是整数，`obligation_items` 才是分页明细。

闭环为 `plan.audit → plan.next / review_followups → 执行或复核并落账 → plan.checkpoint`。AI 应逐项复核登记输入、既有 HTTP 控制和浏览器观察，从实际证据形成 accepted typed 正向或阴性判据，绑定支持的发现并归档观察，再检查完整性。`continue_required:true` 时继续处理现有授权内可做的 ready/review；partial 总结、读取队列、保存 CP、已有漏洞、请求数、低收益、预算或草稿成功均不能作为常规收尾原因。某个证明通道停滞时，先复核已有材料、准备缺失控制或推进另一条具体未复核项；正常轮次结束不授予完成声明或最终报告。

`can_finalize:true` 只在非空登记范围、`completion.status:complete`、零 ready/review/blocked/unresolved、最新同快照 checkpoint 及两轮**完整、有效、证据绑定**的发现/12 族适用性/页面复核同时成立时出现。blocked frontier 不计完整轮次，全部任务标受阻也不等于测无可测。成功 `plan.finalize reason:completed` 后才有 `automatic_stop_allowed:true` 和 `can_claim_complete:true`；二者只针对有证据的登记范围，不证明未知攻击面不存在。

人工 `plan.disposition not_applicable` 保留声明与来源，但 `applicability_review_total` 仍是待验证工作：普通正常响应加一句业务理由不能抹掉整条义务。删减未测输入/漏洞族/分支、弱化角色/属主边界，或在明确 SQL/HTML 消费点省略所需族，会保留 `scope_reduction_review_total`；历史族不能被当前 consumer 改写。上述缺口不能被行政 `plan.review` 归档，须恢复实际边界并完成 typed 判据，不能靠“全部 N/A”或“删掉任务”绕过零剩余门禁。

`plan.disposition/plan.review status:blocked` 先按真实范围、身份、fixture、浏览器、材料和未知写前提重新投影。只靠文字标记的受阻项若实际可推进，保留原声明并给出 `blocker_reconciliation_required` 离线复核：先按当前模板 reopen，不能直接重放请求或放宽门禁。setup、输入追踪与已有证据复核不能被藏掉。完整失败只读浏览器材料可以行政复核，但不是成功页面或安全证明；真实缺前提仍受阻。

登记 URL 去除 query 后若缺少精确 scope 查询绑定，保留 `scope_binding_review_required` 离线准备：先 `surface.inspect`，再由调用者从当前授权来源提供真实完整 URL 并独立 `http.preflight`。模板只给 operation 引用，不从 scope 复制 query、不自动访问、不扩大范围；必需浏览器仍为 prepare 而非 invoke。真实身份、写授权、fixture、路径或页面阻塞不被此准备门绕过，已有有效证据仍可离线复核。

`candidate.dismiss` 仅有 reason 时仍保留发现复核与 `candidate.reopen` 提示。只有机验的 `basis:outside_scope`（具体可靠 URL 真在固定登记 scope 外，新增 exclude 不能作证），或 `basis:duplicate_operation`（精确普通操作线索，方法/协议/输入/分支和声明匹配，全部当前 typed 安全义务已闭环）才可关闭该复核；后者还需实际 `operation_id`。动态/私有 locator、扫描器告警或无关正常基线不能借此消失；来源、范围与证据改变重新打开复核，旧声明不迁移为已验证。拒绝导入的操作线索也有独立来源 ID，并仅对完全相同的旧线索保留旧 ID 与处置历史。

`blocked/budget_exhausted/user_stop/authorization_boundary` 均被最终收尾 API 拒绝；调用方文字、force/override 或自称宿主事件不能建立停止权。真实用户明确暂停/停止或宿主真实中断时遵守该事件，保存 checkpoint、必要的 draft 和真实恢复前提，不制造最终停止记录。旧部分 FN 原样保留，只读重开也不会恢复停止权。systemPrompt 的停止指引不受渗透模式开关影响；没有该服务仍保留引擎硬门禁。

已核验 rc.3 SDK 的 **`agent/turn-stopping` awaited serial 钩子**：离线审计真实 agent 当前绑定，以插件来源 `agent.steer` 交接新的 progress/frontier 状态。同 PR 不能只保存停滞 CP 就放行；守卫继续读取 `plan.next`/`plan.audit` 的具体小页，交接精确输入、证据 ID、复核/准备及浏览器绑定或归档动作。真实工具调用产生复核或前提准备回执后，才继续推进其他当前游标项；回执本身不代替 accepted typed 判据。仅重复读队列、保存 CP 或不调用工具，不会无限重启同一通知，未完成义务和严格 FN 门禁仍保留。CP 等待期间的并行真实进展会重新检查。

`assessment.prepare`、`evidence.inspect`、`finding.bind`、`page.adopt` 等真实离线生命周期调用可建立 offline-only 续接绑定，完成既有材料的复核与归档；这种绑定不提供新网络授权。新意图、真实取消及宿主中断优先，外部前提确实不可用时保存 unfinished checkpoint/draft 和恢复条件。纯报告或历史查询不变成目标测试。缺接口有降级，不承诺无限运行；`continuationGuard:false` 只关闭可选宿主钩子，不关闭最终报告门禁。

## Playwright 测试策略

需要浏览器验证，或浏览器会明显有利于测试的漏洞，**都必须实际调用 Playwright**。XSS/DOM、客户端路由/状态、CSRF/CORS、点击劫持/CSP、Cookie SameSite/HttpOnly/Secure、postMessage、OAuth/OIDC 等浏览器上下文结论属于必需；复杂 UI、登录/动态 token、多角色页面、上传预览/消费和业务链有明显收益时也必须使用。纯后端 SQL 元数据、SSRF、XXE 等不盲目浏览器化，也不因此将整个漏洞族标 N/A。

`plan.next.work_items` 及页面/功能复核项携带离线 `browser_testing`：`requirement:required|assisted|not_needed`，其中 required 和 assisted 都有 `must_call_playwright:true`；assisted 不是可选建议。`call_needed` 表示仍需新运行时观察，`invoke_now` 指示是否本阶段调用；先准备 HTTP 控制和消费链，缺前提保留 blocked，已有合格材料以 review_existing 离线复核，不重放写入凑调用数。顶层 `browser_testing_summary` 保留全队列和全部浏览器跟进任务的计数，不依赖页面大小，也不是安全覆盖率。投影不自动执行工具、不改变授权或新增 oracle。

每次交接重新核对当前 scope/exclude；曾登记或访问的 operation/page/function 不因此继续获准访问。全部关联消费页显式 BLOCKED 时不会自动重开，有合法且非 blocked 的备选才优先使用。GET 型 XSS 和任何带 query 的消费 URL 只公开 `consumer_locator`，不把 `safe_url` 当成可执行输入；须填入精确绑定 URL，之前 `native_visit_input` 不含 url、`invoke_now:false` 且 `native_input_requires_binding:true`。

先发现并调用**实际宿主 Playwright MCP 工具**，执行授权页面导航/快照、必要 click/fill、网络和运行时观察，保存真实输出后 `browser.import_mcp`。仅在 native 回退路线先 `browser.probe` 再 `browser.visit`；本地 Chromium 不可用不代表宿主 MCP 不可用。MCP 导入不绑定 session/actor，不能替代 authenticated XSS typed closure；该证明仍需本地已核验会话绑定的运行时和正常/攻击 HTTP 控制。人工 evaluate(alert)、无 dialog、静态 HTML 或浏览器调用成功本身都不是漏洞证明。

native 不提供上传、任意 evaluate、独立多 context 或下载测试，30x/跨源写/WS/SW 仍阻断；宿主 tabs 不等于隔离 context，unsafe run_code 不是默认安全入口。上传/evaluate/tab 输出不得伪装成 click 导入旧 action enum。范围、身份、写授权和测试资源限制不放宽；具体策略、提供方限制与证据工作流见 [PLAYWRIGHT_TESTING.md](docs/PLAYWRIGHT_TESTING.md)。

## 中文可复现报告

```json
{"action":"plan.audit","project_id":"assessment","input":{"limit":25}}
```

```json
{"action":"report.build","project_id":"assessment","input":{"stage":"draft","output_dir":"D:/Assessments/reports"}}
```

默认阶段为 draft，成功只代表生成快照，不是停测许可。最终交付先按 `action.help` 契约，以当前 checkpoint、实际范围复核说明及 reviewer 执行唯一允许的 `plan.finalize reason:completed`，再使用真实 `finalization_id`：

```json
{"action":"report.build","project_id":"assessment","input":{"stage":"final","finalization_id":"<实际停止记录ID>"}}
```

新批次包含中文 `report.md`、完整 `summary.json`、`manifest.json` 和适用的 `reproduction/`，同时保留阶段、继续判定、停止依据与剩余工作。最终报告在准备材料之前及准备后分别检查严格闭环、当前快照/CP/FN 和全部零剩余计数；部分或不一致停止直接拒绝，不写最终报告目录。新材料或新 checkpoint 使旧停止记录失效。漏洞按严重度置前，每条说明主体/资源前提、编号步骤、实际请求与响应、修复和边界。

每个可导出的 HTTP 复现步骤在 `report.md` 内展示完整脱敏请求数据包，包括请求行、Host、请求头、空行和正文，并保留对应的 `.http` 文件。复制数据包到 Yakit Web Fuzzer 或 Burp Suite Repeater，按步骤 URL 设置目标主机、端口和 HTTPS，替换 `<AWA_...>` 凭据及自建资源后发送；修改正文后让工具重新计算 Content-Length。报告生成不发送请求。原始认证、重置令牌、验证码、支付密码和敏感配置不会直接导出，不能安全脱敏的正文明确不可复现。完整操作见 [REPRODUCTION.md](docs/REPRODUCTION.md)。

每条可适配的 SQL 注入发现默认再附一个 sqlmap 人工复核命令：`-r` 指向已校验的脱敏基线请求文件，`-p` 绑定具体注入参数，使用 `--current-db --current-user` 获取当前库名和数据库用户等只读证据。SQLite 使用固定只读元信息查询；缺少安全请求、参数不明确、格式不支持或写侧重放会修改资源时，报告列出无法生成命令的具体原因。命令不会由报告生成器自动执行。

## TscanPlus MCP

示例控制端点是用户提供的 `http://127.0.0.1:8088/mcp`。宿主 MCP 配置示例在 [examples/tscanplus-mcp.json](examples/tscanplus-mcp.json)；awa-ddd 不自动改写全局 MCP 配置或启动/重启共享扫描器。**当前验收环境将主动 Tscan discovery 标为 unavailable，不能假定该端点在新的运行环境中可达或已授权。** 在真实服务可用且授权明确时，已有评估项目才可先做仅元数据探测：

```json
{"action":"tool.probe","project_id":"assessment","input":{"adapter":"tscanplus","mcp_url":"http://127.0.0.1:8088/mcp","scanner_project":"awa-demo"}}
```

`scanner_project` 必须对应本次评估获准读取的远端项目；省略时稳定派生独立 namespace，不会搜索或迁入其他项目。上游 Skill 写明项目全长最多 30 字符，但历史实测已观察到服务端把长名裁剪为 20 字符；当前适配器继续以归一化后最多 20 字符作为保守兼容上限。历史配置和材料保持不变，但旧的超过 20 字符 namespace 不能用于新请求或读取：在连接 MCP 前拒绝，须明确用短名重新 probe，不能默默截断并查询另一个桶。旧 artifact 仍可离线 inspect，不会根据远端回显静默改项目。

`tool.tscanplus_request` 的受控单包门禁和 `tool.tscanplus_results` 的已有结果读取是源码能力，但本轮没有把它们当作真实服务已验收能力：主动扫描不可用，主动请求/结果/route 路径仍依赖当前可访问、已绑定且授权明确的外部服务。`limit` 和 `result_limit` 兼容、默认 25、范围 1..100，同时提供时必须相等；远端没有 offset 分页。两个只读动作的契约为：

```json
{"action":"tool.tscanplus_summary","project_id":"assessment","input":{}}
```

```json
{"action":"tool.tscanplus_results","project_id":"assessment","input":{"table":"urlscan","limit":25}}
```

```json
{"action":"tool.tscanplus_routes","project_id":"assessment","input":{"limit":25}}
```

`summary` 仅公开允许表的计数与 `has_assets`，不回显服务器 prompt/hint；`routes` 仅把范围内建议归档为未验证候选，不执行建议工具。其 `limit` 是本地导入/展示预算，不是远端分页参数。随后使用 `candidate.list` / `candidate.inspect`、返回的 `run_id` 与 `tool.inspect` / `tool.artifact` 复核。准确字段和表名用 `action.help` 查询；原始结果只留在项目私有材料，artifact 先脱敏后分页。TscanPlus 的成功、POC 告警、空结果、局部截断均不会关闭安全义务。

2026-11-21 的在线元数据探测记录了 TscanPlus 3.5.8、43 个远端 catalog 工具，scanner tools 调用数与目标请求数均为 0；AWA V1 自身为 75 个动作，两个计数不可混用。保存的目录不是当前服务可用性或结果 API 验收证明。URL/IP 扫描、POC、爆破、AK/JWT、多模块联动和 route 自动执行不在本版白名单。远端超时/断连和缺页保留未决，不能自动重放或声称服务端已停止。详见 [TSCANPLUS.md](docs/TSCANPLUS.md)。

## PowerShell 与 WSL

避免把复杂 JSON、中文 XML、multipart 或 SQL 值拼进 PowerShell 命令。保存 UTF-8 JSON 请求文件，直接调用：

```powershell
.\scripts\Invoke-AwaDdd.ps1 -RequestFile D:\Assessments\request.json -OutputFile D:\Assessments\result-new.json -Workspace D:\Assessments\awa-native
```

文件使用 `{ "action": "...", "args": { "project_id": "..." } }` 协议。`result-new.json` 必须尚不存在，helper 直接写 UTF-8 无 BOM 的成功/错误 JSON，同时仍输出到 stdout；PowerShell 5.1 的 `>` 仍可能重编码为 UTF-16，不用于保存协议。helper 仅在本次调用中设置并恢复 UTF-8，不修改 profile。二进制/XML/multipart 正文用明确选择的 `body_file` 或 `body_base64`，不要经过文本转码。场景中禁止由 HTTP 响应变量选择本地 body_file、会话、内部资源 ID 或执行策略。

Kali 可选配置：

```yaml
- id: awa-ddd
  name: awa-ddd
  config:
    workspace: D:/Assessments/awa-kali
    executionBackend: wsl
    wslDistribution: kali-linux
    wslPythonExecutable: python3
    timeoutMs: 120000
```

仓库只保留 WSL 适配代码、历史结构化记录和测试边界；**本轮 2.3.0 最终验收没有重跑真实 Kali WSL2、真实 DSH 桌面或其它操作系统**。历史记录中的 Python、sqlmap 或工具目录结果不能作为当前主机 fresh clone 的通行证。nmap、nuclei、nikto、ffuf 等没有通用执行适配，目录探测不算“已接入扫描”；缺依赖时也不能把 WSL JS AST、浏览器或 Yakit 能力说成可用。需要浏览器时使用满足依赖并经当前环境核验的 native 后端或实际 MCP 输出。

WSL 不自动把 Windows `127.0.0.1` 改成网关，不能据此绕开 scope；Windows/WSL 项目目录应隔离，勿跨 OS 并发打开同一 SQLite。详见 [编码与 WSL 工作流](docs/WINDOWS_WSL.md)。

sqlmap/Yak 执行接口仅接受管理员在插件配置 `trustedSqlmapPath` / `trustedYakPath` 中选择的精确安装路径，可另配 SHA-256；工具参数不再授权任意同名文件。插件发行包仅包含适配器，不包含 sqlmap/Yak 本体。

随包 [SKILL.md](skills/awa-ddd/SKILL.md) 提供操作指引。输入栏渗透模式按钮及 `/penetration` 命令保留为可选会话能力，只影响工作提示词；工具本身不依赖此开关。

## 构建与升级

本节构建的是独立 awa-ddd 插件。GitHub 仓库保存源码、测试、依赖锁文件和文档，不附带本机备份、验证日志或旧安装包。克隆/检出后，在项目根目录安装锁定依赖并重新验证、打包：

开发 SDK 的旧 Zod 4.4.3 命中高危集合校验资源耗尽公告；根项目通过 `overrides.zod:4.6.6` 和锁文件固定修复版，SDK 仍使用原 peer/rc.3，不复制第二份实例。该根 override 只约束本项目安装/验证，不会替安装宿主升级其 SDK 依赖；桌面宿主若仍固定旧 Zod，须由宿主侧单独维护。本次不修改桌面 profile 或全局依赖。

新增私有 CSPRNG nonce 对会话凭据及浏览器 fill 上下文的完整性输入加盐，盐不发送目标、不进入公开输出；同 generation 续期保留盐，新 generation 使用新盐，旧无盐记录按原规则验证。纯凭据/填值上下文摘要不公开，避免用两位 PIN 或六位 OTP 离线枚举摘要。原始材料摘要仍用于完整性检查，不是凭据加密或服务端事实认证。

```sh
npm ci
npm run check
npm run test:python
npm run pack:check
```

Windows PowerShell 可将 `npm` 换为 `npm.cmd`。以上检查在源码或打包文档变化后应重新运行。`pack:check` 会在已忽略的 `.validation` 目录内生成和提取本轮包，并写入 `.validation/package-check.json`。只有 `schema_version:1`、`result:passed`、`record_finalized:true`、`source_frozen:true`、`archive_membership_exact:true`、`final_packlist_unique:true`，且 `git_head`、`release_source_fingerprint` 完整，`.validation/package-check.lock` 与 `.validation/package-check.running.json` 均不存在时，才能采用该记录。旧 `commit_status` 仅表示验证记录落盘，不是 Git commit 或签名。归档保存在 `.validation/archives/<run_id>/`，从记录的 `archive_path` 取得实际包，并核对 `archive_sha256` 和当前源码摘要；安装核对示例见 [宿主契约](docs/HOST_CONTRACT.md#build-test-and-installation)。

安装时只能使用 production freeze 后本次生成的、已验证的包，再由用户在选择的 dsh profile 中安装并重载；awa-ddd 不自动改写桌面配置或存量评估库。当前代码提供 75 个动作，Playwright/TscanPlus 保留既有授权与证明边界。本机历史备份、验收 fixture、日志和 tarball 不属于源码发行或 fresh clone 的运行/验证依赖；历史验收说明也不等于当前检查通过。

需要手工 `npm pack` 时先完成上述验证，再把输出放入已忽略的 `dist` 新目录：

```powershell
$releaseDir = Join-Path 'dist' ('manual-release-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $releaseDir -ErrorAction Stop | Out-Null
npm.cmd pack --ignore-scripts --pack-destination $releaseDir
```

当前结果以重跑检查及新生成的记录为准。回归使用 mock、新建本地 fixture 或明确的本机运行时条件，不访问历史目标，也不把版本检查、历史验收或成功打包描述成漏洞验证。实际浏览器/扫描器能力仍按当前安装和授权边界核对，详见 [Playwright 策略](docs/PLAYWRIGHT_TESTING.md)、[TscanPlus 适配](docs/TSCANPLUS.md) 与 [Windows/WSL](docs/WINDOWS_WSL.md)。

## 当前范围

Yakit 仍仅提供 stdio MCP public GET 单包适配。sqlmap 支持 GET query 和受控 POST JSON/form 的唯一 SQL 参数；POST 须可回退 fixture，嵌套同名 JSON、multipart、GraphQL、PUT/PATCH 和通用扫描器仍无执行适配。BEU/risk1/level1 不是所有 SQL 技术。命令、模板、反序列化等类别没有通用正向机器确认，保留人工复核和有限阴性边界。

本地浏览器默认 `allow_write:false`、`max_writes:0`；项目开启 `allow_mutation` 后仍需单次显式 `allow_write:true`，并满足同源 operation/resource 与预算门禁。HTTPS 默认严格校验；重定向、跨源写、WebSocket 和 service worker 阻断。`state_scope:actor` 仅用于具体 HTTP 路径、没有任何已声明输入、实际无 query/正文/业务头或业务 Cookie 的自状态读/写；允许规范管理头、已核验分类的会话凭据及固定执行器 framing，其他业务输入必须绑定支持的 fixture。header/cookie fixture 不在支持范围，不改名绕过。旧 fixture-free 业务头写仍可读，但不再成为当前证据。旧工具缺启动快照、历史歧义资源或跨域凭据观察不伪造迁移。

原始材料和凭据留在项目隔离目录；`tool.artifact` 只提供摘要校验、脱敏后分页的 untrusted 文本。traffic 的无转义文本不能可信地区分正文中的假包头，只展示首段可辨认 framing，并显式标记剩余正文/数据包省略，不冒充完整逐包视图。外部工具必须来自可信本地安装：固定 argv 和范围绑定不是不可信二进制的 OS 沙箱。摘要用于检测材料改变，不代替服务端事实判断；未知/受阻、代表样本限制和人工复核来源都保留在报告中。
