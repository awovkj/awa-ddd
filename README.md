# awa-ddd

awa-ddd 0.9.0 是 DeepSeek Harness（dsh）的原生、证据驱动安全评估插件。它将操作、输入、主体/会话、测试资源、执行证据、候选与结论存入本地 SQLite，提供 10 组工具、60 个动作。模型沿用 dsh 运行时，不另接模型供应商。

本版依据指定的 `session-9b82695d-b0b9-4ada-81a5-02adc770121d` 对话升级：仍有 98 项就绪任务、134 项复核任务时，旧插件两次接受模型自报 `budget_exhausted`；模型之后承认没有用户或宿主给定的预算。0.9.0 将停止策略改为 **exhaustion_only 硬门禁：除严格核验的测无可测外，禁止以任何理由自动终止**。`plan.finalize` 只接受 `reason:completed`；旧部分退出仅留历史，不能使 `continue_required` 变成 false 或生成新的最终报告。详见 [本轮取证、实现与验证](docs/UPGRADE-20261031.md)。

保留 0.8.0 的持久化 checkpoint、来源绑定的行政 review 和截断恢复，以及 0.7.0 的公平短队列、独立漏洞族义务、多租户样本、复杂正文、状态链与中文复现交付。历史对话的统计不混作本次验收。旧外部退出契约被本版取代，见 [0.8.0 历史记录](docs/UPGRADE-20261030-CONTINUATION.md)、[0.7.0 历史记录](docs/UPGRADE-20261030-ASSESSMENT.md) 与 [人工复现指南](docs/REPRODUCTION.md)。

保留先前的范围/身份/资源血缘、SQL 元数据与真实 XSS 运行时门禁、不可变 finding 修订、UTF-8 文件调用和 WSL 边界；不将更多请求或人工文字冒充完整覆盖。0.6.x 历史修复见 [20261029](docs/UPGRADE-20261029.md) 与 [模式 RPC 修复](docs/UPGRADE-20261030.md)。

## 主要能力

| 能力 | 当前行为 |
|---|---|
| 原生接入 | 60 个动作与 Python help catalog 一致；UTF-8 JSON stdin、固定 argv、宿主取消和独立截止时间；放错顶层的 action 字段明确拒绝 |
| 开局与续接 | `continuation` v2 固定保留 exhaustion_only、剩余任务和严格布尔停测权限；渲染截断先重读当前页；checkpoint 保存闭环进展，重复发包/受阻声明不算耗尽 |
| 项目与发现 | 多源离线 OpenAPI/JS AST/HAR/ARTEX/SARIF 导入、精确输入、来源与 candidate 生命周期；仅驳回文字不再隐藏未验证线索 |
| 身份与资源 | 服务端主体/角色核验、严格 JSON、同 origin 会话、凭据头分类与 actor/fixture 快照；未知访问策略不会毒化整个项目，也不会被历史 200 响应推断为允许 |
| 执行与恢复 | 共用 preflight 门禁；JSON 字段名/Pointer/数组、唯一 form/multipart/Cookie 输入对照；原字节 `body_file`、持久 checkpoint 和失败 run_id；真实 scenario 的读/写/读 `state_transition`；不自动重放 |
| 浏览器 | 必需 / 明显有益的测试必须调用 Playwright；优先实际宿主 MCP、保留 native 回退；公共运行时材料按凭据上下文脱敏，原证据保留私有；超时保留 run 续接，不重放未知写 |
| Yakit MCP | 真实 stdio MCP 握手、tools/list 与受控 HTTP 单包重放；保存目录、交换、执行结果、传输告警及摘要 |
| TscanPlus MCP | loopback Streamable HTTP 握手和目录；受控 GET/HEAD/fixture POST 单包、已有项目结果与只读 route 建议入未验证候选、脱敏项目计数；兼容 3.5.4 结果数组，截断和远端未决保留 partial |
| sqlmap | GET query 与受控 POST JSON/form 单参数，POST 必须写授权与精确可回退 fixture；方法/头/原字节/身份/资源 V2 血缘；元信息-only，partial/signal 留为未验证候选 |
| SQL 确认 | 元数据直接回显/真实 sqlmap transcript/DBMS error channel；写侧行为证明必须是受控 SQL 输入及真实有限业务计数差异，普通响应差异不算 SQLi |
| 人工复核 | SQL proof 不放宽；XSS 可把精确正常/攻击输入、同身份真实消费页及运行时证明绑定具体义务，仍标为 analyst；无弹窗访问不否定整类 XSS |
| 判据与交付 | 畸形/歧义 JSON 与 bool/number 混淆不能冒充阴性对照，fresh/legacy 同判据；元数据包装/ACK 数组不是业务 readback；review 不关闭安全义务，最终交付仅 strict completed |
| 公共输出 | 所有项目动作与错误共用私有凭据上下文脱敏；已知秘密不经 surface/preflight/步骤标签回流，真实控制字段按动作 schema 保留；已分派执行不因输出失败被回滚或自动重放 |
| Windows / Kali | 文件式 UTF-8 调用避免 PowerShell 多层插值；可选 WSL 运行引擎及已适配工具，取消/超时终止本次 Linux 进程组 |

扫描器告警、工具目录、页面登记和请求数量都不会自动满足测试义务。SQL 弱证明、角色未知或身份/资源绑定变化保留历史，不能伪造迁移为已确认。新项目缺少 scope 时仅默认目标 URL 路径范围，不把 `/app` 静默扩大到整个 origin；存量显式 scope 不改写。

## 使用

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
```

默认评估目录为 `~/.dsh/awa-ddd-data`，位于插件包之外。工具统一接收 action、project_id、input；其余 action 字段（包括 limit/offset）必须放 input，不能放顶层。`action.help` 与 `runtime.probe` 无需 project_id。先看 `project.status`、`surface.list`、`plan.next`，每轮与交付前用 `plan.audit`，不要积累大量请求后才登记输入。

```json
{"action":"action.help","input":{"name":"http.capture"}}
```

`project.status` 默认最多 10 条各类实体与 5 个 gap 示例；`plan.list/report.coverage/finding.list` 默认 25 条、最多 100 条。模型展示限制为 24 KiB；出现 `render_recovery` 时先用更小 limit 重读当前 offset，并保留原过滤条件，再跟随正式 `next_offset`，不能跳过省略的条目。`plan.build.obligations` 是整数，`obligation_items` 才是分页明细。

闭环为 `plan.audit → plan.next / review_followups → 执行或复核并落账 → plan.checkpoint → 再读 continuation`。`continue_required:true` 必须继续现有授权内的 ready **及** review；空页、已有漏洞、请求数、耗时、上下文压力、低收益或草稿成功均不能授权自动停止，不得自行设定执行/轮次/时间/token/操作预算。无进展应换具体假设、补消费链/身份/资源或复核已有材料，不能重复写请求凑轮次。

`can_finalize:true` 只在非空登记范围、`completion.status:complete`、零 ready/review/blocked/unresolved、最新同快照 checkpoint 及两轮**完整、有效、证据绑定**的发现/12 族适用性/页面复核同时成立时出现。blocked frontier 不计完整轮次，全部任务标受阻也不等于测无可测。成功 `plan.finalize reason:completed` 后才有 `automatic_stop_allowed:true` 和 `can_claim_complete:true`；二者只针对有证据的登记范围，不证明未知攻击面不存在。

人工 `plan.disposition not_applicable` 保留声明与来源，但 `applicability_review_total` 仍是待验证工作：普通正常响应加一句业务理由不能抹掉整条义务。删减未测输入/漏洞族/分支、弱化角色/属主边界，或在明确 SQL/HTML 消费点省略所需族，会保留 `scope_reduction_review_total`；历史族不能被当前 consumer 改写。上述缺口不能被行政 `plan.review` 归档，须恢复实际边界并完成 typed 判据，不能靠“全部 N/A”或“删掉任务”绕过零剩余门禁。

`plan.disposition/plan.review status:blocked` 先按真实范围、身份、fixture、浏览器、材料和未知写前提重新投影。只靠文字标记的受阻项若实际可推进，保留原声明并给出 `blocker_reconciliation_required` 离线复核：先按当前模板 reopen，不能直接重放请求或放宽门禁。setup、输入追踪与已有证据复核不能被藏掉。完整失败只读浏览器材料可以行政复核，但不是成功页面或安全证明；真实缺前提仍受阻。

登记 URL 去除 query 后若缺少精确 scope 查询绑定，保留 `scope_binding_review_required` 离线准备：先 `surface.inspect`，再由调用者从当前授权来源提供真实完整 URL 并独立 `http.preflight`。模板只给 operation 引用，不从 scope 复制 query、不自动访问、不扩大范围；必需浏览器仍为 prepare 而非 invoke。真实身份、写授权、fixture、路径或页面阻塞不被此准备门绕过，已有有效证据仍可离线复核。

`candidate.dismiss` 仅有 reason 时仍保留发现复核与 `candidate.reopen` 提示。只有机验的 `basis:outside_scope`（具体可靠 URL 真在固定登记 scope 外，新增 exclude 不能作证），或 `basis:duplicate_operation`（精确普通操作线索，方法/协议/输入/分支和声明匹配，全部当前 typed 安全义务已闭环）才可关闭该复核；后者还需实际 `operation_id`。动态/私有 locator、扫描器告警或无关正常基线不能借此消失；来源、范围与证据改变重新打开复核，旧声明不迁移为已验证。拒绝导入的操作线索也有独立来源 ID，并仅对完全相同的旧线索保留旧 ID 与处置历史。

`blocked/budget_exhausted/user_stop/authorization_boundary` 均被最终收尾 API 拒绝；调用方文字、force/override 或自称宿主事件不能建立停止权。真实用户明确暂停/停止或宿主真实中断时遵守该事件，保存 checkpoint、必要的 draft 和真实恢复前提，不制造最终停止记录。旧部分 FN 原样保留，只读重开也不会恢复停止权。systemPrompt 的停止指引不受渗透模式开关影响；没有该服务仍保留引擎硬门禁。

已核验 rc.3 SDK 的 **`agent/turn-stopping` awaited serial 钩子**：正常准备结束轮次时，先离线审计真实 agent 已绑定的当前评估，再以插件自身来源的 `agent.steer` 继续尚可推进的工作、完整复核或正式收尾。新用户意图重置绑定，报告/历史检查不自动变成目标测试；真实取消前后不追加 steering，不使用另开轮次的 followup 冒充阻止结束。仅受阻且当前无可推进项时保留未完成 checkpoint，不重复发包。缺少公开宿主接口有可见降级；不能撤回已经输出的文字、强过实际取消/平台终止或保证无限运行。`continuationGuard:false` 仅供用户静态配置关闭宿主钩子，不关闭最终报告硬门禁。

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

新批次包含中文 `report.md`、完整 `summary.json`、`manifest.json` 和适用的 `reproduction/`，同时保留阶段、继续判定、停止依据与剩余工作。最终报告在准备材料之前及准备后分别检查严格闭环、当前快照/CP/FN 和全部零剩余计数；部分或不一致停止直接拒绝，不写最终报告目录。新材料或新 checkpoint 使旧停止记录失效。漏洞按严重度置前，每条说明主体/资源前提、编号步骤、实际请求与响应、修复和边界。SQL 注入只提供匹配参数和基线请求的只读元信息命令。

所有 `<AWA_...>` 都需人工替换，重新登录并准备自建资源后才能在授权范围复测；报告生成不执行命令。原始认证、重置令牌、验证码、支付密码和敏感配置不会直接导出，不能安全脱敏的正文明确不可复现。完整操作见 [REPRODUCTION.md](docs/REPRODUCTION.md)。

## TscanPlus MCP

接入用户提供的 `http://127.0.0.1:8088/mcp`。宿主 MCP 配置示例在 [examples/tscanplus-mcp.json](examples/tscanplus-mcp.json)；awa-ddd 不自动改写全局 MCP 配置或启动/重启共享扫描器。在已有评估项目中先做仅元数据探测：

```json
{"action":"tool.probe","project_id":"assessment","input":{"adapter":"tscanplus","mcp_url":"http://127.0.0.1:8088/mcp","scanner_project":"awa-demo"}}
```

`scanner_project` 必须对应本次评估获准读取的远端项目；省略时稳定派生独立 namespace，不会搜索或迁入其他项目。上游 Skill 写明项目全长最多 30 字符，但当前 TscanPlus 3.5.4 会裁剪长名；本适配器统一要求归一化后最多 20 字符。历史配置和材料保持不变，但旧的超过 20 字符的 namespace 不能用于新请求或读取：在连接 MCP 前拒绝，须明确用短名重新 probe，不能默默截断并查询另一个桶。旧 artifact 仍可离线 inspect，不会根据远端回显静默改项目。

`tool.tscanplus_request` 使用已登记操作、身份与 fixture 做受控单包；`tool.tscanplus_results` 只查询已配置的非默认项目并生成脱敏、未验证候选。`limit` 和 `result_limit` 兼容、默认 25、范围 1..100，同时提供时必须相等；远端没有 offset 分页。新增两个只读动作：

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

本地服务目录已实测 25 个工具，但目录不等于全部接入。URL/IP 扫描、POC、爆破、AK/JWT、多模块联动和 route 自动执行不在本版执行白名单；读取 route 建议不代表可以执行它。缺少已验证的跳转、范围和远端取消边界时不冒充安全适配。远端超时/断连和缺页保留未决，不能清空默认 MCP 桶、自动重放或声称服务端已停止。详见 [TSCANPLUS.md](docs/TSCANPLUS.md)。

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

本机实测 Kali WSL2、Python 3.14.7；sqlmap `/usr/share/sqlmap/sqlmap.py` 的版本调用成功。nmap、nuclei、nikto、ffuf 等路径存在，但没有通用执行适配，目录探测不算“已接入扫描”。WSL 没有检测到 Node/Yak，因此其本地 JS AST/浏览器/Yakit 能力不能冒充可用。需要浏览器时使用满足依赖的 native 后端或实际 MCP 输出。

WSL 不自动把 Windows `127.0.0.1` 改成网关，不能据此绕开 scope；Windows/WSL 项目目录应隔离，勿跨 OS 并发打开同一 SQLite。详见 [编码与 WSL 工作流](docs/WINDOWS_WSL.md)。

当前 Windows 主机上的 sqlmap 脚本为 `E:\hacker\天狐渗透工具箱-社区版V3.0\tools\gui_scan\sqlmap\sqlmap.py`。sqlmap 执行接口保留，调用该外部脚本；插件发行包仅包含适配器和路径指引，不包含 sqlmap 本体。

随包 [SKILL.md](skills/awa-ddd/SKILL.md) 提供操作指引。输入栏渗透模式按钮及 `/penetration` 命令保留为可选会话能力，只影响工作提示词；工具本身不依赖此开关。

## 构建与升级

GitHub 仓库保存源码、测试、依赖锁文件和文档，不附带本机备份、验证日志或旧安装包。克隆/检出后，在项目根目录安装锁定依赖并重新验证、打包：

开发 SDK 的旧 Zod 4.4.3 命中高危集合校验资源耗尽公告；根项目通过 `overrides.zod:4.6.6` 和锁文件固定修复版，SDK 仍使用原 peer/rc.3，不复制第二份实例。该根 override 只约束本项目安装/验证，不会替安装宿主升级其 SDK 依赖；桌面宿主若仍固定旧 Zod，须由宿主侧单独维护。本次不修改桌面 profile 或全局依赖。

新增私有 CSPRNG nonce 对会话凭据及浏览器 fill 上下文的完整性输入加盐，盐不发送目标、不进入公开输出；同 generation 续期保留盐，新 generation 使用新盐，旧无盐记录按原规则验证。纯凭据/填值上下文摘要不公开，避免用两位 PIN 或六位 OTP 离线枚举摘要。原始材料摘要仍用于完整性检查，不是凭据加密或服务端事实认证。

```sh
npm ci
npm run check
npm run test:python
npm run pack:check
```

Windows PowerShell 可将 `npm` 换为 `npm.cmd`。`pack:check` 会自动创建已忽略的 `.validation` 临时目录，解包并检查当前源码生成的发行包；完成后生成 `.validation/package-check.json`。确认该记录的 `result` 为 `passed`，再从 `archive_path` 取得实际安装包路径，并核对 `archive_sha256`。不要猜时间戳目录或仅凭版本号选择旧包。

安装时使用本次生成的包，在用户选择的 dsh profile 中安装并重载；不自动改写桌面配置或存量评估库。Playwright/TscanPlus 功能和当前 60 个动作不变。旧本地备份、验收 fixture、日志和 tarball 已清理；它们不属于 fresh clone 的运行/验证依赖，历史验收说明也不等于当前检查通过。

需要手工 `npm pack` 时先完成上述验证，再把输出放入已忽略的 `dist` 新目录：

```powershell
$releaseDir = Join-Path 'dist' ('manual-release-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $releaseDir -ErrorAction Stop | Out-Null
npm.cmd pack --ignore-scripts --pack-destination $releaseDir
```

当前结果以重跑检查及新生成的记录为准。回归使用 mock、新建本地 fixture 或明确的本机运行时条件，不访问历史目标，也不把版本检查、历史验收或成功打包描述成漏洞验证。实际浏览器/扫描器能力仍按当前安装和授权边界核对，详见 [Playwright 策略](docs/PLAYWRIGHT_TESTING.md)、[TscanPlus 适配](docs/TSCANPLUS.md) 与 [Windows/WSL](docs/WINDOWS_WSL.md)。

## 当前范围

Yakit 仍仅提供 stdio MCP public GET 单包适配。sqlmap 支持 GET query 和受控 POST JSON/form 的唯一 SQL 参数；POST 须可回退 fixture，嵌套同名 JSON、multipart、GraphQL、PUT/PATCH 和通用扫描器仍无执行适配。BEU/risk1/level1 不是所有 SQL 技术。命令、模板、反序列化等类别没有通用正向机器确认，保留人工复核和有限阴性边界。

本地浏览器默认只读，项目开启 `allow_mutation` 后允许同源写；重定向、跨源写、WebSocket 和 service worker 阻断。`state_scope:actor` 仅用于具体 HTTP 路径、没有任何已声明输入、实际无 query/正文/业务头或业务 Cookie 的自状态读/写；允许规范管理头、已核验分类的会话凭据及固定执行器 framing，其他业务输入必须绑定支持的 fixture。header/cookie fixture 不在支持范围，不改名绕过。旧 fixture-free 业务头写仍可读，但不再成为当前证据。旧工具缺启动快照、历史歧义资源或跨域凭据观察不伪造迁移。

原始材料和凭据留在项目隔离目录；`tool.artifact` 只提供摘要校验、脱敏后分页的 untrusted 文本。traffic 的无转义文本不能可信地区分正文中的假包头，只展示首段可辨认 framing，并显式标记剩余正文/数据包省略，不冒充完整逐包视图。外部工具必须来自可信本地安装：固定 argv 和范围绑定不是不可信二进制的 OS 沙箱。摘要用于检测材料改变，不代替服务端事实判断；未知/受阻、代表样本限制和人工复核来源都保留在报告中。
