# awa-ddd

awa-ddd 0.8.0 是 DeepSeek Harness（dsh）的原生、证据驱动安全评估插件。它将操作、输入、主体/会话、测试资源、执行证据、候选与结论存入本地 SQLite，提供 10 组工具、60 个动作。模型沿用 dsh 运行时，不另接模型供应商。

本版针对指定的 `session-d1022f34-ea19-42f2-80f0-bb64b313764d` 对话升级停测与续接：会话已使用 0.7.0，最后仍有 154 项就绪任务、130 项复核任务，却提前交付；工具截断还把 25 条任务显示为 5 条，却保留 `next_offset:25`。新增结构化 `continuation`、持久化 `plan.checkpoint`、来源绑定的行政 `plan.review` 与正式 `plan.finalize` 门禁；草稿不是完成凭证，最终报告必须引用当前停止记录。详见 [本轮升级记录](docs/UPGRADE-20261030-CONTINUATION.md)。

保留 0.7.0 的公平短队列、独立漏洞族义务、多租户样本、复杂正文、状态链与中文复现交付。旧的 13 个发现、3/382 条义务和 107 个未追踪输入属于上一份对话，不混作本次统计。历史实现见 [0.7.0 升级](docs/UPGRADE-20261030-ASSESSMENT.md) 与 [人工复现指南](docs/REPRODUCTION.md)。

保留先前的范围/身份/资源血缘、SQL 元数据与真实 XSS 运行时门禁、不可变 finding 修订、UTF-8 文件调用和 WSL 边界；不将更多请求或人工文字冒充完整覆盖。0.6.x 历史修复见 [20261029](docs/UPGRADE-20261029.md) 与 [模式 RPC 修复](docs/UPGRADE-20261030.md)。

## 主要能力

| 能力 | 当前行为 |
|---|---|
| 原生接入 | 60 个动作与 Python help catalog 一致；UTF-8 JSON stdin、固定 argv、宿主取消和独立截止时间；放错顶层的 action 字段明确拒绝 |
| 开局与续接 | `plan.next/audit` 返回固定保留的继续判定；渲染截断先重读当前页；`plan.checkpoint` 保存闭环进展并续接，重复发包或重复判据不算进展 |
| 项目与发现 | 多源离线 OpenAPI/JS AST/HAR/ARTEX/SARIF 导入、精确输入、来源和 candidate 生命周期 |
| 身份与资源 | 服务端主体/角色核验、同 origin 会话、凭据头分类与 actor/fixture 快照、唯一资源绑定；同角色跨租户不被去重，采样范围和预算公开 |
| 执行与恢复 | 共用 preflight 门禁；JSON 字段名/Pointer/数组、唯一 form/multipart/Cookie 输入对照；原字节 `body_file`、持久 checkpoint 和失败 run_id；真实 scenario 的读/写/读 `state_transition`；不自动重放 |
| 浏览器 | 隔离 Playwright、逐请求保护与 SPA trail；成功本地观察自动采纳实际页面，`page.adopt` 可离线归档旧观察；功能仍需真实交互，MCP 来源不变 |
| Yakit MCP | 真实 stdio MCP 握手、tools/list 与受控 HTTP 单包重放；保存目录、交换、执行结果、传输告警及摘要 |
| TscanPlus MCP | loopback Streamable HTTP 握手和目录；受控 GET/HEAD/fixture POST 单包、已有项目结果与只读 route 建议入未验证候选、脱敏项目计数；兼容 3.5.4 结果数组，截断和远端未决保留 partial |
| sqlmap | GET query 与受控 POST JSON/form 单参数，POST 必须写授权与精确可回退 fixture；方法/头/原字节/身份/资源 V2 血缘；元信息-only，partial/signal 留为未验证候选 |
| SQL 确认 | 元数据直接回显/真实 sqlmap transcript/DBMS error channel；写侧行为证明必须是受控 SQL 输入及真实有限业务计数差异，普通响应差异不算 SQLi |
| 人工复核 | SQL proof 不放宽；XSS 可把精确正常/攻击输入、同身份真实消费页及运行时证明绑定具体义务，仍标为 analyst；无弹窗访问不否定整类 XSS |
| 纠错与交付 | `plan.review` 不关闭安全义务；不确定写需具体只读资源状态核对；正式收尾检查可推进队列及两轮有来源的范围复核，中文报告显著区分 draft/final-partial/final-completed |
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

闭环为 `plan.audit → plan.next / review_followups → 执行或复核并落账 → plan.checkpoint → 再读 continuation`。`continue_required:true` 不因空页、已有漏洞、请求数或报告生成而变成完成。`completed/blocked` 收尾需要两轮同快照的发现、12 族适用性、页面边界复核和零可推进项；复核是有来源的范围声明，不是两次独立实验。用户暂停、实际预算或授权限制只能作明确的部分退出，调用方不得编造原因；引擎不认证宿主事件，也不能阻止模型自由文本结束会话。

## 中文可复现报告

```json
{"action":"plan.audit","project_id":"assessment","input":{"limit":25}}
```

```json
{"action":"report.build","project_id":"assessment","input":{"stage":"draft","output_dir":"D:/Assessments/reports"}}
```

默认阶段为 draft，成功只代表生成快照，不是停测许可。最终交付先按 `action.help` 契约执行 `plan.finalize`，再使用真实 `finalization_id`：

```json
{"action":"report.build","project_id":"assessment","input":{"stage":"final","finalization_id":"<实际停止记录ID>"}}
```

新批次包含中文 `report.md`、完整 `summary.json`、`manifest.json` 和适用的 `reproduction/`，同时保留阶段、继续判定、停止依据与剩余工作。新材料或新 checkpoint 使旧停止记录失效。漏洞按严重度置前，每条说明主体/资源前提、编号步骤、实际请求与响应、修复和边界。SQL 注入只提供匹配参数和基线请求的只读元信息命令。

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

从完整源码生成发行包：

```powershell
npm.cmd pack --ignore-scripts --pack-destination .validation
```

续接升级的历史发行包为 `.validation/awa-ddd-0.8.0.tgz`，历史源码备份及摘要保持不变。2026-10-31 的 TscanPlus 补齐包另存于 `.validation/tscanplus-completion-20261031-155601-616175/release/awa-ddd-0.8.0.tgz`；版本号仍为 0.8.0，安装时应使用这个新包的完整路径并重载，不要误用旧包。补齐前源码和 SHA-256 清单、隔离打包摘要与本机 fixture 验收材料均保存在 `.validation/tscanplus-completion-20261031-155601-616175/`。不自动改写桌面宿主配置或存量评估库，安装新包并重载后才读取新增动作。

验证命令：`npm.cmd run check`、`npm.cmd run test:python`、`npm.cmd run pack:check`。旧版 WSL 中文/emoji、版本调用及进程取消验证继续保留，本轮不冒称重新验证未执行能力。历史对话、数据库和报告只读分析；回归使用 mock、新建本地 fixture 或隔离历史副本，不访问历史目标，也不把版本检查描述成漏洞验证。

## 当前范围

Yakit 仍仅提供 stdio MCP public GET 单包适配。sqlmap 支持 GET query 和受控 POST JSON/form 的唯一 SQL 参数；POST 须可回退 fixture，嵌套同名 JSON、multipart、GraphQL、PUT/PATCH 和通用扫描器仍无执行适配。BEU/risk1/level1 不是所有 SQL 技术。命令、模板、反序列化等类别没有通用正向机器确认，保留人工复核和有限阴性边界。

本地浏览器默认只读，项目开启 `allow_mutation` 后允许同源写；重定向、跨源写、WebSocket 和 service worker 阻断。`state_scope:actor` 仅用于具体 HTTP 路径、实际无 query/正文的自状态读/写，非空业务输入必须绑定 fixture。旧工具缺启动快照、历史歧义资源或跨域凭据观察不伪造迁移。

原始材料和凭据留在项目隔离目录；`tool.artifact` 只提供摘要校验、脱敏后分页的 untrusted 文本。traffic 的无转义文本不能可信地区分正文中的假包头，只展示首段可辨认 framing，并显式标记剩余正文/数据包省略，不冒充完整逐包视图。外部工具必须来自可信本地安装：固定 argv 和范围绑定不是不可信二进制的 OS 沙箱。摘要用于检测材料改变，不代替服务端事实判断；未知/受阻、代表样本限制和人工复核来源都保留在报告中。
