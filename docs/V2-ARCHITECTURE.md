# AWA-DDD 2.0 架构

版本：2.0.0。设计输入：`awa-ddd-2.0-refactor-plan.md`（0.13）与 `awa-ddd-2.0-plan-review.md`（21 项评审）。本文件描述实际实现，不把方向稿当成已完成事实。

## 1. 主线

```
Campaign
  ├─ Universe    有来源的已知攻击面（route/page/function/operation/input/consumer）
  ├─ KnownCase   导入的可选题案例（import / hint_assisted / blind 三轨分离）
  ├─ Hypothesis  稳定机制键的安全问题
  │    └─ TestRecipe  冻结的私有可执行胶囊 + 有界公开投影
  │         └─ TestRun durable 执行事实（steps / evidence / effect_unknown）
  │              ├─ Finding  machine / reviewed（detection 与 machine proof 分离）
  │              └─ CoverageClaim 引擎计算的多维声明
  └─ Checkpoint / Delivery（partial_accepted 与 exhausted authority 分离）
```

## 2. 为什么这样分层

- **Universe 不是全站真值**：`source_completeness` 只声明来源清点等级；没有 `complete_snapshot` 时，`site_wide_discovery_allowed=false`，所有发现率都只对“已知分母”负责。`unknown_counts` 与 `unresolved/truncated` 永久可见。
- **Hypothesis 身份不是 statement**：身份键 = `family/security_property + operation/protocol + input location/selector/schema_branch + actor/resource relation + business precondition + scope_epoch + target_build + source_kind`。改措辞不加新任务，改机制/输入/角色关系才产生新身份。
- **TestRecipe 冻结**：`spec_hash` 覆盖 provider/version、operation signature、scope epoch、session generation、resource/fixture revision、oracle ID/version、全部控制与私有 manifest。`test.run` 只接受声明过的 caller data 变量；URL 路径、方法、身份、资源、fixture、oracle、expected 和 provider 不可覆盖。
- **durable run**：`prepared → claimed → dispatch_started → response_saved → evaluation_pending → evaluated → published`；写请求在 dispatch 后失联进入 `effect_unknown`，保留 `run_id/evidence_ids`，绝不自动重放。
- **reviewed detection ≠ machine proof**：`ReviewAcceptanceContract` 绑定机制、输入/分支、控制角色、观测、消费点、来源、复核者类型、材料摘要与接受 proof_scope。`agent_recorded` 不能自证 `human_independent`。
- **coverage 分维度**：Discovery、Consumer、Hypothesis（另报 disposition_rate 与 tested_coverage）、KnownCase（按轨）、Machine Proof；delivery acceptance 单独记录。任何调用者都不能自填分子/分母。

## 3. 模块

| 层 | 模块 | 职责 |
|---|---|---|
| 领域 | `awa_ddd/domain/` | universe/hypothesis/test_recipe/test_run/finding/coverage_claim/known_case/gap/review/campaign；`repository.py` 提供同库文档与索引 |
| 规划 | `awa_ddd/planning/` | `route_parser` 静态路由解析；`known_cases` 三轨导入；`hypotheses` 12 族/字段语义/needs_consumer；`scheduler` 公平轮转/attempt 冷却/lease；`coverage` 五维矩阵；`campaign` 生命周期；`migration` legacy 投影 |
| 执行 | `awa_ddd/execution/` | `recipe_builder`、`test_runner`、`oracle_profiles`、`review_engine`、`fixtures`、`capabilities`、`browser_provider`、`external_provider` |
| 报告 | `awa_ddd/reporting/` | `matrix.py` 五维矩阵/中文报告；`__init__.py` 兼容旧 `reporting.py` 全部导出（原文件保留为 `reporting_legacy.py`） |
| 工具面 | `awa_ddd/v2api.py` + `contracts.py` | v2 动作 dispatch；旧 63 动作保留 |
| Node | `src/actions.mjs`、`src/tools.mjs` | `assessmentModel:v1` 注册 10 组旧工具；`assessmentModel:v2` 注册 6 组 v2 工具 |

## 4. 工具面

v2 模式（`assessmentModel: "v2"`）注册六组：

| 工具 | 动作 |
|---|---|
| `awa_campaign` | `campaign.start/status/next/checkpoint/finish/migrate/rollback` |
| `awa_recon` | `recon.snapshot/import/routes/hypotheses/capabilities` |
| `awa_test` | `test.run/run_browser/run_scenario/run_external/record_external/inspect` |
| `awa_review` | `review.evidence/finding/bind/disposition` |
| `awa_report` | `report.matrix/build/compare` |
| `awa_admin` | 旧 project/identity/resource/help 动作 |

默认 `v1` 保持原 10 组 63 动作。v2 动作在 Python `ALL_CONTRACTS` 校验；`action.help` 默认返回 v1 目录，`action.help {catalog:"v2"}` 返回六组目录。旧项目不需要重新创建。

## 5. Proof profile（对 R01 的落地）

`awa_ddd/execution/oracle_profiles.py` 为每个 profile 声明 `proof_scope`、机制契约、必需观察、`not_proof`、严重度上限与失效条件：

- `parser_identification` **永不**确认反序列化/RCE；安全类型白名单拒绝也可满足。
- `unexpected_expression_evaluation` 必须同时有正常纯值、攻击算术值、阴性字面值和反射排除；只证明“表达式被求值”，不证明代码执行。
- `unsafe_type_instantiation` 需要精确类型标记 + 有界 canary + 未知类型阴性。
- `bounded_side_effect` 明确 `timing_not_sole_evidence` 与 `reflection_exclusion`；时间抖动不是命令执行。
- `upload_path_escape` 需要声明的存储契约、自有文件内容回读、路径在允许根之外且文件名/内容分离；只返回一个虚构路径不确认。
- `browser_runtime` 只接受 application-triggered dialog、真实消费页、同身份控制组和内容版本；manual evaluate/静态 HTML/MCP 导入不确认。

## 6. 生命周期与失效

- **Hypothesis**：`unplanned → ready → running → supported|refuted|inconclusive|blocked`；`not_applicable` 必须有业务事实依据；`blocked` 必须有具体 `missing_context`。`inconclusive` 可由结构化人工复核升级为 `supported`（仍不是 machine proof）。
- **Finding**：machine_confirmed / reviewed_confirmed / rejected / withdrawn；`current` 与 lifecycle 追加，不重写旧证据。
- **CoverageClaim**：引擎计算；依赖 universe snapshot hash、recipe spec、oracle version、evidence digest 与 target build。任何输入变化后旧 claim 不能沿用。
- **Campaign**：`partial_accepted` 是交付，不是耗尽；`completed` 要求零 remaining hypothesis/family/route/gap 且当前 checkpoint。

## 7. 安全边界

- 目标写入必须同时满足：项目 `allow_mutation`、campaign `allow_mutation`、recipe `effect:test_resource_write`、`max_writes:1`、冻结 fixture revision、fixture verified/leased 状态和 worker lease。
- 外部工具输出（Yakit/TscanPlus/sqlmap/local script）只进入 unverified candidate/receipt，不直接成为 Finding；`record_external` 保存来源与 digest，标记 `unverified_external`。
- 浏览器导入的 MCP JSON 不绑定 session/actor；authenticated XSS 需要本地真实 visit + application-triggered dialog + 真实消费页。
- 私有 recipe capsule 不进入公开投影；公开投影只含控制 ID、request locator hash、oracle ID/version、limits 和 private_ref。原始凭据由 `identity.session` 私有上下文提供。

## 8. 当前边界

- `campaign.start` 不自动创建宿主 goal；宿主 goal 接口在本版本未验证，按 `docs/HOST_CONTRACT.md` 的既有 stop-policy 运行。用户显式暂停/停止/宿主中断优先。
- `browser_provider` 的 XSS 评估要求实际保存的 visit/evidence；没有宿主 Playwright 时保持 blocked，不伪造。
- `race`、`token_lifecycle`、异步 OAST 的 proof profile 已定义；执行器仍按有界 HTTP/scenario 能力执行，未实现完整并行屏障或 collector。
- 真实 A/B 盲测需要在固定靶场状态、账号/订单/验证码状态下独立运行；当前仓库只提供离线契约与回归测试，不能据此声称召回率。
