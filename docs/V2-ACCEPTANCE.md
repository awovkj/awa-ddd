# AWA-DDD 2.0 验收与评审映射

本文件逐项对应 `awa-ddd-2.0-plan-review.md` 的 21 项评审事项。状态：实现/部分/设计约束。

| 评审项 | 实现 | 验收证据 |
|---|---|---|
| R01 正向 oracle 证明含义 | `execution/oracle_profiles.py` 为每个 profile 声明 proof_scope、机制契约、required observations、not_proof、失效条件；parser/reflection/timing/fake-path/manual dialog 均不确认 | `tests/test_v2_recipe_runner_20261103.py::OracleNegativeTests` |
| R02 人工复核接受契约 | `domain/review.py` + `execution/review_engine.accept`：机制/输入/分支、控制角色、消费点、来源、reviewer 类型、材料摘要、proof_scope；agent 不能自证 human | 同文件 `ReviewContractTests` |
| R03 处置/测试/交付/耗尽分离 | `planning/coverage.py` 分别报告 `disposition_rate` 与 `tested_coverage`；`campaign.finish partial_accepted` 不授予 exhaustion；`report.build final` 拒绝 | `test_v2_review_campaign_20261103.py` |
| R04 Recipe 冻结/override | `domain/test_recipe.py` spec_hash、bindings、变量白名单、URL path/security/oracle 禁止、`assert_current` | `test_v2_recipe_runner_20261103.py::RecipeContractTests` |
| R05 durable run/未知写效应 | `domain/test_run.py` 状态机与 `execution/test_runner.py`；写失败 `effect_unknown`、保留 run/evidence、不自动重放；幂等键不重复发包 | `TestRunTests.test_idempotency_key_never_replays_a_request` / `test_unknown_write...` |
| R06 角色/浏览器身份/跨角色链 | `domain/review.validate_cross_role` writer/viewer/resource_version/content_digest；`execution/browser_provider.evaluate_xss` application-triggered + same identity | `ReviewContractTests.test_cross_role_chain...` |
| R07 旧 decision 迁移 | `planning/migration.py` 只生成 `legacy_evaluation`，保留原 evidence.run_id 关系、`synthetic_test_runs=0` | `MigrationTests` |
| R08 KnownCase 三轨 | `domain/known_case.py` import/hint_assisted/blind；blind label withheld；`planning/known_cases.py` 不合并 source_group | `test_v2_domain_20261103.py::KnownCaseTrackTests` |
| R09 Universe 未知分母 | `domain/universe.py` source levels、`site_wide_discovery_allowed`、unknown_counts/incomplete sources；route_parser 静态解析限制 | `test_v2_universe_scheduler_20261103.py` |
| R10 Hypothesis 稳定键/Claim 失效依赖 | 稳定 identity 键；statement 不参与；claim 带 dependency/unknown_extent；recipe rebuild 后旧 recipe `assert_current` 失效 | `HypothesisIdentityTests` |
| R11 fixture/会话生命周期 | `execution/fixtures.py` create→verify→lease→mutate→readback→cleanup；cleanup_failed 保持 unresolved；写 recipe 要求 fixture revision/lease | `test_v2_recipe_runner_20261103.py` 写用例；fixture 单元可直接调用 |
| R12 竞态/异步/OAST/认证策略 | `oracle_profiles` 定义 race/token_lifecycle 契约；执行器保留有界顺序能力；异步 collector 标为边界 | 设计约束，见下文“未实现” |
| R13 调度轮转/持久 claim | `planning/scheduler.py` family_gap/aging/readiness、两次失败 cooldown、round-robin cursor、claim lease | `test_v2_universe_scheduler_20261103.py` |
| R14 capability readiness | `execution/capabilities.py` installed/configured/catalog_verified/profile_supported/authorized/ready，recipe-specific `ready_for` | `recon.capabilities` 输出与测试 |
| R15 宿主 goal/续接 | 未自动 create_goal；保留现有 host-continuation stop policy；不伪造真实 progress | `docs/HOST_CONTRACT.md` 既有约束 |
| R16 双写/回滚/只读 | `campaign.migrate` 只读投影不执行 DDL；apply 写 migration ledger；v1 保留可写；rollback 只改 model | `MigrationTests`，`V2-MIGRATION.md` |
| R17 工具/契约/发布目录 | Python `ALL_CONTRACTS`/`V2_GROUPS`；Node `V2_ACTION_GROUPS`；setuptools find；reporting shim | `tests/plugin-v2.test.mjs`、package check |
| R18 私有 recipe/预算 | `test_recipe.public_view` 只返回引用/hash，不含私有 body/凭据；1 MiB capsule 与 4 MiB store 预算 | `RecipeContractTests` |
| R19 规模/增量 | `domain/repository.py` 索引表 + 分页；查询不拉全量历史；coverage/compute 按当前实体计算 | repository 单元行为 |
| R20 指标单位 | coverage 五维分母；known case 分轨；machine proof 与 reviewed detection 分栏；报告明确 N/A | `report.matrix` 测试与报告渲染 |
| R21 阶段顺序 | 本仓库按可运行模块一次性实现 Phase 1–3 核心；Phase 4–5 为 adapter/边界；见架构文档“当前边界” | 无时间承诺；以测试和真实 E2E 为准 |

## 最低验收矩阵（实现侧）

| 场景 | 结果 |
|---|---|
| 安全类型白名单/允许公式/纯反射/时延噪声/虚构上传路径 | 不确认相应漏洞（OracleNegativeTests） |
| 全 blocked/inconclusive/N/A、伪造 partial 接受 | 不获得 exhausted authority（CampaignDeliveryTests） |
| 修改 recipe/oracle/URL/fixture 或目标变量选择控制字段 | 拒绝（RecipeContractTests/assert_current） |
| 写成功后断连/崩溃/取消 | effect_unknown 保留、不自动重发（TestRunTests） |
| 商户写入、管理员消费的跨角色 XSS | writer/viewer 两组同身份 + 内容版本一致才接受（ReviewContractTests） |
| MCP JSON/tabs/角色分支冒充身份 | browser_provider/ publication 保持未验证 |
| 旧 decision 复制/双写 | legacy_evaluation，不合成 TestRun（MigrationTests） |
| 截断 bundle/动态路由/来源缺失 | route_parser 返回 unresolved/limitations；Universe 不声称全站 |
| 长历史/两个 worker | claim lease 冲突；repository 分页/索引 |
| npm/wheel 提取 | `npm run pack:check`（另行运行） |

## 未实现/边界（必须如实报告）

- 真实宿主 Playwright MCP 的取消、context 隔离和多角色会话仍依赖宿主能力；`browser_provider` 只接受可核验的本地 observation。
- 完整 race/OAST collector、异步回调归属、跨角色浏览器自动化 UI 尚未形成端到端执行器；只有严格 profile/契约与拒绝用例。
- 真实靶场 A/B 盲测未在本仓库执行；`KnownCase` 只做选题和分轨报告，不能替代独立复现。
