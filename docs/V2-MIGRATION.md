# AWA-DDD 2.0 迁移与兼容

本文描述当前 2.3.0 工作树中的 V1/V2 兼容实现。迁移、回滚、CompletionEvaluator 和 V2 acceptance 已通过本地 Python 全量回归；真实 campaign、用户已有库迁移和部署环境仍需独立核验。发行采用条件及实际证据见 [升级说明](UPGRADE-20261121-SOURCE-LEDGER.md#验证状态)，本地 fixture 通过不代表用户生产库已经迁移。

## 1. 模式

`package.json` 的插件配置新增：

```json
{"assessmentModel": "v1"}
```

- `v1`（默认）：注册 10 组、75 个动作；旧项目读写兼容及显式迁移/回滚路径保留。
- `v2`：注册 `awa_campaign/awa_recon/awa_test/awa_review/awa_report/awa_admin` 六组、41 个动作；新评估使用 Campaign。两个目录共享 17 个动作，并集为 99 个。
- 项目自身还有 `config.assessment_model`（`v1|v2`）。`campaign.start` 在无旧 obligation 的项目上自动设 v2；有旧 obligation 时必须显式迁移确认。

## 2. 旧对象投影

| v1 | v2 | 规则 |
|---|---|---|
| operation/input | Universe.operations/inputs | 保留 ID；新增 source_kind / consumer_status |
| obligation | Hypothesis（`legacy_obligation`） | 保留原 obligation_id/status；不改写历史 |
| decision | `v2_legacy_evaluation` | 保留原 decision、evidence_ids 与 evidence.run_id 关系；**不创建 TestRun** |
| finding | `v2_finding` 投影/`legacy_unlinked` | 有 decision→obligation 关系才可关联；缺失关系不伪造 |
| page/page_visit | Route/Page/Function/Universe | 页面访问记录保留 |
| checkpoint | CampaignCheckpoint | 旧 checkpoint 保留为历史；新 checkpoint 是 v2 快照 |
| candidate | `v2_hypothesis(source=imported/hint)` | 只在显式 promote/link 时升级；保留 hint 来源 |

## 3. 执行迁移

```json
{"action":"campaign.migrate","project_id":"assessment","input":{}}
```

默认只返回只读投影（`synthetic_test_runs:0`），不执行 DDL、不写 v2 记录。应用迁移需：

```json
{"action":"campaign.migrate","project_id":"assessment","input":{"apply":true,"confirm":true}}
```

它写入 `v2_migration` ledger（source_schema、source_counts、projection_sha256、synthetic_test_runs=0、rollback 说明），随后可以创建 Campaign。v1 数据仍然保留并可读写；v2 记录是追加投影。

底层工作区 schema 仍为 `schema_version=1`。本批新增表、索引、投影和迁移 ledger 采用 additive 初始化，已有预算表只追加列；这不改变旧实体语义，也不授权复用历史 N/A、finding 或运行记录。`campaign.migrate`/`project.migrate` 的显式 ledger、备份、quarantine 和 legacy 标记用于处理领域投影，不能把 `schema_version=1` 的兼容初始化当成领域迁移已获证明。

回滚：

```json
{"action":"campaign.rollback","project_id":"assessment","input":{"ledger_id":"MIG-..."}}
```

只把 `assessment_model` 设回 v1，不删除 v2 历史。

## 4. 双写与冲突

- 同一事实只有一个执行器：v1 动作继续写 v1 实体；v2 `test.run` 写 v2 `v2_run` 与 v1 `evidence`（由现有 `engine.capture` 产生）。两者通过 evidence/run ID 关联，不复制网络请求。
- v2 `legacy_evaluation` 是只读投影；不得把它当作新执行或新证据。
- 旧报告 `report.build` 在 v1 项目走原路径；v2 项目走 `reporting.build_v2_report`，不会把旧报告参数强制改成新语义。
- 旧项目的 `plan.finalize` 与 v2 `campaign.finish` 共享 `CompletionEvaluator` 的当前完成判定，分别生成对应交付接受记录；v2 项目不借用旧 `finalization_id` 授予权限。
- `plan.accept_partial` / V2 `partial_accepted` 只记录有界的当前交付已接收。它不授予 exhausted authority，不允许自动停止，不暂停正常宿主续接，也不能生成 final report；剩余 ready/review/blocked/unresolved 工作和其他完成门禁继续生效。

## 5. 发布

- `pyproject.toml` 使用 `[tool.setuptools.packages.find] include = ["awa_ddd*"]`，包含 `domain/planning/execution/reporting` 子包。
- `reporting.py` 已迁移为 `reporting_legacy.py` + `reporting/__init__.py` 兼容 shim；`from awa_ddd.reporting import build_report/coverage/safe_*` 保持可用。
- `scripts/check-package.mjs` 的 required 清单已包含新子包和 `reporting_legacy.py`。wheel/sdist fresh install 与 npm 提取 smoke 必须属于本次冻结源码，并通过版本、75 动作目录（含 `report.artifact`）、资源、源码与归档字节核对；历史包通过记录不能替代本轮结果。

当前本地结果：Python 1,708 tests、OK、跳过 1 项 Windows 不适用的 POSIX FIFO；2,000 operations / 20,000 evidence / 500 pages 的 warm 查询均达到 p95 < 500 ms。Node 全量测试数以本次冻结后的 `full-node-result.json` 为准，最终包是否可采用以 `final-validation.json` 的 passed 和当前字节绑定为准。真实 DSH 桌面、WSL 和其它 OS 未在本轮实测；Tscan 主动能力 unavailable，`dsh-purge 1.8.0` 内嵌的 2.2.0 也不会自动升级。
