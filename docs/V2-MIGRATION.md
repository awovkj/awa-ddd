# AWA-DDD 2.0 迁移与兼容

## 1. 模式

`package.json` 的插件配置新增：

```json
{"assessmentModel": "v1"}
```

- `v1`（默认）：注册原 10 组、63 个动作；所有旧项目可读写续接。
- `v2`：注册 `awa_campaign/awa_recon/awa_test/awa_review/awa_report/awa_admin` 六组；新评估使用 Campaign。
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

回滚：

```json
{"action":"campaign.rollback","project_id":"assessment","input":{"ledger_id":"MIG-..."}}
```

只把 `assessment_model` 设回 v1，不删除 v2 历史。

## 4. 双写与冲突

- 同一事实只有一个执行器：v1 动作继续写 v1 实体；v2 `test.run` 写 v2 `v2_run` 与 v1 `evidence`（由现有 `engine.capture` 产生）。两者通过 evidence/run ID 关联，不复制网络请求。
- v2 `legacy_evaluation` 是只读投影；不得把它当作新执行或新证据。
- 旧报告 `report.build` 在 v1 项目走原路径；v2 项目走 `reporting.build_v2_report`，不会把旧报告参数强制改成新语义。
- 旧项目的 `plan.finalize` 与 v2 `campaign.finish` 是两套交付门禁；v2 项目不会依赖旧 `finalization_id`。

## 5. 发布

- `pyproject.toml` 使用 `[tool.setuptools.packages.find] include = ["awa_ddd*"]`，包含 `domain/planning/execution/reporting` 子包。
- `reporting.py` 已迁移为 `reporting_legacy.py` + `reporting/__init__.py` 兼容 shim；`from awa_ddd.reporting import build_report/coverage/safe_*` 保持可用。
- `scripts/check-package.mjs` 的 required 清单已包含新子包和 `reporting_legacy.py`；npm/wheel 提取 smoke 继续执行。
