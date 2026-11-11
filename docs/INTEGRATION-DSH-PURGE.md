# dsh-purge 内置评估与 awa-ddd 兼容交换契约

dsh-purge **1.8.0** 已将 awa-ddd **2.2.0** 的生产 Python/JavaScript 评估源码写入自身的 `lib/redteam/assessment-engine/`，随 dsh-purge 的源码和发行包提供。红队与 SRC 的当前使用入口是 dsh-purge 自己的原生评估工具，核心从本插件安装目录运行；使用者无需另装 awa-ddd、选择外部包路径或绑定外部项目。

`integration.import/export` 和 `dsh-purge-awa/v1` 格式继续保留。它们为独立 awa-ddd、其他调用者和旧交换资料提供有版本的元数据契约；dsh-purge 的内置核心也复用该格式，在同一靶标内导入候选、复核已有证明并更新来源账本。格式兼容不意味着依赖一个外部 AWA 安装或共享对方的 SQLite schema。

## dsh-purge 1.8.0 原生使用流程

每个 engagement 固定使用 `<当前靶标目录>/assessment` 工作区与内部 `project_id:assessment`。模式和首次选择的评估模型持久保存，运行路径、项目身份与工作区由 dsh-purge 自己提供。模型提交业务动作及其参数，不能替换内部 project、运行后端、源码路径或工作区。

| 原生工具 | 当前用途 |
| --- | --- |
| `redteam_assessment_status` | 查看随包核心与当前靶标的内部上下文 |
| `redteam_assessment_start` | 用当前授权的真实 HTTP(S) target/scope 初始化内部评估，首次可选 v1/v2 |
| `redteam_assessment_import` | 按页把当前靶标的候选和脱敏 HTTP 元数据导入内部评估账本 |
| `redteam_assessment_run` | 按已有 action 契约登记操作、绑定具体输入、准备控制或复核证据 |
| `redteam_assessment_review` | 接收复核回执，或显式重新核验当前机器证明并确认符合条件的发现 |
| `redteam_src_report` | 生成 SRC 发现报告，保留未测、受阻和待核实项 |

先在 dsh-purge 中创建或绑定当前靶标，SRC 任务在创建时选择 `assessment_mode:src` 并明确非空 scope 和 exclude（可为空）。有明确 URL 范围或范围内已登记实际 URL 时，首次评估操作可以初始化内部上下文；只有域名、IP 或 CIDR 而没有实际 URL 时，需要补充真实 HTTP(S) 目标和 URL 范围。初始化保留靶标授权与排除子路径，不从名称猜测协议或扩大范围。

交给 `redteam_assessment_start` 的参数示例：

```json
{"target":"https://authorized.example/application","scope":["https://authorized.example/application"],"assessmentModel":"v1"}
```

随后通过 `redteam_assessment_import` 传入 `offset/limit` 导入当前靶标候选，保留返回的 `import_id/candidate_id/next_offset`。具体动作交给 `redteam_assessment_run`，内部 project 由工具提供，例如：

```json
{"action":"assessment.prepare","input":{"operation_id":"实际返回的 O-ID","limit":3}}
```

陌生动作先用 `action.help` 查询契约。输入类候选必须将 `candidate.link` 绑定到具体 `operation_id` 和真实 `input_location/input_selector`；同 endpoint 的其他参数或其他漏洞族不能提供本项确认。

`redteam_assessment_review` 的 `verify:false` 将回执保存在来源账本并标为 `inferred`，不确认扫描器声明。`verify:true` 重新验证当前 machine decision、对应 confirmed finding、完整证据哈希及精确目标/漏洞族/输入关联，通过后形成本靶标的 observed 直接证据；重复复核不会重复生成证明。SRC 在该操作直接证据成立后保存停止记录，继续离线复核和报告。未测项仍保留分母，发现报告不声明整个攻击面耗尽。

旧的外部 AWA 路径设置、`awa-binding.json` 和独立项目资料保留作为历史记录，不选择新版的运行源码或内部上下文。兼容 JavaScript/HTTP 入口使用同一随包核心；新版模型工具为上述五个 `redteam_assessment_*` 入口。独立 awa-ddd 的项目与数据仍可按其独立工作流查看，不被新版 dsh-purge 自动迁移或改写。

## 独立 awa-ddd 的导入契约

以下原始 `action/args/project_id` 示例适用于独立 awa-ddd 或直接使用其交换契约的调用者。`integration.import/export` 在 v1 `awa_project` 和 v2 `awa_admin` 工具组中提供，均不发送目标请求。独立接收项目应已按自己的真实 scope/exclude 和 `assessment_mode` 创建；交换中的 `engagement.mode` 不改变接收项目的持久模式。dsh-purge 1.8.0 用户通过前述原生工具执行相应内部步骤。

```json
{
  "action": "integration.import",
  "args": {
    "project_id": "src-example",
    "exchange": {
      "schema": "dsh-purge-awa/v1",
      "engagement": {"id": "rt-example", "mode": "src"},
      "candidates": [{
        "external_id": "vuln-1",
        "url": "https://authorized.example/application/preview",
        "method": "GET",
        "title": "候选服务端请求伪造",
        "category": "ssrf",
        "severity": "medium",
        "source_status": "confirmed",
        "evidence_refs": ["http-1"]
      }],
      "http_evidence": [{
        "external_id": "http-1",
        "url": "https://authorized.example/application/preview",
        "method": "GET",
        "status_code": 200,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hash_scope": "metadata",
        "raw_material_included": false
      }]
    }
  }
}
```

单次交换最多 2 MiB，每个 section 最多 200 条对象，单候选最多 32 个来源证据引用。Node bridge 的单次 JSON 请求另有 1 MiB 上限，长材料应减小候选页。来源标识是有界 ASCII handle；数字标识可转换为字符串。每个完整 URL 都先按接收项目的 scope/exclude 检查，交换中的范围声明不会扩大项目授权。非法或冲突的 batch 整体回滚。

候选以来源 engagement + external ID 产生稳定 ID。重复导入复用它，保留已有 `candidate.link` 和处置历史，并追加新来源。相同外部 ID 的 URL 或 method 改变是冲突，不能静默重定向已关联的发现。

`source_status` 仅保存来源声明。即使来源写 `confirmed/exploited`，导入仍只创建 `unverified` candidate，不创建 `E-*`、decision、finding 或已完成覆盖。HTTP 元数据中的摘要保存为 `claimed_sha256`，其 `hash_scope` 为 `metadata`，表示交换元数据，不表示原始请求/响应字节已经得到 awa-ddd 验证。

导入丢弃原始请求、响应正文与凭据。若输入附带 HTTP，仅用于识别并删除在其他文本中复用的秘密，不作为本地证明。已知项目秘密与输入中的认证头、Cookie、秘密字段会用于脱敏；URL 查询值不入候选 locator。受保护的路径要求改成明确安全的 endpoint 后再导入。查询绑定仍须在真正请求前独立确认。

返回 `import_id`、`candidate_ids`、逐条映射 `{external_id,candidate_id,status,created}`、created/reused 数量及局限说明。直接材料应通过现有证据采集接口在正确身份、资源与对照下重新建立；元数据交换不回放请求。

## 独立复核与导出

1. 用 `candidate.inspect` 检查来源，以 `surface.register/batch` 明确登记真实操作与输入。
2. 用 `candidate.link` 关联确切操作。输入类候选还需显式 `input_location/input_selector`，不能把同 endpoint 的其他参数证明挪给当前候选。
3. 复用或建立真实控制材料，用既有 `assessment.prepare/evaluate` 或 v2 的冻结 recipe/run 判据复核。SRC 模式在直接证据成立后停止该操作。
4. 调用 `integration.export`，传入对应的 `import_id`，把可复核元数据交回原调用者。dsh-purge 1.8.0 在自己的内部上下文中由原生 review 工具完成此步。

```json
{
  "action": "integration.export",
  "args": {"project_id": "src-example", "import_id": "IMP-实际导入回执", "offset": 0, "limit": 25}
}
```

每条导出候选带原来源映射、关联 operation、decision 和 finding 摘要。decision 明确提供 `mode/proof_mode`、`oracle_type`、evidence ID 与 SHA-256、`current`、`validated` 和 `usable_for_confirmation`。凭据、请求正文、响应正文与秘密上下文摘要不导出。

只有本地当前 machine proof 能赋予确认权威：v1 使用 `current_machine_proof` 重新验证判据、义务、证据和当前操作；v2 重新检查冻结 recipe、实际控制请求、证据内容与离线 oracle 结果。具体漏洞族必须匹配；输入类还必须匹配实际 link。人工复核继续保留 `analyst` 身份，不能通过交换变成 machine proof。

导出不会信任外部 `source_status`、旧哈希或之前导出的结果。证据被修改、操作/身份/资源变化、判据不再当前或输入绑定缺失时，返回不可确认的元数据和原因，不发新请求。SRC 停测回执仍保持，不能借证据失效自动重启利用。

`limit` 为 1–100；单候选最多返回 20 个判据/发现摘要，`proofs_truncated` 显式表示样本。总响应限制在 2 MiB，`limited/next_offset` 保留实际分页位置。省略的证明不算已复核，候选元数据也不是覆盖度分母的替代品。

## 源码维护、许可与来源

源码维护命令只在 **dsh-purge 仓库根目录**由维护者显式执行：

```sh
node scripts/sync-assessment-engine.mjs --check
node scripts/sync-assessment-engine.mjs --source "../awa-ddd"
```

`--check` 只核对已写入 dsh-purge 的生产文件和来源清单，无需外部 awa-ddd checkout，也不访问网络。`--source PATH` 将明确选中、已审阅的本地生产源码同步写入 dsh-purge，保留必要的内部适配；上游锚点变化要求重新审读，普通同步拒绝覆盖已修改的受管源码。它是维护期的源码导入，普通运行和升级不会自动调用该脚本或加载外部项目。本独立项目的源码、用户数据与旧记录不被该命令改写。

dsh-purge 的内部组件目录保留原 [MIT 许可](../LICENSE) 内容与版权，并提供自己的 `README.md`、`NOTICE.md` 和 `provenance.json`。清单分别记录上游和随包文件的 SHA-256、文件来源与本地适配；dsh-purge 自有的私有上下文适配器单独标明来源。生产核心、动作目录和 AST 辅助代码由 dsh-purge 自己维护和打包，独立 AWA 插件入口及宿主 SDK 按各自项目的安装方式提供。

## 验证范围与来源

`tests/test_src_integration_20261111.py` 使用独立临时项目和合成 HTTP 证据验证 scope/exclude、批量原子性、幂等/冲突、秘密复用脱敏、来源与实际证据的区别、精确族/输入绑定和修改证据后的失效。`tests/src-mode.test.mjs` 通过实际 Python bridge 验证 v1/v2 入口。测试不调用外部目标、扫描器或利用工具。

dsh-purge 仓库的 `test/redteam-embedded-engine.test.mjs` 将受管核心、内部说明文件及声明的 acorn 依赖复制到独立临时安装，实际调用其中的 Python 引擎，验证无需同级 awa-ddd、源码完整性、SRC 写入前零请求拒绝、静态 JS 不执行、候选确认声明不获得证明，以及私有上下文的并发合并和事务回滚。`test/redteam-native-assessment.test.mjs` 从隔离的 `lib` 安装验证原生初始化、当前机器证明的复核、observed 证据、SRC 停止及报告生命周期。

这些测试分别验证独立契约和内置使用路径。真实 DSH GUI、外部工具安装、实际目标及完整桌面部署需另行验收；历史验收记录不等于本次测试已通过。
