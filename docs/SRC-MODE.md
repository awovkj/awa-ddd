# SRC 模式：发现、直接证据、停止

SRC 是独立的项目执行策略，与 `assessmentModel:v1/v2` 是两个不同设置。v1 和 v2 项目均可创建为 SRC；既有项目缺少该字段时按 `assessment` 处理。宿主 `/src` 或 `assessmentMode:src` 指导创建 SRC 项目，并随请求提交 `required_assessment_mode:src`。引擎会检查数据库中的真实模式；会话选择不能改变旧项目的权限。

```json
{
  "action": "project.create",
  "args": {
    "project_id": "src-example",
    "target": "https://authorized.example/application",
    "scope": ["https://authorized.example/application"],
    "exclude": ["https://authorized.example/application/logout"],
    "assessment_mode": "src",
    "allow_mutation": false
  }
}
```

模式保存在项目数据库中，并在 `Project.set_config` 和 `project.update` 两层保持不可变。SRC 禁止开启 `allow_mutation`。需要另一种评估方式时创建单独项目，保留原有证据、发现和停测记录。

## 执行规则

- `http.capture` 仅接受 `GET/HEAD/OPTIONS` 与 `effect:read_only`。请求重新检查现有 scope/exclude、操作、身份和资源绑定；实际执行的超时最多 15 秒、响应最多 64 KiB。较大预算会被收紧，截断响应沿用既有“不完整证据”规则。
- 原生 `browser.visit` 保持只读，仅接受观察等待类动作；点击、填写、按键和 `allow_write:true` 不可用。真实浏览器仍使用既有每个请求的范围与方法检查。
- SRC 禁用主动 `tool.sqlmap`、`tool.yakit_replay`、`tool.tscanplus_request`、`test.run_external` 及多步骤 `scenario.run/test.run_scenario`。外部工具结果查询、已有证据导入与离线复核仍可使用。
- `identity.resource` 等本地台账操作不会创建目标资源。目标写入和 v2 fixture mutation 均不可执行。
- 已接受的正向安全判据或已记录的、具有直接证据的发现，会为该操作产生不可变 `src_stop`。之后的新请求返回 `stopped_at_evidence`；更换内容类型或将同一路径模板重新登记为具象 URL，也不会恢复执行。
- 已成功请求的同一个幂等键可以读取原证据，不会再次发包。普通 `assessment.prepare/evaluate`、`finding.bind`、`evidence.inspect`、报告与交换接口继续离线工作。其他操作可以继续发现。

这是一条引擎执行边界，不能判断服务器是否错误地让 GET 产生业务写入，也不能约束独立运行的 shell 或外部 MCP 工具。目标授权、正常业务请求的影响与明确排除路径仍应由使用者按实际场景确定。SRC 工具入口不会把提示词当成数据库模式或目标授权。

## 证明与覆盖

沿用现有 typed oracle、真实对照、身份/资源绑定和 SHA-256 校验，不降低确认标准。扫描器标签、状态码、反射、计时和其他弱信号仍不是直接证明。已有直接证据应交给相应判据复核，无需为扩大影响继续提取数据、写文件、取得权限或进行横向动作。

`project.status` 的 `assessment_policy` 返回 `assessment_mode`、停测策略、预算与 `stopped_operations`。`plan.next`、`assessment.prepare` 和 v2 调度器会将已停测操作或写操作转为离线复核/阻塞样本，不再为填满覆盖度推荐新的主动请求。其他未执行测试仍保留在覆盖分母中，不自动变成阴性、不适用或已完成。

SRC 交付应明确“已证明的具体问题”与“止于发现而未继续验证的范围”。v1 的完整结项门禁保持原有含义；有剩余项时可生成草稿范围报告。v2 可按现有 `partial_accepted` 流程形成有明确接受者与说明的部分交付，该状态不授予耗尽证明。

## 回归

源码目录中运行：

```powershell
python -X utf8 -B -m unittest tests.test_src_integration_20261111
node --test tests/src-mode.test.mjs
```

专项覆盖真实引擎策略、模式持久化、直接 store 配置检查、零发包阻断、证据停测、缓存证据读取、操作变体、证据被修改后的停测保持，以及 SRC 会话绑定旧项目时的实际 Python bridge 拒绝。
