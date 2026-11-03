# 0.11.0：信息先行与实际负优化修复

## 范围与结论

本轮依据用户指定的 `session-adaae1ef-48cf-48d1-93b0-0e05d50e6eb9`、当前完整源码、未提交升级和本地回归进行优化。没有重放会话请求，没有访问历史目标、读取存量评估库来重新测试，也没有修改桌面 dsh 配置。原有未提交工作保留，0.10.0 已有 multipart、短字段脱敏、参数覆盖和前端 AST 等修复不混作本次新增。

证据不支持“Python 模块多所以 HTTP 慢”的推断：会话 HTTP 中位数约 0.227 秒，主要可证实损失是宿主自激续接、常驻契约重复、错误对照/身份绑定及离线队列重复读取。详细事件、统计口径和版本边界见 [脱敏会话取证](SESSION-20261102-ADAAE1EF.md)。

## 先收集信息，再选择渗透假设

流程现在明确为：

1. 确定当前授权范围、入口、真实账号和可回退资源前提。
2. 一次统筹正常页面、静态资源、API/功能流程和 OpenAPI/JS/HAR 等可获得材料，优先批量登记，不边猜边反复发包。
3. 统一建立站点画像：origin、技术/框架线索、API/参数/访问策略、实际页面/功能交互、待确认表单/链接/脚本与收集缺口。
4. 复用未变化的信息，仅补新事实；再按实际功能、消费点和身份/资源边界用 `plan.next` 选择具体假设、对照和判据。

新增同 `awa_surface` 组的 `surface.recon`，保持 10 个工具组，总计 61 个动作：

```json
{"action":"surface.recon","project_id":"assessment","input":{"mode":"prepare","section":"collection","limit":10}}
```

`prepare` 仅读当前清单、给离线收集入口；不读取 HTTP/浏览器工件、不发请求。使用已有工具集中采集获准的正常材料后：

```json
{"action":"surface.recon","project_id":"assessment","input":{"mode":"aggregate","section":"overview","limit":10}}
```

`aggregate` 对当前已保存材料做被动聚合，每次重检 scope、artifact 和身份/资源 lineage。五个 section 分别为 `overview/technologies/functions/clues/collection`，使用各自 `offset/limit/next_offset`；默认 10，最多 50。

- 技术与框架：明确 HTTP、Cookie **名称**、HTML/JS 静态标记和库文件名；全部是带 source ID 的 `hint`，不等于安装版本或漏洞确认。
- 功能与输入：登记的 API/policy/input 和已重新核验的 UI 交互分别展示；HTML 源存在但没有页面账本时，保留实际 Playwright 收集需求，不推断为 API-only。
- 发现线索：表单重复字段、submit override 和未知方法保留歧义；路径模板匹配只是可能关联，新增未映射输入仍须复核。每条原始 locator 先按固定 scope 检查，再去除公共 query，不复制 query 或给可执行的脱敏 URL。
- 信息复用：`baseline_reused/baseline_changed/delta` 区分未变化与实际增量。完整 input/consumer/branch/family/policy 参与语义变化，即使不在展示预览里也能更新。

`recon_baseline` 使用随机 RC handle，私有小事实哈希不公开。它只记录准备性信息，不改变安全完成 snapshot/progress、不创建 finding/decision/CP/FN，不自动登记或执行线索；不能拿来 finalization。RC 复用不跳过下一次证据核验。

“一次做好”不是一键无边界全扫或保证发现全部未知攻击面。单次聚合最多检查 1,000 条已存 HTTP 材料、每条被动解析 256 KiB、保留 2,000 个不同线索；解析器另有 headers/DOM/forms/fields 限制。缺失、截断、歧义与未访问项明确保留，DNS/TLS 等未获得部署信息不编造。浏览器和后台证明仍须实际正常控制、身份/fixture preflight 与 typed 判据。

## 修复宿主续接活锁

会话只有一个真实用户评估请求，却产生 729 条插件继续通知。最后相同快照出现 536 次，最后一次工具之后仍有 427 条通知和 427 条答复，57.81 分钟没有新工具/证据，最终触发 429。

旧代码只给 blocked/recovery 去重，却对成功的 work/frontier audit 每次 `agent.steer`。`no_progress_rounds` 来自持久 CP，宿主空转没有新 CP，因此一直为零，不能替宿主识别空转。

新控制器按真实 `progress_id`、frontier 和完成状态去重：raw captures、CP ID 和 no-progress 计数不能重启提醒；同状态一次交接、一次未完成 stall CP，之后允许正常轮次结束但保留未完成绑定。A/B 状态循环、恢复成功/失败摆动、并发 callback 和遗漏项目分页有回归。CP 等待期间的并行真实 PR/frontier 或严格 finalized 会重新核验后处理，实际取消/新意图始终优先。

离线合成回放将 536 个相同边界从 536 次提醒变为 **1 次提醒 + 1 个未完成 CP**。这不是“认定任务完成”：所有 `continue_required`、剩余义务、strict completed/final report 门禁不变，宿主不发目标请求，也不自动重放未知写入。

无 `progress_id` 的旧兼容引擎仅回退 snapshot 去重，不保证过滤所有 raw churn。去重集合限当前绑定意图/生命周期，不宣称持久化、无限规模或桌面平台无限运行。

## 精简常驻上下文与恢复

同一 SDK 的实际 UTF-8 字节量：

| 项目 | 修改前 | 0.11.0 |
|---|---:|---:|
| 工具 schema/说明 | 44,669 | 19,365 |
| 独立停止提示 | 4,658 | 1,875 |
| 开启模式提示 | 10,264 | 3,737 |
| 合计 | 59,591 | 24,977 |

常驻部分减少约 **58.1%**，即便新增信息聚合动作仍小于 25,000-byte 回归上限。skill 入口限制为 10 KiB，复杂细则路由现有文档和单动作帮助，不新增 SDK/扫描器/模型依赖。这是上下文字节量，不是精确 token 或价格。

帮助入口前置为 `awa_project action.help input:{name:"..."}`，保持单一 catalog，不以更多工具别名解决发现问题。页内字段、字符串和数组截断同样触发当前页恢复；重试 limit 严格变小。单项仍超限标 `retry_same_page:false/projection_limit:single_record`，提供离线 detail 指引，不再无限同页重读或跳过缺失字段。

## 身份续期与安全闭环

- 过期但同代、凭据/主体/角色/证据及 origin 仍有效的会话给精确 `session_id/renew:true` 候选；代理在已授权续接意图下可以显式续期，候选不自行执行、不发包。队列仍 blocked，过期直接 capture 仍拒绝。
- 缺 restricted-role 证明、异 origin、scope/exclude、换凭据或主体/代际、材料损坏都不能借续期解锁；不自动合并/删除存量 actor/resource，也不改义务 ID。
- subject/tenant/roles Pointer 混同在 capture 前拒绝，自动猜测的 alias 和历史断言重新核验；不同字段是否真正属于同一主体仍需可信 self-profile 业务语义，不能声称泛 JSON 已完全证明角色关系。
- 续期公共模板同步接入受限 typed schema：真实 session/actor handles、固定 `renew:true`、固定 false 门禁与 generation/count。短凭据 `true/false/root/0/1` 不再把可复制模板变成字符串，但任意业务文字仍脱敏，不泛恢复。

全量回归还实证一个原有时钟偶发问题：PIN `123` 恰好出现在生成时间的微秒部分时，外层 publication 把内层已保留的 run 时间再次脱敏。现在仅真实台账绑定的 run/session 时间和 PV 的生成 `created_at` 可作为控制字段保留；须合法 aware ISO、实际 bound handle、同 kind/field/value、相关上下文类型和值完全一致。不同实体/冲突 alias、布尔或浮点代际、不合法/无时区时间、未知或业务 ISO 文本仍脱敏。browser run 的 schema 合并明确保留 run 时间规则；未对无独立台账绑定的报告时间做“格式即恢复”。新增 18 个确定性回归，不靠重跑时钟碰撞掩盖失败。

## 降低离线调度成本

`queue_inventory` 在当前调用只读一次资源、按 operation 分桶，并复用本次 config；方法矩阵复用当前 inventory 已核验观察，不在同次调用再完整核验一遍。没有跨调用 mtime 缓存，下一次仍重读/重新核验，旧坏证据不能因缓存保留为当前。

完全离线、mock HTTP 的相同规模夹具测得：

| 场景 | 修改前 | 修改后 |
|---|---:|---:|
| 200 条证据：plan.next | 341.0 ms | 255.4 ms |
| 同场景 plan.audit | 343.2 ms | 258.2 ms |
| 同场景 checkpoint | 660.6 ms | 524.4 ms |
| next/audit artifact reader 调用 | 400 | 200 |
| checkpoint artifact reader 调用 | 800 | 400 |
| 1,250 义务：资源完整列表读取 | 1,251 | 2 |
| 同场景 plan.next | 543.4 ms | 206.6 ms |

200 证据场景公共输出字节保持不变；1,250 义务场景没有删减义务或 blocked 数。数据见本地 `.validation/audit-20261102-adaae1ef/engine-costs.json`。artifact reader 计数不包含所有独立 digest 文件读取；这些数字证明离线调度成本降低，不承诺所有目标请求加速、完整漏洞召回或实站吞吐改善。

## 验证与部署边界

验收命令：`npm run check`、`npm run test:python`、`npm run pack:check`。初始基线为 164 个 Node 测试、1,224 个 Python 测试；新增宿主重复状态/取消/并发、新信息画像/解析/作用域/增量/不证明性、renewal/selector/I/O 与短凭据投影回归。实际本轮结果和日志保存在忽略的 `.validation/audit-20261102-adaae1ef/`，打包检查记录在 `.validation/package-check.json`。

提取安装包 smoke 使用真实 SDK/Cordis/Python bridge 和临时 SQLite，验证 61 catalog、被动 parser、prepare/aggregate RC 复用、重复宿主交接不再通知、strict final 拒绝及原有导入/判据/报告 manifest；不发目标流量。发布包不含会话、测试数据、评估库、秘密、node_modules 或验证日志，归档与源码 byte/hash 绑定。

本轮没有实跑用户桌面 closing driver、替用户安装/启用插件，或在同靶场状态/模型/授权条件下做真实 A/B 召回验收。请用最新验证归档更新实际宿主后，在另行获准的目标上验收“统一信息收集 → 定向测试”的真实流程；不要把本地测试成功说成历史目标已复测、已测完或漏洞召回已提高。
