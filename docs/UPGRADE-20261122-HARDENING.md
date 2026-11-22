# 2026-11-22：2.4.0 证明、执行与仓库完整性加固

## 范围

本次升级针对 2.3.0 候选源码的公开执行链，而不是增加新的扫描器或漏洞结论。默认 V1 保持 10 组、75 个动作；V2 保持 6 组并扩展为 48 个动作，新增 `campaign.review_frontier` 与 6 个证据驱动 fixture 动作。

## 证明与配方

- `test.run mode:verify` 必须提供原始 `run_id`，逐 control 校验 recipe、run、step、dispatch receipt、native capture run 和 evidence/artifact。请求 URL、方法、头、正文、operation、session/actor、resource 和 fixture mutation/fence 不一致时拒绝，缺字段旧 run 保持 `legacy_unverified`，不产生新证明。首次执行也不允许通过 idempotency key 采用属于另一 native/V2 run 的旧 evidence，首次与离线路径共用同一权威关系。
- 通用 reviewed 通道从 run 内 evidence 派生 `observation.actual`、身份和 source trust；普通调用参数不能注入 `human_independent`、独立人类声明或伪造 actual。reviewed detection 与 machine proof 继续分栏。
- 自动写配方使用显式 `single_write_attack_only`：只派发 attack，normal/negative 保留声明但明确未分派、未观察，结果不会伪装成完整三组控制证明。单次真实写完成后记录 fixture mutation、evidence、dispatch 和 fence。
- 查询输入及 recipe 查询变量按 URL component 编码，避免空格使 SQL payload 在 preflight 失败，也避免 `&`、`#`、`=` 注入额外控制参数。
- `reflection_exclusion` 与 oracle 实际求值字段保持一致。

## Fixture 公开生命周期

新增：

```text
test.fixture_create
test.fixture_verify
test.fixture_lease
test.fixture_inspect
test.fixture_readback
test.fixture_cleanup
```

`create/verify/readback/cleanup` 的状态均从真实、完整的只读 evidence 和 JSON Pointer 派生。写 operation 可另配 `readback_operation_id/readback_resource_id`，读回接口与写接口可以不同，但 owner actor 和 external resource identity 必须一致；POST fixture 因此拥有完整公开生命周期。readback 只比较真实业务状态，不与本地 execution ID/摘要比较；readback/cleanup 还要求当前 mutation 或 lease 之后的新证据，写入前的初始证据不能伪报清理成功；证据新鲜度与状态转换在同一 `BEGIN IMMEDIATE` 事务内复核，双连接 mutation 无法穿过检查窗口。每次真实目标写在 dispatch 之后、发送字节之前建立持久 `in_flight` 标记；成功证据落账后才随 mutation 清除，取消、断连和未知效应保留标记，readback/cleanup 不得越过在途或未知写。resource 与 fixture 错配会在构造及 dispatch 前拒绝，实际写 A 不会给 B 记录 mutation。重复 create 幂等，不能重置已有 lease。lease、mutate、readback、cleanup 在 SQLite `BEGIN IMMEDIATE` 事务内按原始 revision CAS，并绑定 operation/owner/resource、TTL 和单调 fence。公开返回只包含状态、计数和租约元数据，不公开私有业务初始值。

## Campaign、Universe 与迁移

- `campaign.finish` 固定使用门控开始时的 revision；acceptance、delivery 和 event 同事务提交，CAS 冲突回滚 acceptance。checkpoint 的 gap 集合按稳定机制键规范化排序，避免内容派生 ID 的创建顺序让刚生成的 checkpoint 间歇失效。
- `campaign.review_frontier` 从当前 Universe、discovery/category/page/work 投影和 campaign run evidence 构造真实 receipt。相同 topic、重复 ID 或相同 evidence 字节不构成新的语义轮次；完成仍要求两个不同的 current round 和包含它们的 checkpoint。
- `recon.snapshot save:true` 支持 `campaign_id`，可推进所有或指定 active campaign。新增 operation/source/consumer 形成新工作，未变 mechanism 保留历史；旧 checkpoint/frontier/final authority 随 Universe/hash 变化失效。
- `complete_snapshot` 只描述来源快照，不自动赋予全站发现权限。
- migration 的 ledger、hypotheses、legacy evaluations 和 config 原子提交。重复 apply 幂等，rollback→reapply 复用或新建 generation；旧 decision 仍为 `legacy_evaluation`，不合成 TestRun。

## 浏览器、外部工具与恢复

- `browser.visit` 默认 `allow_write:false`、`max_writes:0`；写访问必须显式开启并满足 scope、同源、operation/resource 和预算门禁。HTTPS 默认严格校验，只有管理员显式配置才能放宽单次环境。
- sqlmap/Yak 只接受管理员在插件配置中选择的精确路径和可选 SHA-256；工具参数不能选择任意同名文件。子进程清理 `NODE_OPTIONS`、`PYTHONPATH`、代理和其它高风险环境。
- TscanPlus 对 `success:true,data:{}` 或缺少 HTTP 终态的响应保持 unknown，写请求不释放 reconciled lease，也不再把缺少流量证明写成 `target_traffic_sent:false`。
- HTTP 总 deadline 覆盖连接、状态行、响应头和正文；Yak 按字节块限长读取。未知长度浏览器正文不读取、不标记 complete，不宣称支持流式证明。
- `scenario.run` 与 `test.run_scenario` 都接受 `SC-*` 恢复 ID，桥根据持久 dispatch 事实保留 uncertain effect。

## 仓库与发行

- `work/`、`recon-local8081/` 已从 Git 跟踪移除；本地原始证据未随源码发行。新增 `git ls-files` 硬门禁，禁止 runtime projects、sessions、reports、build/dist 和敏感环境文件重新进入仓库。
- GitHub Actions 固定完整 SHA，Node 使用 22.19.0，Python build 固定 1.6.1。
- 新增中英文插件 metadata 和原创 36px SVG 图标，npm/wheel 继续检查实际归档成员。
- 发行记录新增 `record_finalized`、`git_head`、`source_frozen` 和 `release_source_fingerprint`。旧 `commit_status` 只保留兼容含义，不表示 Git commit 或签名。

## 验证与兼容

回归使用合成项目、独立 SQLite、两个真实连接、公开 dispatch/action、mock provider 和本地 loopback。所有最终数量以本轮全量测试、fresh install 和 pack 记录为准。旧 run 缺少完整 control/evidence 绑定时不补造迁移证明，必须重新执行取证。真实 Playwright 桌面 UI、真实 WSL、外部 TscanPlus 服务和下游 dsh-purge 同步仍需各自独立验收。
