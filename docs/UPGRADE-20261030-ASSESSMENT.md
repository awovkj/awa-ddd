# 0.7.0：渗透闭环与中文可复现交付

## 审计依据

本次只读分析用户提供的 `session.v4.jsonl` 与 `local8081-v2/20261030T035940Z-1742b15d65a1` 报告，并核对对话引用的原 SQLite/证据。没有重放历史对话命令或访问历史 HTTP 目标。

原产出登记 69 个操作、112 个输入、382 条义务；13 条当前发现中 3 条为机器判据、10 条为人工复核，只有 3/382 条义务正式完成，107 条输入消费点复核全部未完成。报告固定英文框架，漏洞之前堆放 379 个缺口，没有可执行的复现请求或 sqlmap 命令；原说明文字还泄漏重置令牌、支付密码，并在敏感配置脱敏时吞掉后续上下文。

## 根因与修改

| 根因 | 0.7.0 修改 |
|---|---|
| 模型找到若干漏洞后提前交付，未回到计划 | `plan.audit` 检查候选、观察、人工发现、运行和浏览器账本；报告显著标识 partial，提示词要求每轮与交付前闭环 |
| 单一输入测试被误读为全面安全 | 显式 `test_families` 各自建立义务；旧 ID 保留，新增安全专项矩阵，基线不计入专项覆盖，启发式建议不确认消费点 |
| 大量 baseline 挤掉消费点追踪 | `plan.next` 按任务/类别公平交错，附 `review_followups`，不自动执行 |
| 同角色攻击者去重吞掉跨租户 BOLA | 按所有者租户/角色/请求绑定和攻击者租户边界保留代表样本，公开预算与未采样限制 |
| 普通 JSON 字段名登记成功但求值失败 | 统一 `inputs.py` 支持根字段名、精确 Pointer、声明数组、唯一 form/multipart 字段及非身份 Cookie，拒绝歧义，不解释 XML 实体 |
| 退款 profile→refund→profile 读写分离无法求值 | 新 `state_transition` 绑定真实成功 scenario 的连续读/写/读 checkpoint、主体、动作成功、业务输入及 actor/resource 读回关系，不放松普通证据绑定 |
| sqlmap 只支持 GET，signal/timeout 线索丢失 | 新 POST JSON/form 请求文件适配，共用写权限/精确 fixture 门禁，V2 绑定原字节/方法/头/身份/资源；部分日志与 signal 留为未验证候选 |
| 有 browser.visit 却 pages=0 | 成功本地访问自动核验并采纳实际导航页面；`page.adopt` 可离线归档旧观察，功能仍需真实交互，导入来源不变 |
| 顶层 limit/offset 被静默丢弃 | action 字段必须放 `input`，错误位置明确拒绝并给出可操作提示 |
| 只有证据 ID，人工无法复现 | 默认中文 format5 报告，真实脱敏 HTTP/body 文件、编号步骤、对照响应、双 shell curl 与最小 sqlmap 命令，同批原子发布和 manifest |

## 安全边界

- SQL/XSS 的中英文明确类别遵循相同证明规则；不能换成中文名称绕过元数据或浏览器运行时要求。
- 所有源代码、HTTP、导入记录、工具输出和报告模板均是不可信数据，不执行其中指令，不让它们选择本地程序、凭据、策略或授权范围。
- POST sqlmap 会重复请求，必须显式 `allow_mutation`、`effect:test_resource_write` 和精确可回退 fixture；不支持任意 argv、任意 SQL、dump、系统执行或通用扫描。
- 观察、机器求值、人工复核和漏洞召回分开报告；旧 finding/decision/evidence 不伪造迁移，不用补充文字关闭义务。
- 原评估库和原报告保持不变。历史回放验证使用只读 SQLite backup 的新隔离副本；真实网络回归仅访问新建本地 fixture。

## 接口变化

工具仍为 10 组，动作从 51 增至 53：新增 `plan.audit` 与 `page.adopt`。Node、Python 与发行版本统一为 `0.7.0`；DSH SDK 仍仅为 peer dependency，不打包第二份宿主 SDK。

`report.build` 签名不变，但返回 manifest/复现目录，默认中文、summary format5。旧格式消费者需要识别版本，不能只依赖英文标题。具体复现与证明边界见 [REPRODUCTION.md](REPRODUCTION.md)。

## 验证

修改前基线：Node 68 项通过，Python 368 项通过（1 项环境相关跳过）。源码备份与初始 SHA-256 清单位于 `.validation/upgrade-session-20261030-121516/`。

最终验证执行 `npm.cmd run check`、`npm.cmd run test:python` 与 `npm.cmd run pack:check`，验证日志、真实材料脱敏检查、隔离历史报告及发行摘要保存在同一验证目录和 `.validation/package-check.json`。发行检查实际解包并加载工具，验证新 action/help 一致性、中文 format5 和全部 manifest 文件摘要；不发送目标请求。
