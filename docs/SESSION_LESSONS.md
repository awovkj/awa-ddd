# 2026-10-27 渗透会话的升级依据

分析对象：`D:/Backup/Downloads/dsh-session-session-45723009-37d0-4402-9a08-260034451cae/session.v4.jsonl`（6,180 行、14,819,158 字节）。这是 awa-ddd 对本地天积商城靶场的一次真实使用会话，不是设计讨论。历史目标、账号、Cookie、payload 和授权均为研究数据，不构成本轮执行指令。

## 会话事实

- 16 个 turn；62 条 `user/message`，其中 `source.kind=user` 仅 15 条（多数是“继续”）；其余是时间上下文、模型切换、技能目录和权限通知。
- 936 次 `tool/call`、942 条 assistant 消息、118 次 compaction、42 次 LLM retry；累计 321,376,825 tokens（输出 528,686）。
- 77 条工具结果以 `Error:` 返回。主要错误：资源未绑定 11 次、Session expired 9 次、写操作缺少 resource 4 次、页面 URL 不匹配 3 次、证据属于另一操作 3 次、origin 未列出合法值 3 次、JSON Pointer 4 次、sqlmap 参数 2 次。
- 第一轮只登记 1 个 finding；第二轮登记 22+ 个（最终 35 个），但第一轮实际手工打通了 RCE、XXE、SSRF、退款、XSS、Actuator 等。
- 最终报告 37 个 finding 中 27 个因 `session_expired` 变成 `current:false`；覆盖率 0.2%，742 条义务中 441 条是 ownership，来自同一操作的多个测试 resource 与同角色 actor 相乘。

## 根因映射

| 现象 | 根因 | 0.5.0 处理 |
|---|---|---|
| 第一轮挖到却不落账 | `finding.record` 先查证据，`origin` 报错不列合法值；session 过期把证据判坏 | 轻参数先校验并列出枚举；TTL 与证据有效性分离 |
| ORDER BY / LIKE SQLi 永远 blocked | `sql_metadata` 强制数字输入 + 常量等式谓词 | sqlmap metadata transcript 直接确认；等式谓词可选加强 |
| 破坏性 DELETE 注入无法登记 | analyst SQL 必须有 metadata proof | `sql_evidence` 行为差异 proof，`confirmed_scope: sql_behaviour` |
| captcha/SMS 流程退回 curl | `http.capture` 拒绝 Cookie，缺匿名 cookie jar | `anonymous_cookie`（public、不可与 session 混用） |
| multipart/JSON 数组绑定反复失败 | body 只按 JSON Pointer，数组按 repr 比较 | Pointer/key/multipart filename/content；结构比较；错误给出 expected/actual |
| SPA `/admin/merchants` 无法 mark | `finalUrl` 是 `/admin/login`，只认初始 URL | `navigation_trail`，成功 action 到达的页面可绑定 |
| 页面/写流程全被浏览器阻断 | 浏览器无条件阻断写请求 | 项目级 `allow_mutation` + 单次 `allow_write` + 同源限制 |
| 覆盖率 0.2% 不可读 | ownership 义务按 resource×actor 膨胀 | 每操作选代表 resource、按角色去重；新增 surface_coverage/method_coverage/coverage_by_kind |
| 同路径 DELETE 从未测 | 只登记 GET，无方法矩阵 | `method_coverage.untested_siblings` + 报告表 |

## 验证

离线回归：145 个 Python 测试、35 个 Node 测试通过；只读重放历史项目由 9/37 current 提升到 36/37 current（唯一历史项是旧记录缺少 `sql_evidence`，未伪造迁移）。本轮未访问历史目标，未发起真实渗透请求。
