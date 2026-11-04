# 会话审计：2026-11-04 / 2BE1DAC3

本说明只读检查用户提供的 `session.v4.jsonl`：6,107,059 字节、2,780 行，JSON 均可解析。第 1 行是会话头；其余事件的 `seq` 为 0–2778。下表行号从 1 开始。不收录目标地址、凭据、原始请求正文或日志中的操作指令，审计没有发送目标请求。

## 提前结束的实际时序

| 行 / seq | 事件 | 已记录的事实 |
|---|---|---|
| 26 / 24 | 用户请求 | 从零开始渗透测试，没有请求停止或接受部分交付。 |
| 2654 / 2652 | `report.build` 结果 | 报告为 `stage:draft`、`delivery_status:draft`，`continue_required:true`、`can_finalize:false`。 |
| 2670 / 2668 | 第一次收尾文本 | AI 以 partial 总结，同时承认登记义务、输入复核与浏览器归档尚未闭环。 |
| 2676 / 2674 | 宿主 continuation notice | 守卫确实注入一次；新审计仍有 319 项 actionable，禁止自动停止。 |
| 2679 / 2677 | `plan.next` 结果 | `continuation` 仍是 319 项 actionable，并展示可离线处理的 SQL 和浏览器复核项。 |
| 2704 / 2702 | `candidate.link` 错误 | 缺少精确来源、输入、族及当前已接受的证明；错误不授权停止其余工作。 |
| 2707 / 2705 | 第二次收尾文本 | AI 将其余 review 概括为需要新的合法前提、身份或资源。 |
| 2710 / 2708 | `turn/end` | `reason.kind:completed`，当前对话轮正常结束。 |
| 2715 / 2713 | 第二轮用户请求 | 用户核实 27 项是否有真实漏洞现象。 |
| 2778 / 2776 | 第二轮 `turn/end` | 读取、整理和展示已有证明后正常结束；该轮没有评估工具调用。 |

守卫后的实际工具调用只有五次：`plan.next`（2678 / 2676）、两次 `pwsh`（2684 / 2682、2691 / 2689）、`candidate.inspect`（2698 / 2696）、`candidate.link`（2703 / 2701）。两次 shell 命令包含 HTTP 发包；此后没有 `assessment.evaluate`、`evidence.inspect` 或 `page.adopt` 调用。

## 收尾时仍未完成的工作

守卫 notice 与最后一次 `plan.next` 的 **continuation** 均为：ready 58、review 261、blocked 281、actionable 319、unresolved 600；`continue_required:true`、`automatic_stop_allowed:false`、`can_finalize:false`、`frontier_rounds:0`。`plan.next` 顶层分页队列是另一投影，不能拿它的筛选计数替代 continuation 总数。

最后结果还保留 496 项未闭环义务（安全专项 353 项）、60 个未归档 HTTP 观察、21 个未绑定人工发现、11 个孤立浏览器观察、2 个待协调运行。参数覆盖有 106 个参数、107 个测试单元，typed tested 5、untested 102、consumer review 92。这些维度存在重叠，不能相加为漏洞数量。

2679 / 2677 展示了无需新增目标请求即可开始的具体工作：

- SQL `input_test` 为 review，已有 3 个证据引用，`missing_prerequisites:[]`；建议先 `evidence.inspect`，随后按证明要求 `assessment.evaluate`。
- 一个 `orphan_browser_visit` 的 `missing_prerequisites:[]`，下一动作是 `page.adopt`，浏览器阶段为 `review_existing`、`call_needed:false`。

因此不能将所有 review 视为真实受阻。离线复核是否最终支持漏洞、阴性结论或明确阻塞，仍须检查实际材料；未测单元也不代表必然存在漏洞。

## 宿主和覆盖边界

修复前的 `src/host-continuation.mjs` 对已通知且 `workKey` 不变的状态，只保存一次 stalled checkpoint，然后抑制同状态通知。宿主仍有 actionable 工作时，这条分支可以让下一次正常收尾结束。日志没有导出第二次边界的诊断指标，因此不能直接断言某个内部诊断已触发；一次有效通知后仍正常结束的事件与该分支一致。

本机 SDK 为 `@deepseek-ai/dsh-agent` 0.2.1-rc.3。`lib/types/runtime-types.d.ts` 的 `agent/turn-stopping` 契约是 serial、awaited，返回 `void` / `Promise<void>`；插件必须通过 `agent.steer` 留下新的 inbox 消息来延续，不能依赖回调返回 `false` 否决结束。真实取消和新用户输入必须优先处理。`turn/end:completed` 只描述对话轮结束，不等于严格 `plan.finalize` 或评估耗尽；本会话没有 `plan.finalize` 调用。

全会话有 537 次工具调用，其中 `http.capture` 113 次、`finding.record` 31 次、`assessment.evaluate` 6 次、`browser.visit` 16 次；计划工具只有一次 audit、两次 checkpoint、一次 next。HTTP 捕获涉及 44 个不同操作；浏览器涉及 5 个页面，其中两个页面分别访问 7 次和 5 次。存在重复浏览器操作，但不能把整个会话归因于同页循环，也不能把访问成功当作安全测试或证据归档完成。

日志记录的 context window 是 1,000,000，单次输出上限是 128,000；模型流结束原因是 441 次 `toolUse` 和 3 次 `stop`，未出现 `length`。没有记录用户中止或上下文溢出，不能据此将第一次提前结束解释为已获停止授权；未导出的运行时约束仍不能从本文件排除。
