# Windows 编码与 Kali WSL

## 为什么不继续堆 PowerShell 转义

两次会话大量退回 PowerShell/curl；JSON、XML、multipart、中文和引号经过多层 shell 后可能改变字节或显示乱码。插件原有 Python bridge 使用 UTF-8，但绕行命令没有统一编码边界。0.6.0 不新增任意 shell 执行工具，而是把请求送回可验证的 JSON/原字节通道。

- Node bridge：严格 JSON 类型和 UTF-8，固定 argv、`shell:false`；请求和响应均拒绝非有限数、孤立 surrogate，保留真实中文/emoji；拒绝 undefined/function、class/toJSON/accessor 等隐式变形。
- `scripts/invoke-request.mjs`：打开 fd 后确认普通文件，定长最多读取 1 MiB+1 并严格 UTF-8 解码；不把 JSON 拼进命令行，不无界读取设备/FIFO 或 stat 后增长的文件。
- `scripts/Invoke-AwaDdd.ps1`：仅传路径和配置，本次设置并恢复 Console/Pipe UTF-8，不改 profile；`-OutputFile` 直接写 UTF-8 无 BOM 结果。
- Python CLI：即使不传 `-X utf8`，协议 stdout/stderr 仍明确 UTF-8；在打开项目前校验 JSON scalar、有限数、循环/深度/数量。
- `body_file`：明确选择的普通本地文件原字节、有界读取，最多 1 MiB；与 body/body_base64 互斥。HTTP 响应变量不能选择该文件路径。
- UTF-16/GB18030 自动识别仅用于本地控制台目录诊断，不能悄悄把正文或协议按另一编码猜测后发送。

请求文件形状（与 dsh 的 action/project_id/input 外层不同）：

```json
{"action":"action.help","args":{"name":"http.capture"}}
```

```powershell
.\scripts\Invoke-AwaDdd.ps1 -RequestFile D:\Assessments\help.json -OutputFile D:\Assessments\help-result-new.json -Workspace D:\Assessments\awa-native
node .\scripts\invoke-request.mjs --request-file D:\Assessments\help.json --output-file D:\Assessments\kali-result-new.json --workspace D:\Assessments\awa-kali --backend wsl --distribution kali-linux
```

PowerShell 5.1 的默认 `Out-File` 和 `>` 编码不适合协议文件，即使 `$OutputEncoding` 已设 UTF-8，重定向仍可能写 UTF-16。使用 `-OutputFile` / `--output-file` 保存结果：必须是尚不存在的新文件，派发前独占创建，绝不覆盖输入、已有文件或符号链接；成功和错误都写一个 UTF-8 无 BOM JSON envelope 加 LF，stdout 保持同一结果。失败返回非零（2）；磁盘写入失败时文件可能不完整，先检查项目状态，不能因此自动重试写请求。

需要从 PowerShell 写请求文件时显式使用 UTF-8；请求文件允许 UTF-8 BOM，原始 body_file 的 BOM 则是实际发送的字节，不会自动删除。可用 `-PythonExecutable` / `-WslPythonExecutable` 选择本地已安装解释器，无 shell 参数拼接。

## 可选执行后端

native 为默认，WSL 必须在宿主配置中显式选择，模型不能从工具参数改后端或 workspace：

```yaml
workspace: D:/Assessments/awa-kali
executionBackend: wsl
wslDistribution: kali-linux
wslPythonExecutable: python3
timeoutMs: 120000
```

bridge 直接启动固定 `wsl.exe --distribution <name> --cd <package> --exec <python> ...`，没有 `bash -c`/PowerShell/cmd 字符串。发行版名称和解释器参数分别校验。仅文件字段通过固定 `wslpath -a -u` argv 转换；URL、scope、payload 和正文内部 path 永不转换。

`runtime.probe` 无需项目，只读取 native/WSL 版本、编码、发行版和工具路径。路径存在是 catalog，实际适配仍仅有 HTTP/场景、浏览器/MCP、Yakit 单包与 sqlmap 元数据工作流。没有通用 nmap/nuclei/任意命令执行器。

本机验证：Kali WSL2、Python 3.14.7，`/usr/share/sqlmap/sqlmap.py --version` 返回 1.10.8#stable。nmap、curl、nikto、nuclei、ffuf、gobuster 路径可见，Node/Yak 未发现。缺 Node 时不能声称 WSL JS AST 或本地 Playwright 可用；可选择有依赖的 native 后端或实际 MCP 观察。不会自动安装工具、修改 WSL 网络配置或打开窗口。

## 取消与不确定状态

WSL guardian 先监听无缓冲控制通道，建立本地截止时间，再创建本次 Linux 进程组。路径转换、engine、外部工具及其普通子进程全部属于该组。第一行是 JSON 请求；后续只能取消，不能执行 shell 命令。

- CANCEL、控制 EOF 或本地 deadline：终止本次 owned group，TERM 后有界 KILL；不终止发行版或其他进程。
- 请求写入也受监督：无缓冲 writer 与控制 loop 分离，pipe backpressure 不能挂住取消。
- Node 返回 ABORTED/ENGINE_TIMEOUT 不把晚到成功当成功；回归另外检查 Linux engine/tool/grandchild 的已知 PID、start_time、pgid，而非仅检查 wsl.exe 关闭。
- 杀进程不能回滚已经发送的业务写。中断 run 可能仍为 running/uncertain；先 `project.status`、`run.inspect`，必要时 `run.recover` 标为 interrupted，绝不自动重放。

历史实机验收曾保持 stdin open 测试本地 deadline，并修复 daemon BufferedReader shutdown 的 `_enter_buffered_busy` 崩溃；随后另验证 Unicode、真实 sqlmap 版本、宿主取消/截止和 guardian 本地截止，检查真正 guardian、worker、engine、tool、grandchild 的 PID/start_time/pgid。旧本地日志/备份已清理，不随仓库交付，也不是当前检出的验收结果。当前回归按 [README](../README.md) 重跑；需要实际 WSL/可信本地工具的检查仍依赖当前环境，不能从历史说明或缺失日志推断通过。

## 网络与存储边界

Windows localhost 与 WSL localhost 不保证是同一网络端点。插件不会自动改成网关地址：新地址必须确实在授权范围，并重新满足 operation/identity origin 绑定。版本/路径探测没有联系历史靶场，不是一次渗透验证。

native 与 WSL 使用独立 assessment workspace，避免跨 OS 并发打开同一 SQLite/WAL。旧项目、Cookie、generation、范围和结论不会自动复制到新环境。原始 artifacts 留在各自项目；`tool.artifact` 提供 digest-checked、脱敏后的 Unicode 字符分页。

多 origin scope 也不扩大凭据使用范围：原生 HTTP、浏览器和外部工具都只把已核验 session 发往其 identity endpoint 同 origin。另一 origin 需要独立会话核验。空 inputs 不允许把 query/正文中的资源伪装成 `state_scope:actor`；实际业务写仍需唯一匹配的测试 fixture。

本机制不是 OS 级沙箱：可信本地工具、WSL 和宿主安装仍是信任前提。应用响应、导入报告、工具描述和 transcript 只作为不可信数据，不能获得执行策略、凭据或本地文件选择权限。
