# Local File MCP Gateway

面向 Windows 的本地文件 MCP 网关：把这台电脑上你**明确授权**的目录，通过公网 HTTPS（Streamable HTTP）暴露成一个 MCP Server，并用 OAuth 2.1 Authorization Code + PKCE S256 和本机人工审批来保护访问。

网关本体只使用 Python 标准库，不需要安装任何第三方包，也不需要激活码、许可证或联网校验。

## 一、它解决什么问题

云端 AI 客户端（Notion AI、Claude、ChatGPT 等）默认读不到你本地磁盘上的文件。常见做法是把文件上传上去，但这样文件就离开了你的电脑。

这个项目换一种做法：文件始终留在本机，只把「受控的访问能力」通过隧道暴露出去。

- 路径默认全部拒绝，只有你在本机控制台添加的授权根才可访问，授权根对子目录递归生效。
- 每个授权根单独设置 1~4 级权限，写入、删除、执行命令的门槛逐级提高。
- 高风险操作（删目录、永久删除、明显破坏性命令）必须在本机弹窗或 `127.0.0.1` 控制台上人工点批准，远端客户端和模型都无法自行放行。
- 所有读、写、删、命令、批准、拒绝都写入本机审计日志。

适用对象：任何有一台常开 Windows 电脑、希望让远端 AI 客户端安全读写本地项目文件的人。项目本身不绑定任何特定账号、域名或安装路径。

## 二、功能概览

运行时共 19 个 MCP 工具：

| 分类 | 工具 |
| --- | --- |
| 读取与检索 | `read_file`、`list_dir`、`search_files`、`search_content`、`search`、`fetch` |
| 写入 | `write_file`、`create_dir`、`move_path`、`copy_path` |
| 删除 | `delete_path`（默认进网关回收站，可恢复） |
| 本地命令 | `run_command`、`get_command_status`、`list_command_jobs` |
| 权限与审批 | `list_allowed_paths`、`get_permission`、`pick_path`、`list_pending_approvals`、`confirm_action` |

其他能力：

- 四级授权路径 + deny 黑名单 + 全局锁；符号链接与递归成员会被重新校验，`..` 逃逸会被拦截。
- OAuth 2.1 动态客户端注册（DCR）、PKCE S256、短期 Access Token、旋转 Refresh Token。
- 支持 MCP 协议版本 `2025-11-25`、`2025-06-18`、`2025-03-26`、`2024-11-05`，并兼容各家客户端在 OAuth 自动发现、浏览器预检、DCR 客户端认证方式上的差异。
- Cloudflare Quick Tunnel（临时地址）或 Named Tunnel（自有域名固定地址）。
- 登录自启计划任务、健康检查、故障自动恢复、本机审计日志与回收站。

## 三、环境要求

- Windows 10 或 Windows 11
- Windows PowerShell 5.1（系统自带；脚本按 5.1 语法编写）
- Python 3.10 或更高版本（开发与验证使用 3.13）
- `cloudflared.exe`（Cloudflare 官方下载）
- 如需运行 `node --check` 这一项可选校验，才需要 Node.js

## 四、安装

仓库可以放在任意目录，脚本会用自身所在位置推断安装根目录，不需要改任何路径。下面用 `<REPO>` 代表你的仓库目录，例如 `D:\mcp\local-file-gateway` 或 `C:\Users\你的用户名\local-file-gateway`。

（1）克隆仓库

```powershell
git clone https://github.com/csmsqj/notion-claude-mcp.git <REPO>
cd <REPO>
```

（2）创建虚拟环境

启动脚本固定使用 `<REPO>\.venv\Scripts\python.exe`，所以虚拟环境必须建在仓库根目录下、且名字必须是 `.venv`：

```powershell
py -m venv .\.venv
```

网关只用标准库，不需要 `pip install` 任何依赖。

（3）放入 cloudflared

新建 `bin` 目录，把官方 `cloudflared.exe` 放进去：

```powershell
New-Item -ItemType Directory -Force .\bin
```

最终必须存在：`<REPO>\bin\cloudflared.exe`。

（4）确认三个必需文件

启动时会检查这三项，缺一个就会直接报错退出：

```text
<REPO>\.venv\Scripts\python.exe
<REPO>\runtime-patches\gateway-v21.py
<REPO>\bin\cloudflared.exe
```

## 五、启动与连接

（1）双击 `START.cmd`

它会启动网关（本地 8875）和本地控制台（本地 8876），再启动 Cloudflare Tunnel，最后在窗口里打印公网 `/mcp` 地址。

（2）打开本机控制台：`http://127.0.0.1:8876/`

控制台只监听 `127.0.0.1`，不会通过隧道对外暴露。

（3）在控制台里添加要授权的路径，并为每条路径选择权限等级

刚装好时授权列表是空的，此时任何路径都会返回 `PATH_NOT_ALLOWED`。这是预期行为，不是故障。

（4）把启动窗口显示的 `/mcp` 地址添加到 MCP 客户端，认证方式选 OAuth

（5）首次连接会在这台电脑上弹出一次 OAuth 同意窗，后续高风险操作也会弹窗，都需要你本人在本机点确认

常用入口：

| 入口 | 作用 |
| --- | --- |
| `START.cmd` | 启动网关和隧道 |
| `STOP.cmd` | 人工停止，并写入停止意图以抑制看门狗自动拉起 |
| `STATUS.cmd` | 查看进程、本地/公网健康状态、当前地址、授权路径 |
| `OPEN-CONTROL-PANEL.cmd` | 打开本机控制台 |
| `OPEN-NOTION-CONNECTION.cmd` | 用记事本打开当前连接信息（URL、认证方式、隧道模式） |
| `INSTALL-AUTO-RECOVERY.cmd` | 安装登录自启 + 故障自动恢复计划任务 |
| `UNINSTALL-AUTO-RECOVERY.cmd` | 卸载上面的计划任务 |
| `SETUP-STABLE-TUNNEL.cmd` | 一次性配置 Cloudflare Named Tunnel，获得固定域名 |

## 六、权限等级

在控制台给每个授权根单独选级别，级别向下兼容：

| 级别 | 名称 | 能做什么 |
| --- | --- | --- |
| 1 | 只读 | 读取、列目录、搜索 |
| 2 | 开发 | 第 1 级 + 创建 / 覆盖 / 追加 / 移动 / 复制，以及一般本地 Python、shell、测试、编译命令 |
| 3 | 项目维护 | 第 2 级 + 通过 `delete_path` 删除普通小文件（默认进网关回收站） |
| 4 | 高风险 | 删除目录、永久删除、大文件或受保护目标、明显破坏性命令；每次都要人工确认 |

硬性红线：删除驱动器根目录或当前授权根本身始终禁止，即使给了第 4 级也不放行。

## 七、固定域名（可选）

Quick Tunnel 的 `trycloudflare.com` 地址在隧道重建后会变化。想要地址不变，需要一个已托管在你 Cloudflare 账号下的域名，然后运行：

```text
SETUP-STABLE-TUNNEL.cmd
```

按提示输入形如 `mcp.example.com` 的 hostname，完成浏览器授权，再依次运行 `STOP.cmd` 和 `START.cmd`。

注意它固定的只是 URL：断网、关机、重启期间服务仍然不可用，恢复后 URL 不变，客户端不需要重新添加连接。

## 八、命令执行与超时

`run_command` 走的是「短同步 + 后台任务」模型，用来避免隧道超时导致的重复执行：

- 最多同步等待约 15 秒。
- 超过就转为后台任务，立即返回 `job_id` 和 `status: running`。
- 用 `get_command_status` 查询；`job_id` 丢了用 `list_command_jobs` 找回。不要重跑同一条命令。
- 同一 cwd + 同一命令在 120 秒内会复用已有任务，除非显式传 `force_new: true`。
- 最多两个命令任务并发。输出写入文件后按上限截断回传，单个任务仍受 300 秒运行上限约束。
- 审计记录会对常见凭据（`sk-` / `github_pat_` / `Bearer` / `--token=` / `API_KEY=` 等）做脱敏，并记录 job id、PID、状态、耗时、超时、退出码。

## 九、安全边界

这一节请务必读完再决定授权哪些目录。

- 控制台只监听 `127.0.0.1:8876`，不通过隧道暴露；不要把 `8875` 端口直接映射到公网，OAuth 与审批链路依赖网关自身的地址判断。
- **第 2 级的本地命令不是操作系统沙箱。** 命令在当前 Windows 账号权限下执行。策略会识别常见的删除 / 清理 / 系统破坏写法并要求第 4 级，但任意 Python 或 shell 代码可以伪装其真实效果。只授权你信任的项目，删除请统一走 `delete_path`，这样大小、目录、审批、回收站、审计规则才都能生效。
- 目录删除（含空目录）、永久删除、大文件或受保护路径（系统目录、程序目录、凭据类文件名与扩展名）一律要求第 4 级 + 逐次本机批准。
- 审批只能在本机原生弹窗或本地控制台完成。`confirm_action` 只能登记「拒绝」，不能代替用户批准，避免远端伪造同意。
- 明确被拒绝的操作不允许自动重试。
- 弹窗总时长 120 秒；为了不撞隧道超时，MCP 请求最多同步等待约 85 秒，之后返回「尚未执行」，弹窗仍在电脑上继续。此时客户端应停止轮询并等用户操作。

## 十、验证

下面命令都在仓库根目录执行，`.\.venv\Scripts\python.exe` 就是安装步骤里创建的虚拟环境解释器：

```powershell
cd <REPO>
powershell -NoProfile -ExecutionPolicy Bypass -File .\workspace\validate-powershell.ps1
.\.venv\Scripts\python.exe .\workspace\validate-assets.py
.\.venv\Scripts\python.exe -m compileall -q .\gateway .\runtime-patches
.\.venv\Scripts\python.exe .\workspace\test-v0-oauth-compat.py
.\.venv\Scripts\python.exe .\workspace\test-lobehub-oauth-compat.py
.\.venv\Scripts\python.exe .\workspace\test-manus-oauth-compat.py
.\.venv\Scripts\python.exe .\workspace\test-command-timeout-fix.py
```

可选（需要 Node.js）：

```powershell
node --check .\gateway\web\app.js
```

关于另外两个测试脚本：

- `workspace\test-command-overlay-integration.py` 会真实加载运行时补丁并在仓库目录里跑一条命令，因此**要求仓库所在目录本身已在控制台里被授权到第 2 级或更高**，否则会以 `PATH_NOT_ALLOWED` 失败。这是权限校验生效的正常表现。
- `workspace\test-watchdog-recovery.ps1` 会安装 / 停止计划任务并杀掉网关进程来验证自动恢复，属于破坏性测试，只在你确认可以中断服务时手动运行。

## 十一、常见问题

（1）客户端连不上，`STATUS.cmd` 显示 `Public health: unavailable`

先看 `gateway\logs\tunnel.err.log`。如果是 `failed to dial to edge` 或 `no free edge addresses`，那是 Cloudflare 边缘连接问题，与网关无关，等待重连或重新运行 `STOP.cmd` + `START.cmd`。本地健康仍显示 healthy 就说明网关本身正常。

（2）所有工具都返回 `PATH_NOT_ALLOWED`

授权列表为空或目标不在任何授权根内。到 `http://127.0.0.1:8876/` 添加路径，或让模型调用 `pick_path` 弹出本机文件夹选择器，再由你去控制台添加。

（3）端口被占用启动失败

`START.cmd` 会检查 8875 / 8876 是否已被监听并打印占用进程。先运行 `STOP.cmd`；若仍占用，说明是别的软件占了端口，需要先停掉它。

（4）想彻底停掉，包括自动恢复

先 `UNINSTALL-AUTO-RECOVERY.cmd`，再 `STOP.cmd`。只跑 `STOP.cmd` 时会写入停止意图，看门狗不会把它拉起来，但计划任务仍然装着。

（5）本机产生的数据在哪里

`gateway\config`（策略、OAuth 状态、隧道设置）、`gateway\logs`（审计日志、命令任务输出）、`gateway\trash`（回收站）都在本机，且已被 `.gitignore` 排除，不会进入 Git 提交。
