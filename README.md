# Local File MCP Gateway

面向 Windows 的本地文件 MCP 网关，通过公网 HTTPS Streamable HTTP 暴露 MCP，并使用 OAuth 2.1 Authorization Code、PKCE S256 和本机人工审批保护文件访问。

项目可供 Notion、Claude、ChatGPT/OpenAI 及其他兼容远程 MCP 与 OAuth 的客户端使用。实际可用性仍取决于对应客户端的套餐、管理员策略和当前 MCP 支持情况。

## 功能

- 17 个文件、目录、搜索、权限、回收站和本地命令工具。
- 四级授权路径，所有路径默认拒绝，授权根递归生效。
- deny 路径、全局锁、符号链接和递归成员重新校验。
- 高风险操作只能在 Windows 本机确认窗或 `127.0.0.1` 控制台批准。
- OAuth 2.1 动态客户端注册、PKCE、短期 Access Token 和旋转 Refresh Token。
- Cloudflare Quick Tunnel 临时地址，或 Named Tunnel 固定域名。
- 登录计划任务、健康检查、故障恢复和本机审计日志。

## 环境

- Windows 10/11
- Windows PowerShell 5.1
- Python 3.11 或更高版本
- `cloudflared.exe`

当前启动脚本以 `D:\notion` 为安装目录。首次使用时将仓库放在该目录，并准备：

```powershell
py -m venv D:\notion\.venv
New-Item -ItemType Directory -Force D:\notion\bin
```

然后把官方 `cloudflared.exe` 放到：

```text
D:\notion\bin\cloudflared.exe
```

网关自身只使用 Python 标准库，不需要额外安装 Python 包。

## 启动

1. 双击 `START.cmd`。
2. 打开本机控制台：`http://127.0.0.1:8876/`。
3. 在控制台添加允许访问的路径和权限等级。
4. 把启动窗口显示的 `/mcp` HTTPS 地址添加到 MCP 客户端，并选择 OAuth。
5. 首次连接和高风险操作必须在运行网关的 Windows 电脑上批准。

常用入口：

- `START.cmd`：启动 Gateway 和 Tunnel。
- `STOP.cmd`：人工停止并抑制 watchdog 自动恢复。
- `STATUS.cmd`：查看进程、本地/公网健康和当前地址。
- `OPEN-CONTROL-PANEL.cmd`：打开本机控制台。
- `INSTALL-AUTO-RECOVERY.cmd`：安装登录自启及故障恢复。
- `SETUP-STABLE-TUNNEL.cmd`：配置 Cloudflare Named Tunnel 固定域名。

## 固定域名

Quick Tunnel 的 `trycloudflare.com` 地址会在 Tunnel 重建后变化。要固定地址，需要一个由当前 Cloudflare 账号管理的 DNS Zone，然后运行：

```text
SETUP-STABLE-TUNNEL.cmd
```

输入例如 `mcp.example.com` 的 hostname，完成浏览器授权后重新运行 `STOP.cmd` 和 `START.cmd`。固定的是 URL；断网、关机或重启期间服务仍会暂时不可用，恢复后 URL 不变。

## 安全边界

- 控制台只监听 `127.0.0.1:8876`，不会通过 Tunnel 暴露。
- `gateway/config` 包含 OAuth 签名密钥、客户端状态和本机路径策略，已被 Git 忽略，严禁提交。
- Level 2 本地命令在当前 Windows 用户权限下运行，并不是操作系统沙箱。只给可信项目授权，删除应优先使用 `delete_path`。
- 目录、永久删除、受保护路径及明显破坏性命令需要 Level 4 和逐次本机批准。
- 不建议将 `8875` 端口直接映射到公网。

## 校验

```powershell
D:\notion\workspace\validate-powershell.ps1
D:\notion\.venv\Scripts\python.exe D:\notion\workspace\validate-assets.py
D:\notion\.venv\Scripts\python.exe -m py_compile D:\notion\gateway\*.py
node --check D:\notion\gateway\web\app.js
```
