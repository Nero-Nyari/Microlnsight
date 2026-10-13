# Microlnsight 应用目录

这里包含本机 CLI 和网页工作台。以下命令均在本目录执行。

## 本机 CLI

需要 Python 3.10+。Windows：

```powershell
.\install-windows.bat
.\start-windows.bat
```

Linux：

```sh
sh install-linux.sh
sh start-linux.sh
```

已安装依赖的开发环境也可执行 `python agent.py`（Linux 可用 `python3 agent.py`）。部署、模型配置、数据目录和更新说明见 [NATIVE_CLI.md](NATIVE_CLI.md)。

## Windows 网页工作台

需要 Python 3.10+、Node.js 18+。首次安装：

```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
npm --prefix frontend ci
```

检查并启动：

```powershell
python dev.py check
python dev.py start
```

打开 `http://127.0.0.1:5173`。在启动终端按 Q 或 Ctrl+C 停止本次启动的服务。数据库命令行工作台使用 `python dev.py cli`。

## 代码入口

| 路径 | 职责 |
| --- | --- |
| `agent.py`、`guard*.py`、`server_logs.py` | 本机 CLI、规则、模型与日志解析 |
| `terminal_ui.py` | 终端展示与交互辅助 |
| `cli.py` | 基于后端数据库的命令行工作台 |
| `cli_update.py`、`launch_cli.py`、`install_cli.py` | 更新、启动与安装 |
| `build_cli_releases.py` | 按白名单构建 Windows / Linux 发行包 |
| `backend/app/`、`backend/tests/` | API、服务、Python 测试及合成样本 |
| `frontend/src/`、`frontend/tests/` | React 工作台与前端测试 |
| `dev.py`、`start.bat` | 完整开发环境的统一入口 |

详细操作、服务器日志分析与常见问题已集中到 [完整开发与工作台指南](../docs/guides/workbench.md)。更多资料见 [文档索引](../docs/README.md)；测试与文件放置规则见 [开发约定](../CONTRIBUTING.md)。
