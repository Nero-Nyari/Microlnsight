# WinSecAgent 本机 CLI 版

## 部署方式

Windows 版装在 Windows 主机，Linux 版装在 Linux 主机。每个实例独立采集和分析本机日志，任务与对话默认保存在安装目录的 `data/agent.guard/`。主机之间无需连接，也不会自动汇总日志。Xshell 可用于登录 Linux 并运行安装命令；关闭终端会结束前台程序。

这两个包是 **Python 源码发行包**，需要 Python 3.10+，没有捆绑 Python 或模型权重。安装脚本创建 `.venv-cli`，只安装本平台 CLI 依赖，不安装网页、向量库和模型运行时。首次安装需要从配置的 Python 包源下载依赖。

## Windows

解压 `winsecagent-windows-cli.zip`，在解压目录执行：

```powershell
.\install-windows.bat
.\start-windows.bat
# 合成演示，无需日志读取权限
.\start-windows.bat demo
# 读取本机 Security 日志
.\start-windows.bat scan
```

安装只需执行一次。Security 读取失败时请使用有事件日志读取权限的终端，例如管理员 PowerShell；程序不会自行提权。

## Linux

把 `winsecagent-linux-cli.tar.gz` 上传到需要保护的 Linux 主机。Ubuntu/Debian 如果没有 Python/venv，先由管理员安装 `python3`、`python3-venv`；其他发行版用对应包管理器。

```sh
tar -xzf winsecagent-linux-cli.tar.gz
cd winsecagent-linux-cli
sh install-linux.sh
sh start-linux.sh
# 合成演示
sh start-linux.sh demo
# 读取当前服务器的 SSH journal
sh start-linux.sh scan --minutes 15 --limit 1000
# 前台持续轮询；Ctrl+C 停止
sh start-linux.sh watch --minutes 15 --interval 60
```

采集依赖本机 `journalctl` 和 SSH 服务 journal。使用有 journal 读取权限的账号；root 可在服务器终端运行。程序不自动 sudo，不调整 SSH 或防火墙配置。不使用 systemd/journal 的系统暂不支持此实时入口；菜单可分析兼容的 `ssh.journal.log` 导出目录。watch 尚未安装为 systemd 服务，读取失败会保存失败任务并退出。

## 统一操作

菜单：1 本机日志分析与模拟防护；2 任务、证据与模型追问；3 模型配置；4 本平台合成演示。采集器随当前系统选择，Windows 读取 Security，Linux 读取本机 SSH journal。

从 0.2.2 开始，配置与采集向导支持 **回车采用默认值、0 或 Ctrl+C 取消当前操作**。填错地址、目录或保护名单时，只重填当前一项。任务历史按列表序号选择；打开任务后可连续查看证据、追问和导出，无需复制任务 ID。Linux 交互终端启用行编辑，兼容 Xshell 常见的两种退格键编码。

模型配置流程：选择 **本地 Ollama / DeepSeek API / 其他 OpenAI 兼容服务** → 服务地址 → 密钥方式 → 获取模型列表并按序号选择（也可手动填写）→ 显示名称 → 确认保存。DeepSeek 地址默认 `https://api.deepseek.com`。显示名称只是本机标签，不能填写网址。获取列表仅请求模型服务的 `/api/tags` 或 `/models`，不发送日志，也不代表已验证模型能完成推理。服务不可达时可重试或手动填写模型名称。配置过程中取消不会覆盖原配置。

密钥默认隐藏输入，仅当前进程有效；重启后提问时可重新输入，也可选环境变量方式。请在同一次交互菜单中完成配置和提问。获取模型列表的服务端说明见 [DeepSeek 文档](https://api-docs.deepseek.com/api/list-models/)。

启动脚本可以追加 `models`、`tasks`、`tasks 任务ID`、`ask 任务ID`、`scan`、`watch` 或 `demo`。指定数据位置使用 `--data-dir /path/to/data`（Windows 也支持目录路径），该选项放在子命令前；也可设置 `WINSEC_DATA_DIR`。

默认不调用模型；在菜单明确启用，或执行 `scan --with-model`。本机模型地址是**当前安装机器**的 localhost。Linux 可配置 Linux 本机 Ollama，Windows 可配置 Windows 本机 Ollama；也支持兼容接口和 API。非本机地址须逐次确认；非交互命令还需 `--allow-remote-model`，才发送有限证据摘要。API Key 可隐藏输入，仅存当前交互进程，或通过环境变量读取。程序不捆绑本地模型，无模型服务时仍可运行规则分析。

### 0.2.3 模型回答与诊断

旧 DeepSeek 官方接口配置在读取时自动采用新默认值：关闭思考模式、输出上限 4096 tokens、连接后读取等待上限 180 秒，无需删除重建配置。仅对 `api.deepseek.com` 应用 DeepSeek 专用参数；其他 OpenAI 兼容服务与 Ollama 保留服务默认思考行为。

菜单 **3 模型配置 → 3 调整当前模型参数** 可选择 DeepSeek 普通回答/深度思考、输出额度（256–65536 tokens）与读取等待时间（10–600 秒）。从普通回答切到深度思考时建议额度为 16384，可修改；提高额度可能增加耗时与费用。模型服务仍可能拒绝超过自身限制的值。读取等待时间不是整个请求的绝对总时长。配置参数不会发送推理请求。

接口适配依据 [DeepSeek Chat Completions 文档](https://api-docs.deepseek.com/api/create-chat-completion/)：明确处理 `finish_reason`，输出达到上限时不把部分答案当完整报告，也不把 `reasoning_content` 当最终答案。错误区分 HTTP 状态、网络/超时、无效 JSON、结构不兼容、输出截断、仅有思考及空答案。不自动重试或切换模型。

失败后只保存固定错误类别、结束原因、是否有思考内容、答案字符数及服务返回的数值用量；不保存响应正文、思考正文、认证头或密钥。诊断随任务保存在本机，可在追问中输入 `/status` 查看，不发送请求；下一次经授权的提问会包含诊断，便于解释失败原因。成功后更新最新提问状态，原始自动分析结果仍保留。

远端模型可输入 `y` 仅授权当前问题，或 `s` 授权当前任务的本次对话及后续问题。退出追问或切换模型配置后需重新确认。无登录证据时明确提示只能咨询排查方法；Linux 本机采集向导可设置最近 1–1440 分钟的范围，不会把未识别记录当成有效登录证据。

所有防护动作仍为**模拟**：模拟器检验规则创建、到期失效和撤销，不改动实际防火墙。真实防护效果标记为未验证。重复失败线索不等于确认入侵成功。

旧入口 `python dev.py cli` 及原 Windows 数据库功能保留在源码工程中。本机发行包聚焦跨平台登录防护流程，不包含网页和完整 Windows 历史数据库工作台，不迁移旧开发数据。

## 发行包检查

包内 `SHA256SUMS.txt` 校验源文件，包外清单校验压缩包。打包采用固定清单，排除开发数据库、真实日志、虚拟环境、`.env` 和模型密钥。

## 检查和更新已安装版本

本机工作台菜单 **5 检查更新、6 更新并退出**。只检查不会安装，不会上传日志。更新成功后重新执行启动脚本。

Windows：

```powershell
.\start-windows.bat version
.\start-windows.bat check-update
.\start-windows.bat update
```

Linux：

```sh
sh start-linux.sh version
sh start-linux.sh check-update
sh start-linux.sh update
```

`update --yes` 可用于明确授权的非交互更新。请先停止同一安装目录的 watch/其他实例；运行锁会阻止并发更新。安装目录需要当前账号有写权限，程序不会自动提权。

更新源固定为 `Nero-Nyari/Microlnsight` 的 GitHub Releases，检查最近 30 个发布条目中的 `cli-vX.Y.Z` 稳定版本，比较数字版本号。源码分支的普通提交不会直接安装，草稿和预发布也不会安装。更新按 [GitHub Releases 接口](https://docs.github.com/en/rest/releases/releases) 读取元数据。仓库未发布、网络错误和没有更新分别提示。

私有仓库需要在当前机器设置 `WINSEC_UPDATE_TOKEN` 环境变量，令牌仅需该仓库 Contents 读取权限。不要将令牌放进启动脚本、聊天、Git 或模型配置。更新器只向 `api.github.com` 发送此令牌；下载跳转到其他主机时移除认证头。未授权或地址不可访问会报错，不会被当成“已是最新版”。

下载后校验整包 SHA256、包内各文件哈希、平台和版本。只替换程序清单中的文件，保留 `data/`、`.env`、模型配置及本机额外文件。如果已有程序文件被手动修改，停止更新并指出冲突，避免覆盖你的修改。自定义日志/数据应放在 `data/` 或安装目录之外。

依赖未变时沿用当前环境；有变化时在 `.updates/env-*` 创建独立环境并安装，原环境保留。隔离演示试运行成功后才切换程序和 `runtime.json` 环境指针。新版的模拟自检不会读取真实日志或调用模型。替换失败会恢复旧文件；替换过程中被中断，下次从启动脚本启动时读取事务记录恢复旧版。旧文件备份留在 `.updates/事务ID/backup`，此目录与旧环境暂不自动清理。

第一次使用更新功能需要安装包含本节功能的新包。此前没有更新器的样板包需要手动替换一次程序文件，保留 `data/`。之后使用更新菜单即可。开发源码目录不会自我覆盖，应通过 Git 管理更新。

### 维护者发布新版本

先提交代码、测试和 `.github/workflows/cli-release.yml` 到仓库，再为通过审核的提交创建递增的版本标签，例如下一版 `cli-v0.2.4`，推送该标签。发布工作流在 Windows/Ubuntu 上验证解析、本机发行包和更新事务；通过后构建两个包及校验清单并创建 GitHub Release。已安装的客户端随后能检查到它。只在本机修改或打包不会产生可下载的线上更新。

本地打包：`python build_cli_releases.py --version 0.2.3`。包内版本写入 `edition.json`，不要修改已发布标签下的资产内容；后续变更发布更高版本。更新流程保留本机数据，但未来涉及数据库格式变更的版本仍需单独实现并验证迁移，本样板尚无数据格式迁移机制。
