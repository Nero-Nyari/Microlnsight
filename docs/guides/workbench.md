# Microlnsight 完整开发与工作台指南

本文命令均在仓库的 `Microlnsight/` 应用目录执行。返回 [文档索引](../README.md)。

Windows / Linux 日志研判原型：各自在被保护主机上采集、分析和保存日志，查看原文依据，并导出核查报告。

## 本机安装版（当前 CLI 主线）

**Windows 装 Windows 版，Linux 装 Linux 版。** 每台主机独立工作。本机模型也在各自机器配置；选择远端 API 时才会在明确授权后发送证据摘要。

- Windows：`install-windows.bat` 安装，`start-windows.bat` 启动。
- Linux：`sh install-linux.sh` 安装，`sh start-linux.sh` 启动。
- 开发目录可直接运行 `python agent.py` / `python3 agent.py`，自动选择本机平台。
- `python build_cli_releases.py` 生成 Windows ZIP 和 Linux tar.gz 源码发行包，排除真实日志和密钥；需要 Python 3.10+。
- 安装版菜单 5/6 支持检查仓库发布版本和更新；也可用启动脚本追加 `check-update` / `update`。更新保留本机数据，失败恢复旧文件；私有仓库使用本机 `WINSEC_UPDATE_TOKEN` 环境变量。

部署步骤、依赖和限制见 [本机 CLI 安装说明](../../Microlnsight/NATIVE_CLI.md)。以下 `dev.py` 和网页说明保留给完整开发工程。

当前演示主线是 **导入日志 → 本地联合分析 → 核对证据 → 下载报告**。本地联合分析无需模型或 API Key。单条模型分析为独立的可选功能，结论需要人工核实。

## Windows 快速开始

环境：Python 3.10+、Node.js 18+，两者需可从终端访问。以下命令在包含 `dev.py` 的应用目录执行（仓库根目录下的 `Microlnsight`）。

首次安装：

```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
npm --prefix frontend ci
```

检查、启动和测试使用同一个入口：

```powershell
python dev.py check
python dev.py start
# 在另一个终端验证
python dev.py test
npm --prefix frontend test
npm --prefix frontend run build
```

也可以双击 `start.bat`，或执行 `start.bat check` / `start.bat test`。启动器依次检查 `backend/.venv`、历史 `myenv`、历史 `mayenv`、当前 Python 和 PATH 中的 Python，跳过缺少核心依赖的环境，并打印实际使用的解释器。新安装统一使用 `.venv`，无需激活环境。

要固定解释器，使用 `python dev.py start --python "D:\path\to\python.exe"`；`check` 和 `test` 支持相同选项。指定环境不合格时会报错，不静默切换。

- 工作台：http://127.0.0.1:5173
- 后端健康检查：http://127.0.0.1:8000/api/health
- 启动器等待服务就绪后显示 Ready；任一服务失败会停止本次启动的其他服务。
- 8000 或 5173 被占用时明确报错，请先停止已有服务。
- 保留启动终端，按 **Q 或 Ctrl+C** 停止前后端。统一启动不启用热重载后端，修改 Python 后重启。
- `check` 只检查环境和应用导入，不启动服务；测试使用隔离数据库。

## 命令行工作台

安装后端依赖后，在应用目录执行：

```powershell
python dev.py cli
```

这是交互式终端菜单，不启动网页，也不需要 Node.js。启动后显示已导入 Windows 记录的总览；菜单 3 可按日志时间、来源、事件类型和单条结论查找记录，菜单 4 可逐层查看线索、原文并运行单条分析，菜单 5 先预览报告再决定是否导出。菜单 2 引导读取 Security/Application/System 通道，先展示通道状态和事件概览，再询问是否导入并批量分析；菜单 6 可重新批量分析已导入的真实日志。若 Security 通道权限不足，可尝试 Application；是否可读仍取决于当前终端权限。当前联合规则主要针对 Security 和 System 事件，Application 日志导入后通常仍需人工核查。命令行使用独立的 `backend/data/cli-preview.db`，不会把演示案例写入网页版本的数据库。

也可以直接执行单个命令（使用安装好后端依赖的 Python）：

```powershell
python -X utf8 cli.py demo windows_demo_sequence
python -X utf8 cli.py list
python -X utf8 cli.py report 6 --output report.md
python -X utf8 cli.py scan --channel Security --max-events 200
python -X utf8 cli.py scan --channel Security --max-events 200 --import-logs
python -X utf8 cli.py batch --output batch-report.md
```

`scan` 默认只预览通道状态与事件类型数量；加 `--import-logs` 才保存本次日志并自动批量分析。`batch` 会对试用数据库中最新 5000 条已导入真实日志联合分析，保存报告时包含原始证据。`report` 和 `analyze` 的 ID 以实际 `list` 输出为准，用于单条证据核查。事件编号只代表 Windows 事件类型，不单独证明恶意；未收录的编号会显示来源，供核对原文。真实日志和报告可能包含账户、地址等敏感信息，默认只保存在本机。原有日志分析子命令只调用本地联合规则；模型解释使用新增入口，所有入口均不执行真实封禁或隔离。Security 通道仍需由运行终端的 Windows 账户具备读取权限。

### Linux 服务器导出日志

命令行菜单选 **7 分析服务器日志目录**，粘贴包含 `ssh.journal.log`、`nginx-security-access.log` 等文件的目录。界面先列出识别及缺失的文件，再在后台只读分析；可继续使用菜单，并在 **9 后台任务状态** 查看结果。退出时会等当前分析完成并显示报告路径。直接执行命令仍会同步等待并输出结果：

```powershell
python -X utf8 cli.py server "D:\path\to\server-logs" --output "D:\path\to\server-report.md"
```

这是独立的本地只读入口：按 SSH 认证、Nginx JSON 访问日志和应用 journal 中的 JSON 记录汇总；验证目录中的 `SHA256SUMS.txt`，生成含文件名与行号的 Markdown 报告。未指定 `--output` 时自动保存到 `backend/data/server-reports`。每个日志文件上限 100 MB；超限文件跳过解析和清单校验，继续处理其他文件，并明确提示跳过行数未知。空文件、缺失文件、未识别文本和清单不符会在报告中说明。该入口不读取服务器在线状态，不使用 Windows 事件编号规则，也不把服务器日志写入试用数据库。目录中的其他文件（例如 `.accdb`）只列名称，不读取内容。

### 第一轮改进：分析范围与关联准确性

- 服务器控制台和报告显示发现/识别/未支持/超限文件数，以及读取、已识别、未识别、格式无效、重复和空白行数。逐文件满足 `读取 = 已识别 + 未识别 + 格式无效 + 重复 + 空白`；缺少时间单独统计，可与前述类别重叠。
- 各来源分别给出可识别时间范围（UTC）和未识别/无效行的原文位置。无时区时间不猜测；没有已识别记录时明确显示无法判断。某个来源缺失不代表该服务一定存在。
- 完全相同的重复文本行在同一文件内保守去重，不重复累计；原始文件保持不变。文本去重无法证明每行都是独立事件，也不提供跨文件去重保证。
- SSH 失败后成功要求同主机、同账户（区分大小写）、同有效来源 IP，并且失败发生在成功之前 30 分钟以内。缺少必要信息时只保留汇总。原文乱序时按实际时间确定最早证据；root 登录与服务停止也必须同主机，仅提示时间邻近。
- HTTP 关联要求相同 `request_id`、兼容请求信息、前后 120 秒时间窗；唯一匹配还要求明确且一致的 `service` 和服务器主机。主机取 JSON 的 `server_host` 或应用 journal 头部主机，不把 HTTP `Host` 当作服务器主机。同 ID 的多个异常全部保留为候选；缺少标识或同一异常对应多个网关请求时只显示待核实，不计入唯一匹配，也不据此确认根因。
- Windows 批量分析显示所选总数、5000 条上限导致的跳过数、重复/标识冲突排除数、结构识别、规则覆盖和各主机/通道时间范围。本次采集达到条数上限时提示可能还有未读记录，数量未知；失败通道会进入本次批量报告。
- 历史采集范围和批量任务尚未持久化：重新分析已有数据时会明确提示无法核实原通道是否读全。任务历史、中断状态和通用日志格式扩展属于后续轮次。

### P0 收尾：来源校验与结论状态

- 离线目录和本机/SSH 采集共用 `parse_ssh_line`。支持导出的 journal 文本及 journal JSON；仅接受 `sshd`、`sshd-session`、`sshd-auth` 的认证消息。JSON 优先核对 `_COMM`，仅在缺少该字段时使用 `SYSLOG_IDENTIFIER`；正文中引用登录消息的其他进程不计入认证次数。
- 主机、账户、有效来源 IP、带时区时间必须齐全。离线报告列出无法确认来源、缺失字段、无效格式和未支持消息的排除数量及原文行号；源文件保持只读。文件名和日志字段本身不构成来源真实性的密码学证明。
- 结论区分「数据不足，无法判断」「在已分析范围内未发现规则线索」「发现待核查线索」。结构可识别但不属于当前规则支持范围、或缺少规则必需字段的记录，不作为“已运行规则且未命中”的依据。
- 数据质量单独显示：部分解析失败、字段缺失、记录冲突、达到采集上限或历史采集范围无法核实时，标记「分析范围不完整」。有效部分仍可产生线索，未参与分析的内容尚无法判断；普通重复记录去重不自动等同于数据缺失。
- 新版本机任务保存结论状态，任务详情和模型证据摘要使用相同判断；采集失败、分析失败和中断不会显示为“未发现线索”。Windows 单条/批量控制台及新生成的 Markdown 报告显示同一轮结论和范围信息。历史 Windows 报告保持原样，需重新分析后生成新版结论。
- 本轮在 Windows 运行完整后端回归：149 项，其中 148 项通过、1 项 Linux PTY 专用测试跳过。包括两个 SSH 入口一致性、非 SSH 来源、无时区/无效 IP、空或全部无效数据、部分可分析数据、任务重启后的结论及采集失败。Windows/Linux 发布包隔离启动检查通过；未据此宣称已完成真实 Linux 服务器联调。

自动检查包括后端单元测试、前端测试与构建；推送或提交合并请求时由仓库根目录的 `.github/workflows/ci.yml` 运行。本地可分别执行 `python dev.py test`、`npm --prefix frontend test` 和 `npm --prefix frontend run build`。后端测试设置 `WINSEC_TEST_MODE=1`，强制使用本地规则模式，避免误用本机保存的模型密钥或调用外部模型。

## 三分钟演示

### CLI 比赛样板：Windows / Linux 登录防护流程

运行 `python dev.py cli` 后新增：**10 模型配置与选择、11 采集分析与模拟防护、12 防护任务/证据/追问**。

本轮支持真实 Windows Security 登录事件、Linux 本机 journal，以及导出目录中的 `ssh.journal.log`。
流程为采集 → 固定规则关联 → 可选模型解释 → 保护名单校验 → 模拟处置 → 模拟验证。
模型解释单独留档，不修改规则结论，也不能提交任意系统命令。当前没有接入 MCP。

```powershell
# 项目目录内执行；两个演示明确标注合成数据
python -X utf8 cli.py guard demo-linux
python -X utf8 cli.py guard demo-windows

# 真实 Windows 日志；需要 Security 读取权限
python -X utf8 cli.py guard windows --limit 1000

# 在 Linux 服务器本机执行
python3 -X utf8 agent.py scan --minutes 15 --limit 1000

# 历史导出只读复盘
python -X utf8 cli.py guard export --directory "D:\path\to\server-logs"

# 自动轮询，每轮重新读最近 15 分钟；Ctrl+C 停止。所有处置仍然模拟
python3 -X utf8 agent.py watch --interval 60 --protect 192.0.2.10

python -X utf8 cli.py tasks
python -X utf8 cli.py tasks <任务ID>
python -X utf8 cli.py models
python -X utf8 cli.py ask <任务ID>
```

Linux 上可用 Python 3.10+ 直接运行 `python3 cli.py guard linux`；上述 `guard/tasks` 子命令使用标准库，模型调用另外需要 `python3 -m pip install requests`。完整交互菜单和原有 Windows 数据库功能仍需安装 `backend/requirements.txt`。SSH 使用现有密钥、批处理认证和严格主机密钥检查，不提示输入密码、不自动信任新主机、不自动提权。权限、认证或采集失败会保存失败任务并停止本次运行。SSH 端口和私钥路径请放进 SSH config。Linux 仅支持 journal 中 sshd、sshd-session、sshd-auth 的密码失败/成功登录；不支持的文本和缺字段事件显示排除数量。

模型配置支持 **Ollama `/api/chat`** 和 **OpenAI 兼容 `/chat/completions`**（地址应包含服务所需的 `/v1` 等前缀）。本地无需 API Key；也可以选兼容的远端 API。CLI 配置独立于网页已有模型配置，不会自动读取网页密钥。API Key 隐藏输入只保留本次进程，或通过自选环境变量读取；配置文件仅保存环境变量名。通过 `python cli.py models` 输入的临时密钥在命令退出时失效，跨命令使用请设置环境变量；交互主菜单内配置可持续使用到程序退出。

启用自动模型解释需显式加 `--with-model`。非本机地址还需 `--allow-remote-model`，表示允许本次运行发送证据摘要和最近对话；交互提问则逐次确认，并可先预览证据 JSON。发送内容至多 30 条证据片段、10 条线索及最近 8 条对话，含被省略证据数量；账号、IP、主机名和日志业务字段可能包含敏感信息。模型失败显示失败，保留固定规则分析，不回退到其他服务或模拟回答。真实服务的可用性需在用户配置后验证，协议测试不能代替实际模型联调。

**样板验证的含义：** 内存模拟器检验规则创建、到期失效和撤销；`actual_system_change=false`、`verification=not_performed` 始终表示未改动真实防火墙、未验证真实防护效果。保护名单支持 IP/CIDR；重复相同证据不新增模拟动作。阈值是同主机、账户和 IP 在 5 分钟内至少 5 次失败，后续 15 分钟内成功登录只作为核查线索。规则未覆盖所有攻击方式，单次未命中不能证明安全。

任务、覆盖范围、失败状态、证据片段、模拟方案和追问保存在默认 `backend/data/cli-preview.guard/`；`--database` 会为其他数据库使用独立的同名 `.guard` 目录。证据原文每条最多 4096 字符，超出时标注并保存完整记录 SHA256；导出源文件保持只读。菜单 12 可导出 JSON，包含任务及最多最近 1000 条会话消息。此任务历史针对新防护入口，旧菜单 2/6/7 的历史不会自动迁移。

新增测试覆盖两平台解析、去重冲突、保护名单、固定 SSH 参数、认证失败、模拟到期/撤销、任务持久化、两种模型协议和发送确认；CI 新增 Windows/Ubuntu 矩阵。CI 配置需推送后运行，本机 Windows 的测试通过不代表真实 Linux SSH 联调已完成。

先切到左侧“演示数据”，展开“Windows 演示案例”，在下拉框依次选择以下场景并点击“载入案例”：

| 场景 | 输入 | 运行本地联合分析后的预期 |
| --- | --- | --- |
| 1. 正常运维 | 一条服务清单查询 | 未发现规则覆盖范围内的异常，留在日志列表，仍需核对授权 |
| 2. 单次登录失败 | 一条 4625 | 不达到重复失败阈值，留在日志列表 |
| 3. 连续失败后成功 | 五条独立 4625 + 一条 4624 | 当前选中事件进入告警列表，展示失败次数和后续成功登录线索 |

每次加载后点击“运行本地联合分析”，默认窗口 15 分钟。第三个场景一次导入 6 条日志，自动选中最后一条作为分析起点；其他记录仍保留原状态。重复加载会新增演示记录，但关联计数会去重。

三个场景使用不同主机名，并明确标记合成数据，与真实日志隔离。成功登录不等于入侵成功；没有命中规则也不代表整机安全。

完整讲解顺序与验收标准见 [三分钟演示](demo-walkthrough.md)。

## 真实日志与模型

“导入日志”支持读取本机 Windows Security、System、Application、Defender、PowerShell 通道，也支持粘贴文本、JSON、XML。先预览，再导入；原始等级不直接构成告警。

Security 读取权限取决于后端账户。权限不足时页面显示通道错误，其他成功读取的记录仍可使用；应用不会自动提权。

本地联合分析仅检查已导入数据，按主机、账户、来源 IP 和时间窗口关联。5 分钟内至少 5 条独立失败记录是本项目的启发式阈值；重复记录不累计，缺少必要字段的记录不参与阈值判断。

如需单条模型分析，在“模型管理”配置本地或云端服务。只有显式启动模型分析才会发送输入给所配置的服务。未配置模型时的模拟输出不用于评价检测效果。导入和本地联合分析不调用模型。

## 当前范围

- React + FastAPI + SQLite；页面和 Markdown 报告复用同一轮研判。
- 保留日志原文、记录号、时间、证据引用和内容哈希；缺失信息显示“未提供”。
- 关联范围限于最新 5000 条导入日志及选中记录，超限会提示。
- 不模拟外部资产、威胁情报或漏洞查询结果；时间关联不能证明因果关系。
- 本轮验收不包含真实封禁、账户禁用、文件隔离、服务删除或生产部署。
- 合成样本和自动化测试不能代表真实环境的误报率、漏报率或商用适用性。

## 数据与文档

数据库、模型密钥、`.env`、虚拟环境和构建产物均为本地数据，不提交 Git。不要将真实日志放入演示样本。

- [使用说明](user-manual.md)
- [当前项目说明](../project/project-report.md)
- [验收记录](../validation/windows-validation.md)
- [固定回归样本](../../Microlnsight/backend/tests/fixtures/README.md)

## 常见问题

**环境检查失败：** 查看输出中的 Python 路径，用该解释器安装依赖，或按首次安装步骤创建 `backend/.venv`。使用 `python -m pip`，避免将包安装到另一个环境。

**前端依赖缺失：** 在应用目录执行 `npm --prefix frontend ci`。

**端口占用：** 先停止之前的前后端，再运行统一入口；启动器不会关闭其他程序或自动换端口。

**Security 无权限：** 查看读取面板的后端账户及权限说明。由本机管理员核实采集权限；以管理员身份打开浏览器不会改变后端权限。
