# WinSecAgent

基于 FastAPI + React + LLM 的 Windows 安全事件智能研判平台。

系统通过多阶段智能体流水线，将原始安全告警自动转化为结构化的安全事件分析报告，涵盖告警解析、风险研判、证据提取、攻击链分析和处置建议。

---

## Windows 版本工作流（2026-09）

- **导入日志 → 读取本机日志**：读取后端所在 Windows 电脑的 Security、System、Application、Defender 和 PowerShell 通道。先预览并勾选记录，再加入日志列表；发现有证据支持的异常线索后才形成告警，不会在导入时执行处置。
- **导入日志 → 粘贴 Windows 日志**：支持事件查看器常规文本、JSON 和 XML，可补充事件 ID、日志通道、主机名。缺失字段保留为未知。
- 默认案例为 4625、7045、1116、4104、4648 Windows 事件，明确标记演示输入。历史 Linux/通用记录保留，报告仍以记录来源为准。
- 报告保留来源与目标平台，不再模拟外部防火墙、CMDB、IOC 或漏洞查询；模型报告不完整时，提供有提示的完整结构化报告。
- Windows 采集失败会展示通道/采集项错误，不使用假进程替代。Security 通道可能需要额外权限；“没有关注事件”不等于整机安全。
- 窄窗口以纵向布局展示各面板。下载为 Markdown 文件。服务重启后的未完成分析标记为中断，可重新分析。

验证：后端 `python -m unittest discover -s tests -v`；前端 `npm run build`。

## 环境要求

| 依赖 | 版本要求 |
|------|---------|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 随 Node.js 安装 |

---

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/Nero-Nyari/Microlnsight.git
cd Microlnsight/WinSecAgent
```

### 2. 安装后端依赖

```bash
cd backend

# 创建虚拟环境（推荐，避免污染系统 Python）
python -m venv myenv

# 激活虚拟环境
myenv\Scripts\activate        # Windows
# source myenv/bin/activate   # Linux / macOS

# 安装所有 Python 依赖
pip install -r requirements.txt
```

主要安装的包包括：FastAPI、SQLAlchemy、OpenAI、Anthropic、ChromaDB、sentence-transformers 等。Windows 平台会额外安装 pywin32（用于读取 Windows 事件日志）。

### 3. 安装前端依赖

```bash
cd ../frontend

# 安装 Node.js 依赖（React、Vite、Tailwind CSS 等）
npm install
```

### 4. 配置环境变量（可选）

如果需要使用真实的大模型 API（如 DeepSeek、OpenAI 等），需要配置 API Key。

**方式一：通过 .env 文件**

```bash
# 从 frontend 目录切换到 backend，复制应用根目录的示例
cd ../backend
copy ..\.env.example .env
```

编辑 `backend/.env`，填入你的 API Key：

```ini
LLM_TYPE=deepseek
DEEPSEEK_API_KEY=你的API密钥
DEEPSEEK_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-v4-flash
```

**方式二：通过前端界面配置**

启动后可在前端工作台的「模型管理」界面中添加和切换模型，无需手动编辑文件。

`backend/data/models.json`、数据库、隔离文件和 `.env` 均为本地运行数据，不提交到 Git。模型配置不存在时可通过界面创建；`backend/data/models.example.json` 是空配置示例。不要把真实日志、API 密钥或数据库加入提交。

> 不配置 API Key 也可以运行，系统会自动使用本地模拟模式，返回占位分析结果，适合功能演示和开发调试。

### 5. 启动服务

**启动后端（终端 1）：**

```bash
# 确保在 backend 目录下，且虚拟环境已激活
python run.py
```

后端启动后访问 http://127.0.0.1:8000/api/health 验证是否成功，正常返回：

```json
{"ok": true, "app": "WinSecAgent", "version": "1.0.0"}
```

**启动前端（终端 2）：**

```bash
# 确保在 frontend 目录下
npm run dev
```

> **Windows 用户**安装依赖后可双击应用目录下的 `start.bat` 启动前后端。脚本优先使用可用的 `backend/myenv` Python，否则使用 PATH 中的 Python；不会自动安装依赖。

### 6. 访问系统

| 服务 | 地址 |
|------|------|
| 前端工作台 | http://127.0.0.1:5173 |
| 后端 API | http://127.0.0.1:8000 |
| API 文档 | http://127.0.0.1:8000/docs |

> 如果 5173 端口被占用，Vite 会自动切换到 5174、5175 等，请以终端实际输出为准。

---

## 使用指南

### 加载演示案例

左侧面板提供内置演示案例，点击后创建待分析日志；分析后按结论决定是否形成告警：

| 案例 | 场景 |
|------|------|
| Windows 登录失败激增 · 4625 | 远程登录异常核查 |
| 可疑服务安装 · 7045 | 服务路径、签名与变更核查 |
| Defender 威胁检测 · 1116 | 检测记录与处置结果核查 |
| PowerShell 可疑脚本 · 4104 | 脚本块和进程上下文核查 |
| 显式凭据登录 · 4648 | 账户与目标主机授权核查 |

### 手动导入日志

点击右上角「导入日志」，选择读取本机日志或粘贴 Windows 日志；手动输入支持文本、JSON 和 XML，可补充事件 ID、通道和主机名。

### 分析事件

选择记录后可运行本地联合分析，或显式选择“单条模型分析”。后者会将输入发送给当前配置的模型服务，按以下流程执行：

1. **解析** — 提取告警类型、目标、来源等关键字段
2. **研判** — 判断风险等级和置信度
3. **证据提取** — 从输入日志提取可定位的原文依据，不虚构外部查询结果
4. **攻击链分析** — 正常或证据不足时不建立攻击链；异常线索仍需核实
5. **处置建议** — 依据统一结论生成建议，不在分析过程中自动执行
6. **报告生成** — 复用统一研判生成 Markdown 报告

### Windows 日志读取

系统支持读取后端所在 Windows 电脑的 Security、System、Application、Defender 和 PowerShell 事件日志（需 Windows 平台 + pywin32），读取到的记录不自动视为异常。

读取失败会显示原因；演示案例需显式选择。

---

## 支持的 LLM 提供者

| 提供者 | 说明 |
|--------|------|
| DeepSeek | deepseek-chat / deepseek-reasoner 等 |
| OpenAI | gpt-4o / gpt-4o-mini 等 |
| Anthropic | claude-3-opus / claude-3-sonnet 等 |
| Ollama | 本地部署，支持 llama2 / mistral / qwen2 等 |
| Local | 内置模拟模式，无需 API Key |

---

## 项目结构

```
WinSecAgent/
├── backend/
│   ├── app/
│   │   ├── agents/        # 智能体（解析、研判、证据、攻击链、处置、报告）
│   │   ├── api/           # FastAPI 路由
│   │   ├── core/          # 配置与 LLM 提供者
│   │   ├── db/            # 数据库连接
│   │   ├── models/        # SQLAlchemy 数据模型
│   │   ├── schemas/       # Pydantic 请求/响应模型
│   │   └── services/      # 日志读取、记忆、RAG 等服务
│   ├── data/              # 运行时数据（SQLite、模型配置等）
│   ├── requirements.txt
│   └── run.py
├── frontend/
│   ├── src/
│   │   ├── components/    # React 组件
│   │   ├── pages/         # 页面
│   │   ├── services/      # API 调用
│   │   └── stores/        # Zustand 状态管理
│   └── package.json
├── docs/                  # 文档
└── start.bat              # Windows 一键启动
```

---

## 常见问题

**Q: 启动后端报错 `ModuleNotFoundError`？**

确保已激活虚拟环境并安装了所有依赖：`pip install -r requirements.txt`

**Q: 分析结果返回的是模拟内容？**

说明未配置 LLM API Key，系统使用本地模拟模式。通过 .env 文件或前端「模型管理」界面配置 API Key 即可。

**Q: Windows 日志读取功能无法使用？**

该功能依赖 pywin32，仅在 Windows 平台可用。非 Windows 环境或权限不足时会返回明确提示；演示数据需显式选择，不能作为本机真实采集结果。

**Q: Security 提示“日志读取权限不足”，其他通道正常？**

错误 5 表示当前后端账户被拒绝访问该通道。读取面板按通道显示结果，其他成功读取的记录仍可选择和导入；“读取成功”只表示本次请求范围成功，每个通道最多读取指定条数，不代表读取了所有历史记录。原始异常位于“错误详情”。

展开“如何处理日志读取权限不足”可查看后端实际运行账户及进程是否提升权限。浏览器账户、启动终端的用户名和后端进程账户可能不同，以后端返回的诊断为准；以管理员身份打开浏览器不会改变后端权限。

由本机管理员核实账户、UAC 令牌、Security 通道 ACL 及组织策略。可在停止现有后端后，以管理员身份启动后端进行验证，避免同一端口重复启动；长期运行应使用具有必要日志读取权限的专用采集账户。不要为方便读取而给沙箱账户授予管理员权限。应用不会自动提权、修改用户组、审计策略或通道 ACL。修改权限后需按实际配置更新登录令牌或重启后端，再读取 Security 验证；不能仅凭其他通道正常判定问题已解决。

读取接口额外返回 `read_status`（success/partial/failed/demo）、`channel_results`（逐通道条数、错误类型及详情）和 `reader_context`。`warnings` 保留兼容；导入接口也保留读取状态和警告。Windows 缺少依赖或读取失败时不回退到模拟数据。`EvtNext` 的错误 259 是正常读到末尾，不作为失败提示。

参考：[Microsoft 事件查询与读取文档](https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events)。

**Q: 前端启动后白屏？**

检查后端是否已启动（http://127.0.0.1:8000/api/health），前端需要后端 API 支持。


### 日志与告警分流、结论一致性

- 导入（含演示案例）先作为待分析日志。原始 severity 和 Windows EventID 不直接触发告警。
- 日志列表包含待分析、正常活动、证据不足待核实和失败/中断记录。告警列表只包含研判发现异常且提供了可在原文定位的证据片段的记录。
- 每轮分析以统一研判为准。分类和 disposition 冲突、模型失败、异常证据无法定位时，归为 unknown/needs_review，保留在日志列表。
- 正常或证据不足的记录跳过攻击链和处置模型，只提供日志留存/补证核查建议。正常并不代表整台主机安全。
- 报告以结构化模板复用同一研判，避免报告模型另行生成攻击结论。异常阶段仍为待核实假设；引用匹配只能验证原文存在，不保证模型对其含义判断正确。
- 当前详情只展示最近一轮分析；历史原始输出仍保存在数据库中。旧报告通过一致性视图重新整理并明确标注，原报告内容不覆盖。旧有缺少可定位证据的异常判断会回到待核实，重新分析后才能形成告警。
- API 保留旧 alerts 表/路由作为兼容存储；GET /api/incidents 和 GET /api/alerts 支持 queue=logs|alerts，由后端研判规则分流。调用者提交的 status/risk 不会跳过待分析阶段。
- 导入接口返回 logs_imported；alerts_created 仅统计经过分析后实际形成的告警。无需数据库迁移或删除旧记录。

验证：在 backend 运行 python -m unittest discover -s tests -v；在 frontend 运行 npm run build。

### 结构化证据与本地联合分析

结果页顶部展示“发现了什么、依据是什么、建议做什么”，并分列导入记录的原始等级和分析后风险。原始等级不表示已经形成告警，也不是 Windows Event Level。

选择一条已导入记录，点击“运行本地联合分析”。默认搜索该记录前后各 15 分钟、同主机的已导入 Windows 日志，可选择 5/15/30/60 分钟。不调用外部模型，不自动读取新的本机日志。仅更新当前事件的研判与队列，其他关联事件保持原状。最新一轮联合分析和单条分析相互替代展示，历史原始记录、分析和报告保留。

- 按主机、账户域/用户名、来源 IP 分组，5 分钟内至少 5 条独立 4625 记录产生“疑似密码猜测”线索。这是应用初始启发式阈值，不是 Windows 标准，也不证明攻击；失效凭据重试等情况仍需人工核实。
- 关联同账户、来源 IP 后续的 4624，以及同主机后续 7045/4697，明确标注时间关联；尚未用 LogonId/进程链证实因果关系。
- 自动服务的可执行路径包含 Temp、Users/Public 或 AppData 时产生核查线索；不会把命令参数里的临时目录误当可执行文件路径，不检查真实签名或实际目录权限。
- 时间、失败次数、IP、账户、数据库日志 ID、Windows 记录号、逐条原文和 SHA-256 可追溯；报告保存本轮证据快照。原文哈希只用于核对内容，不证明日志来源可信。
- 重复记录不累加次数；同标识字段冲突的记录排除统计。缺少时区、独立记录号、账户或有效 IP 时，不用于登录失败次数阈值判断。演示与真实日志隔离。
- 最多扫描最新 5000 条导入日志及当前记录，超限明确提示。未导入日志、Security 权限缺失等采集空缺必须补证，不能推断“没有攻击”。
- 本地规则未命中时保留在日志列表并显示待核实；不因为工具名包含 PowerShell/Codex 就生成告警或直接认定安全。联合分析不生成可执行处置。

接口：`POST /api/incidents/{id}/correlate`，请求 `{"window_minutes":15}`。详情返回 `source_record`、`correlation`。使用现有 AgentRun/EvidenceItem/Report 表，无数据库迁移。

固定样本在 `backend/tests/fixtures/windows_regression.json`，说明在同目录 README。规则验证不等于模型误报率评估。

事件字段参考：[4625 登录失败](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)、[4624 登录成功与关联字段](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)、[4697 服务安装](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)。
