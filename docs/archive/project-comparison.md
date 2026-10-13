> 历史方案文档：以下描述不代表当前已实现或已验收能力。当前范围见 [项目说明](../project/project-report.md)，运行与演示见 [README](../guides/workbench.md)。

## SecAgentX vs win10-security-agent 项目对比
### 1. 项目定位
维度 win10-security-agent SecAgentX 背景 挑战杯"揭榜挂帅"专项赛参赛作品 企业级安全运营平台 目标 面向终端的智能化安全运营 Agent 面向 SOC 的多 Agent 协作分析平台 核心理念 读取 Windows 日志 → AI 分析 → 自主闭环处置 告警接入 → 多 Agent 流水线分析 → 人工审核

### 2. 架构差异（最关键）
win10-security-agent — 单体架构 ，一个 Python 进程搞定一切：

所有逻辑集中在 SecurityAgent 一个类中，包含 8 个子系统（日志读取、RAG 知识库、LLM 客户端、工具注册、记忆、ReAct 引擎、多源采集、调度器）。

SecAgentX — 前后端分离 + 多 Agent 流水线 ：

- 后端： pipeline.py 编排 6 个独立 Agent，每个 Agent 职责单一
- 前端：React + TypeScript + TailwindCSS + Zustand 状态管理
- 数据持久化：SQLAlchemy + SQLite
### 3. Agent 设计差异
win10-security-agent — 单一 ReAct Agent：

react_agent.py 实现经典的 Thought → Action → Observation 循环，一个 Agent 负责所有事（分析、决策、执行）。

SecAgentX — 6 个专职 Agent 流水线：

Agent 职责 Parser Agent 解析原始告警内容 Triage Agent 风险评级与分类 Evidence Agent 采集关联证据 Attack Chain Agent 攻击链还原 Response Agent 生成响应动作建议 Report Agent 汇总生成报告

每个 Agent 的执行状态都记录在 AgentRun 数据库表中。

### 4. 数据层差异
win10-security-agent ：无持久化数据库

- 日志存内存
- 知识存 ChromaDB 向量库
- 记忆存 JSON 文件（ long_term_memory.json ）
SecAgentX ：完整关系型数据模型

- Alert （告警）→ Incident （事件）→ AgentRun / EvidenceItem / ResponseAction / Report
- 支持告警生命周期管理：pending → analyzing → review → approved/rejected → closed
### 5. 前端/UI 差异
维度 win10-security-agent SecAgentX 框架 Gradio（Python 声明式） React + TypeScript + TailwindCSS 部署 单 Python 进程自带 Web 服务 前端 Vite dev server + 后端 FastAPI 分开运行 交互模型 Tab 页切换（日志/分析/处置/报告/知识库） 工作台：告警列表 → 详情 → AgentFlow 可视化 → 处置面板 可视化 Matplotlib 图表 AgentFlow 组件 + AttackChain 可视化

### 6. 独有能力对比
仅 win10-security-agent 拥有：

- 🔴 真实 Windows 日志读取（通过 log_reader.py 读取 Windows Event Log）
- 🔴 本地 RAG 知识库（ChromaDB + sentence-transformers 本地嵌入模型）
- 🔴 多源数据采集（进程/网络连接/服务/计划任务/注册表 — multi_source.py ）
- 🔴 自主调度器（定时扫描 + 自动处置阈值）
- 🔴 ReAct 闭环处置（封禁 IP、隔离文件、禁用账户）
仅 SecAgentX 拥有：

- 🟢 完整的前后端分离架构
- 🟢 关系型数据库持久化
- 🟢 多 Agent 流水线（职责分离）
- 🟢 攻击链分析
- 🟢 告警生命周期管理 + 人工审核流程
- 🟢 Demo Cases（预置演练场景）
- 🟢 多 LLM 后端支持（OpenAI / Anthropic / Ollama）
### 7. 技术栈对比
win10-security-agent SecAgentX 语言 Python Python (后端) + TypeScript (前端) 后端框架 无（Gradio 自带服务） FastAPI 前端框架 Gradio React 18 + Vite 数据库 无 / JSON 文件 SQLAlchemy + SQLite AI/LLM DeepSeek / Sangfor / Mock DeepSeek / OpenAI / Anthropic / Ollama 向量库 ChromaDB 无 CSS Gradio 内置 TailwindCSS

### 总结
两个项目的关系可以理解为： win10-security-agent 是一个面向终端的"单兵作战"原型系统 （从底层日志读取到上层 AI 分析全部自研），而 SecAgentX 是一个面向 SOC 场景的"团队协作"平台 （架构更规范，更注重可扩展性和流程化）。

如果 win10-security-agent 是参赛用的"概念验证"，SecAgentX 则更接近"产品化"方向演进。