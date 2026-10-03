> 历史方案文档：以下描述不代表当前已实现或已验收能力。当前范围见 [项目说明](project-report.md)，运行与演示见 [README](../README.md)。

## 一、启动与运行方式
### win10-security-agent
- 一个命令启动 ，单进程包含所有功能
- Gradio 自带 Web 服务器
- 所有组件在 SecurityAgent. init 中一次性初始化（8个子系统串联启动）
### SecAgentX
- 需要两个终端 ，前后端分离
- 前端通过 api.ts 发 REST 请求到后端
- 数据库自动建表（SQLAlchemy create_all）
## 二、数据输入方式
### win10-security-agent — 直接读取本机 Windows 日志
操作流程：

1. 点击 "读取Windows日志" 按钮
2. WindowsLogReader 通过 win32evtlog 直接读取本机 Event Log
3. 读取 Security / System / Application / Defender 四个日志通道
4. 自动识别可疑事件 ID（4625 暴力破解、4648 委托登录、4740 账户锁定、7045 服务安装、1116/1117 Defender 告警等）
没有真实日志也能运行 ：非 Windows 环境自动使用 模拟数据 。

### SecAgentX — 手动创建或加载预置案例
操作流程：

1. 点击 "New Alert" 按钮，手动粘贴告警文本
2. 或通过 POST /api/alerts/from-case/{case_id} 加载 Demo Cases
3. 内置 5 个预置案例：SSH 暴力破解、SQL 注入、Log4j 漏洞利用、异常挖矿进程、横向移动
不读取真实日志 ，面向的是已有的告警/SIEM 数据。

## 三、分析流程差异（核心）
### win10-security-agent — 两种分析模式
模式A：传统 CoT 分析 （ llm_analyzer.py ）

- 一条 prompt 包含所有信息，LLM 返回 JSON 格式的思维链 + 威胁评估 + 建议
- 简单直接，但分析深度有限
模式B：ReAct 自主推理 （ react_agent.py ）

- 最多循环 5 步（ max_steps=5 ）
- 每步由 LLM 自主决定下一步行动
- 可调用的工具：查询知识库、搜索历史事件、执行系统命令等
- 每步记录在 AgentStep 中，用户能看到完整推理轨迹
### SecAgentX — 6 Agent 流水线
pipeline.py 串联执行：

每一步的执行状态都持久化到数据库（ AgentRun 表），前端 AgentFlow 组件实时展示各 Agent 的运行状态和耗时。

## 四、处置/响应差异
### win10-security-agent — 真正的系统操作能力
ActionEngine 能执行真实系统命令：

处置类型 实际操作 安全保障 封禁 IP Windows 防火墙规则 ( netsh advfirewall ) dry_run 模拟 隔离文件 移动到 ./quarantine 目录 dry_run 模拟 禁用账户 Windows 账户管理命令 dry_run 模拟 通知告警 生成通知文本 无风险

- 支持 手动确认模式 和 自动模式 （置信度 > 0.85 自动执行）
- 有"待确认队列"，用户可逐条审批
- 默认 dry_run=True ，不真正执行危险操作
### SecAgentX — 审批工作流（不执行真实操作）
actions.py 实现的是管理流程：

- 没有 真实的防火墙/账户操作能力
- 重心在 审批流程的可视化和记录 ，适合 SOC 团队协作场景
## 五、记忆与持续学习
### win10-security-agent — 双层记忆系统
AgentMemory 实现：

- 短期记忆 ：当前会话的事件和分析结果（内存）
- 长期记忆 ：持久化到 JSON 文件（ long_term_memory.json ）
每次分析完都会自动存储：

ReAct 引擎可以调用 search_similar_events 工具， 从历史记忆中检索相似事件 辅助分析。

### SecAgentX — 数据库持久化（无记忆检索）
- 所有分析结果存入 SQLAlchemy 数据库
- 没有 历史记忆检索功能
- 每次分析独立进行，不参考历史案例
## 六、自主运行能力
### win10-security-agent — 有自主调度器
AgentScheduler 实现了 全自动闭环 ：

用户可以 start / stop / pause / resume 调度器，不需要人工干预。

### SecAgentX — 纯手动触发
- 点击 "Analyze" 按钮才会触发流水线
- 没有 定时扫描或自动触发机制
- 适合"人在回路"的 SOC 工作模式
## 七、知识库差异
### win10-security-agent — 本地 RAG
- 使用 ChromaDB 向量数据库 + all-MiniLM-L6-v2 本地嵌入模型
- 预置了 windows_events_advanced.json 安全知识
- 分析时自动 检索相关知识 注入到 LLM prompt 中
- 解决大模型"幻觉"问题
### SecAgentX — 无 RAG
- 依赖 LLM 自身知识进行分析
- evidence_agent.py 模拟生成证据（防火墙日志、资产信息、IOC 匹配），但不是真实查询
## 八、UI 交互对比
### win10-security-agent — Gradio Tab 页
- 操作结果以 纯文本 展示（ gr.Textbox ）
- 所有数据在同一页面内
- 简洁直接，适合单人使用
### SecAgentX — React 工作台
- 左侧告警列表，右侧详情区
- 多 Tab 切换不同维度的信息
- AgentFlow 组件展示每个 Agent 的运行状态、耗时、输出
- 适合安全分析师逐条审查告警
## 九、总结对比表
维度 win10-security-agent SecAgentX 读取真实日志 ✅ Windows Event Log ❌ 手动输入 / 预置案例 RAG 知识增强 ✅ ChromaDB 本地向量库 ❌ 无 ReAct 自主推理 ✅ Thought-Action-Observation 循环 ❌ 固定流水线 CoT 思维链展示 ✅ 每步推理过程 ⚠️ 部分（Triage 的 reasoning） 攻击链分析 (MITRE) ❌ 无 ✅ AttackChain Agent 多 Agent 流水线 ❌ 单 Agent ✅ 6 个专职 Agent 真实系统处置 ✅ 封IP/隔离文件/禁用账户 ❌ 仅审批流程 自主定时扫描 ✅ AgentScheduler ❌ 手动触发 历史记忆检索 ✅ AgentMemory + 相似搜索 ❌ 仅数据库存储 多源系统采集 ✅ 进程/网络/服务/计划任务/注册表 ❌ 无 持久化数据库 ❌ JSON 文件 ✅ SQLAlchemy + SQLite 前后端分离 ❌ Gradio 单体 ✅ FastAPI + React 告警生命周期 ❌ 无 ✅ pending→analyzing→review→closed 多人协作审批 ❌ 单人使用 ✅ approve/reject 工作流 预置演练案例 ❌ 无 ✅ 5 个 Demo Case 报告输出 ✅ HTML + JSON（含图表） ✅ 数据库存储 + 前端展示

一句话概括 ：win10-security-agent 是一个"全栈自治型"安全 Agent（能看、能想、能动手），SecAgentX 是一个"分工协作型"安全工作台（流程规范、便于团队协作，但不直接操作系统）。两者在不同维度上各有优势，理论上可以互补。