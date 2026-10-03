# Microlnsight
Microlnsight Server Security Log Monitoring and Analysis with Local Large Language Models

当前仓库包含 Windows 版本 **WinSecAgent**，基于 FastAPI、React 和可配置模型服务，支持 Windows 日志读取、证据追溯和联合分析。

## 当前功能

- 读取 Windows Security、System、Application、Defender 和 PowerShell 日志，支持粘贴文本、JSON、XML。
- 原始记录先进入日志列表，有证据支持的异常线索再形成告警。正常活动与证据不足均不会被直接描述为入侵。
- 本地规则按主机、账户、来源 IP 和时间窗口关联登录失败、登录成功和服务创建，展示次数、时间范围、相关原文及缺失证据。
- 支持配置本地或云端模型进行单条分析；本地联合规则不调用模型。导入不会自动上传日志到模型服务。
- 页面及 Markdown 报告复用统一研判结论，原始告警等级与分析后风险分别展示。

## 运行与验证

应用位于 [`WinSecAgent/`](WinSecAgent/)。

当前使用的远程仓库为 [Microlnsight](https://github.com/Nero-Nyari/Microlnsight)，应用名称为 WinSecAgent。

```powershell
git clone https://github.com/Nero-Nyari/Microlnsight.git
cd Microlnsight/WinSecAgent
```

安装与启动步骤见 [应用说明](WinSecAgent/README.md)。统一入口 `python dev.py start` 使用前端 5173、后端 8000；端口占用时明确报错，请先停止已有服务。

- [Windows 验收记录与测试命令](WinSecAgent/docs/windows-validation.md)
- [三分钟演示：正常、单次失败、连续失败后成功](WinSecAgent/docs/demo-walkthrough.md)
- [固定回归样本说明](WinSecAgent/backend/tests/fixtures/README.md)
- [许可证](LICENSE)

## 工作区结构与当前进度

- `WinSecAgent/backend/`：API、日志采集、关联规则及后端测试。
- `WinSecAgent/frontend/`：工作台、工具设置和来源切换测试。
- `WinSecAgent/docs/`：使用说明、演示流程与验收记录。
- `WinSecAgent/dev.py` / `start.bat`：统一检查、启动及后端测试入口。

截至 2026-10-03，用户手动验证已读到 Security 等五个日志通道，重启后网络连接、服务和计划任务列表可显示。计划任务状态和下次运行时间仍待完善。当前异常关联主要由合成样本验证；真实异常日志的采集、关联、证据核对和报告验证仍是下一阶段工作，不能将采集成功视为检测能力验收完成。

## 本地数据与权限

数据库、真实日志、模型密钥、`.env`、虚拟环境及构建产物不随仓库分发。`backend/data/models.example.json` 提供空配置示例，可启动后在模型管理界面添加模型。

Security 通道是否可读取取决于后端 Windows 账户权限。权限不足时只标记该通道，其他成功读取的记录仍可使用。应用不会自动提权；本地联合规则只提供核查建议，不执行封禁、隔离或删除。

本地规则及固定样本验证不等于真实环境的完整检测能力；时间相邻不证明因果关系，未发现线索也不代表整机安全。
