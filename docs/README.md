# 文档索引

本机 CLI 的安装说明保留在 [Microlnsight/NATIVE_CLI.md](../Microlnsight/NATIVE_CLI.md)，因为构建脚本会将它打进 Windows / Linux 发行包。其他项目文档集中在这里。

## 使用与开发

| 文档 | 内容 |
| --- | --- |
| [应用目录说明](../Microlnsight/README.md) | 本机 CLI 与网页工作台快速启动 |
| [本机 CLI 安装说明](../Microlnsight/NATIVE_CLI.md) | 安装、配置、更新与运行限制 |
| [完整开发与工作台指南](guides/workbench.md) | 开发环境、各 CLI 入口、服务器日志、演示与常见问题 |
| [网页使用说明](guides/user-manual.md) | 页面布局、导入、分析、模型和证据核对 |
| [三分钟演示](guides/demo-walkthrough.md) | 正常、单次失败、连续失败后成功的合成场景 |
| [开发与仓库约定](../CONTRIBUTING.md) | 文件归类、测试、发布和本地产物 |

## 项目与验证

| 文档 | 适用范围 |
| --- | --- |
| [项目说明](project/project-report.md) | 2026-10-03 工作台阶段的功能、边界和后续计划 |
| [0.3.0 名称迁移](project/brand-migration.md) | 新名称、旧版本升级、数据迁移和停机目录更名 |
| [Windows 验收记录](validation/windows-validation.md) | 按日期保留的验证证据与已知限制 |
| [固定回归样本](../Microlnsight/backend/tests/fixtures/README.md) | 合成测试输入与预期行为 |

验收记录中的测试数量和结论对应当时版本，不代表最新工作区已重新验收。

## 历史方案

以下资料用于追溯早期设计，不代表当前已实现能力：

- [早期项目对比](archive/project-comparison.md)
- [早期 Win10 安全智能体方案](archive/win10-security-agent.md)
- [早期 PPT 大纲](archive/ppt-outline.md)

## 旧路径对照

| 原路径 | 新路径（相对仓库根目录） |
| --- | --- |
| `WinSecAgent/README.md` 的完整指南 | `docs/guides/workbench.md`，原位置保留简明启动说明 |
| `WinSecAgent/docs/USER_MANUAL.md` | `docs/guides/user-manual.md` |
| `WinSecAgent/docs/demo-walkthrough.md` | `docs/guides/demo-walkthrough.md` |
| `WinSecAgent/docs/project-report.md` | `docs/project/project-report.md` |
| `WinSecAgent/docs/windows-validation.md` | `docs/validation/windows-validation.md` |
| `WinSecAgent/docs/project-comparison.md` | `docs/archive/project-comparison.md` |
| `WinSecAgent/docs/win10-security-agent.md` | `docs/archive/win10-security-agent.md` |
| `WinSecAgent/docs/ppt-outline.md` | `docs/archive/ppt-outline.md` |
