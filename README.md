# Microlnsight

Windows / Linux 本机日志采集与研判原型。当前包含本机 CLI，以及 FastAPI + React 工作台；支持核对原始证据、查看规则线索和导出报告，模型分析为可选功能。

## 从这里开始

| 目标 | 入口 |
| --- | --- |
| 安装 Windows / Linux 本机 CLI | [安装与使用说明](Microlnsight/NATIVE_CLI.md) · [下载发布包](https://github.com/Nero-Nyari/Microlnsight/releases) |
| 从源码启动 | [应用目录说明](Microlnsight/README.md) |
| 开发、运行测试、构建发行包 | [开发与仓库约定](CONTRIBUTING.md) |
| 使用网页工作台或演示 | [完整开发指南](docs/guides/workbench.md) · [三分钟演示](docs/guides/demo-walkthrough.md) |
| 查找项目资料和验收记录 | [文档索引](docs/README.md) |

## 仓库结构

```text
.
├── .github/workflows/      # 自动检查与 CLI 发布
├── docs/                  # 指南、项目说明、验收记录、历史方案
│   ├── guides/
│   ├── project/
│   ├── validation/
│   └── archive/
├── Microlnsight/            # 应用目录，启动与开发命令在这里执行
│   ├── agent.py            # 本机 CLI 入口
│   ├── NATIVE_CLI.md       # 随 CLI 发行包分发的安装说明
│   ├── backend/            # API、日志服务、Python 测试与合成样本
│   ├── frontend/           # React 工作台与前端测试
│   └── dev.py              # 环境检查、开发启动与测试入口
├── CONTRIBUTING.md        # 文件放置、开发验证与产物约定
└── LICENSE
```

项目名称为 [Microlnsight](https://github.com/Nero-Nyari/Microlnsight)。应用源码位于 `Microlnsight/`；旧版本的升级兼容与数据迁移步骤见 [0.3.0 名称迁移说明](docs/project/brand-migration.md)。克隆后进入应用目录：

```sh
git clone https://github.com/Nero-Nyari/Microlnsight.git
cd Microlnsight/Microlnsight
```

本机 CLI 需要 Python 3.10+；按平台执行安装与启动脚本。网页工作台还需要 Node.js，详细命令见上面的对应指南。

## 功能与验证边界

Windows 本机 CLI 读取 Security 日志，Linux 本机 CLI 读取 SSH journal；网页工作台还支持多个 Windows 通道及手动导入。本地规则从已分析的记录中寻找待核查线索，报告保留范围、原文依据与缺失信息。合成样本通过不等于真实检测能力完成验收，时间相邻也不证明因果关系。

CLI 处置为模拟，不修改真实防火墙；读取日志取决于运行账户权限，程序不会自动提权。数据库、真实日志、模型密钥、虚拟环境和构建产物保留在本机，不随仓库分发。历史验收及其日期见 [验收记录](docs/validation/windows-validation.md)。

许可证见 [LICENSE](LICENSE)。
