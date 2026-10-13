# 开发与仓库约定

项目名称统一使用 **Microlnsight**。0.3.0 使用新发行包、环境变量、数据库和知识库名称；旧安装包及环境变量仅作为升级兼容入口。当前源码目录已更名为 `Microlnsight/`，已有部署的迁移步骤见 [名称迁移说明](docs/project/brand-migration.md)。

## 目录与入口

仓库根目录保存项目导航、协作约定、许可证和 `.github/workflows/`。应用代码位于 `Microlnsight/`；下文命令除特别说明外，均在这个应用目录执行。

CLI 模块目前保留在应用目录，启动脚本、导入路径、更新清单和发布白名单依赖这一布局。调整这些模块的位置时，需要同时检查导入、测试、更新和两个平台的发行包。Python 测试目前集中在 `backend/tests/`，其中也包含独立 CLI 的测试。

## 新文件放在哪里

| 内容 | 位置（相对仓库根目录） |
| --- | --- |
| 本机 CLI 与共享日志逻辑 | `Microlnsight/` 下对应模块 |
| API、后端服务和数据模型 | `Microlnsight/backend/app/` |
| Python 测试和合成样本 | `Microlnsight/backend/tests/`、其下 `fixtures/` |
| 页面、组件和前端测试 | `Microlnsight/frontend/src/`、`Microlnsight/frontend/tests/` |
| 操作、开发与演示指南 | `docs/guides/` |
| 项目说明与设计决策 | `docs/project/` |
| 带日期的验证结果与限制 | `docs/validation/` |
| 已被替代的方案和演示材料 | `docs/archive/`，保留历史说明 |
| 本机报告、截图与临时验证文件 | `outputs/<任务名>-<YYYYMMDD>/`，不提交 Git |
| 默认 CLI 发行包 | `outputs/cli-releases/`，不提交 Git |

新增正式文档时更新 [文档索引](docs/README.md)。仓库 README 负责导航，应用 README 负责快速启动；详细说明放进相应指南。`Microlnsight/NATIVE_CLI.md` 是随发行包提供的文档，保留原位。

## 安装与验证

首次安装见 [应用说明](Microlnsight/README.md)。Windows 网页工作台环境检查：

```powershell
python dev.py check
```

完整 Python 测试、前端测试与构建：

```powershell
python dev.py test
npm --prefix frontend test
npm --prefix frontend run build
```

仅验证独立 CLI 时，使用已安装 CLI 依赖的 Python；以下也是 CI 中的专门检查：

```sh
python -X utf8 -m unittest discover -s backend/tests -p test_guard.py -v
python -X utf8 -m unittest discover -s backend/tests -p test_native_cli.py -v
python -X utf8 -m unittest discover -s backend/tests -p test_cli_update.py -v
python -X utf8 -m unittest discover -s backend/tests -p test_terminal_ui.py -v
```

仅修改文档时，核对相对链接、文中的工作目录以及 `git diff --check` 即可。不要把历史验收记录里的测试数量当作本次运行结果。

## 构建与本地产物

```sh
python build_cli_releases.py
```

默认生成仓库根目录 `outputs/cli-releases/` 下的 Microlnsight Windows ZIP、Linux tar.gz、两个旧名称过渡包和校验清单。过渡包与新包的程序内容相同；移除它们会阻止旧更新器直接升级。发布工作流使用根目录 `release-assets/`。新增发行文件需要同步审查构建白名单及更新器的允许清单。

运行数据保留在既有位置：本机 CLI 默认使用 `Microlnsight/data/`，网页与数据库工作台使用 `Microlnsight/backend/data/`。示例配置 `backend/data/models.example.json` 受版本控制；真实配置、密钥、数据库和采集日志不提交。旧的 `Microlnsight/outputs/` 属于本地产物目录，新建人工整理产物统一放根目录 `outputs/`。

提交前检查 `git status --short` 和 `git diff --check`，只纳入本次修改。虚拟环境、依赖目录、缓存和运行数据由 `.gitignore` 排除；不要将真实日志复制进测试样本。
