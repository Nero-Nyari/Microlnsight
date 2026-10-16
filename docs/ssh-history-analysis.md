# SSH 历史归档的本地模型分析

工作台 `/reports` 已接入完整流程：选择归档、时区和起止分钟，核对数量与模型目的地后开始；可查看分批报告、原文、单批追问、导出和续跑。详情见 [本机使用说明](../Microlnsight/NATIVE_CLI.md#历史报告分析034)。原脚本报告也会从安装目录同级 `history-analysis/` 中发现。

引擎 `Microlnsight/history_analysis.py` 读取采集器 `raw/*.jsonl`，按日志时间筛选、按 journal cursor 去重，再将每条消息分批发送到指定 Ollama。源码中的 `scripts/analyze_ssh_history.py` 是兼容入口，依赖同仓库引擎，不再单独复制。发行包已包含引擎，可直接运行 `python history_analysis.py prepare/run ...`。它不依赖历史任务的 20 分钟窗口，也不排除旧解析器不认识的消息。

这不是对整台服务器安全状态的判断。采集开始前的日志、缺失归档、应用和数据库日志不在范围内；最早和最晚时间不能证明中间连续采集。记录的完整 `MESSAGE` 和时间、主机、进程、PID 会发送给模型，其余 journal 元数据保留在原始快照中。

## 准备（不调用模型）

使用 CLI 已安装的 Python 环境；输出目录必须是新目录。时间必须带时区，结束时间不包含在范围内。覆盖 16:35 整分钟时，结束时间写 16:36。

```bash
./.venv-cli/bin/python -X utf8 history_analysis.py prepare \
  --raw /home/aces/microlnsight/collector/raw \
  --output /home/aces/microlnsight/history-analysis/20261015-to-20261016-1635 \
  --source remote-ssh:47.109.68.29 \
  --start 2026-10-15T00:00:00+08:00 \
  --end 2026-10-16T16:36:00+08:00
```

检查 `manifest.json` 的实际覆盖范围、记录数、批次数及无效记录列表。单条消息超过批次大小时直接停止，不静默截断。

## 分批调用与续跑

确认目的地后运行；命令会发送真实日志中的账户、地址、主机名、密钥指纹等字段。

```bash
./.venv-cli/bin/python -X utf8 history_analysis.py run \
  --output /home/aces/microlnsight/history-analysis/20261015-to-20261016-1635 \
  --model-url http://192.168.0.105:11434 \
  --model qwen3.5:9b --allow-model-send
```

固定使用该目的地，不跟随重定向或使用环境代理，不切换云端。每批最多尝试两次；成功批次会缓存，重复执行只重试未成功批次。退出码 0 表示全部批次返回通过检查的回答，2 表示仍有失败批次。每次重新运行会对失败批次重新授予最多两次尝试。

若因输出长度或覆盖编号不完整而失败，该批会再拆成两个小批次，每个最多尝试两次。只有两份结果都覆盖各自全部输入，整批才算成功；原失败尝试及两份子批次回答全部保留，报告明确标注拼接。

- `snapshot.json`：带归档位置的完整原始快照。
- `evidence.json`、`inputs/`：完整消息与实际发送的批次。
- `results/`：逐批回答、引用、耗时、token 数及失败信息。
- `status.json`：已成功记录数、批次数和失败批次。
- `report.md`：本地程序统计，以及每批本地模型原文分析。

记录覆盖和引用检查只验证可机械检查的条件，不保证模型理解正确。模型结果须人工核实，不执行其中的命令或处置建议。所有结果独立保存，不修改原始归档、定时任务或 CLI 历史数据库。
