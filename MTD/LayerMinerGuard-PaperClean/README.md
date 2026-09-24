# LayerMinerGuard-PaperClean

LayerMinerGuard-PaperClean 是一个面向服务器场景的人工启动型挖矿检测工具。它不会随系统自动启动，也不会自动处置进程；运行方式是由管理员手动启动检测进程，长期运行轻量扫描逻辑，在发现强可疑进程后，按需启动短窗口探针，并在证据链完整时输出终端告警和 JSON 告警。

## 系统形态

```text
人工启动
-> 长期运行
-> 轻量扫描进程
-> 发现强可疑进程
-> 按需启动短窗口探针
-> 确认挖矿后输出终端告警和 JSON 告警
```

## 快速使用

进入项目目录，并设置 `PYTHONPATH`：

```bash
cd ~/MTD/LayerMinerGuard-PaperClean || exit 1
export PYTHONPATH="$PWD:${PYTHONPATH}"
```

启动 live 检测。`live.yaml` 默认后台运行，命令返回后检测进程会继续实时监测；启动后会立即随机选择一个进程做一次短窗口流量探测，之后每隔半小时再随机探测一次，并将正常/异常结果写入 JSON。

```bash
sudo env PYTHONPATH="$PWD" python3 -u server_tool/bin/layerminerd.py \
  --config server_tool/config/live.yaml
```

后台运行信息：

```text
results/layerminerd.pid
results/layerminerd.log
```

如需前台调试，可加 `--foreground`：

```bash
sudo env PYTHONPATH="$PWD" python3 -u server_tool/bin/layerminerd.py \
  --config server_tool/config/live.yaml --foreground
```

查看检测状态：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml status
```

查看正式告警：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml alerts
```

查看观测记录：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml observations
```

查看 warning 摘要：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml warnings
```

清空历史输出：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml clear-all
```

停止后台检测：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml stop
```

如需同时清理可能残留的短窗口探针进程，可执行：

```bash
sudo pkill -TERM -f "plaintext_stratum_probe|tls_openssl_probe" 2>/dev/null || true
```

## 检测核心：证据链

LayerMinerGuard-PaperClean 的正式挖矿确认依赖四类证据：

| 证据 | 含义 |
|---|---|
| `compute` | 目标进程存在持续高 CPU 计算 |
| `job` | 目标进程收到矿池下发的 mining job |
| `submit` | 目标进程向矿池提交 share |
| `association` | submit 能与此前 job 形成关联 |

只有同时满足以下条件，系统才会输出正式确认挖矿结果：

```text
compute_evidence_present = true
job_marker_count > 0
submit_marker_count > 0
associated_submit_count > 0
```

满足以上证据链后，最终输出：

```text
confirmed_mining_live
```

这表示系统已经在 live 检测中正式确认目标进程存在挖矿行为。

## 输出说明

LayerMinerGuard-PaperClean 没有单独的“流量告警”文件。流量探针的结果会先写入观测记录；只有当流量证据与 CPU 计算证据组成完整证据链后，才会升级为正式 JSON 告警。

- 终端告警：检测进程运行期间会输出扫描摘要；确认挖矿时会打印 `MINING WARNING`。
- JSON 告警：正式确认挖矿后写入 `alerts.jsonl`，其中 `evidence` 字段包含 CPU 与流量证据汇总。
- 观测记录：短窗口探针的流量观测结果，写入 `observations/`，包括 `job_marker_count`、`submit_marker_count`、`associated_submit_count`、`visibility_mode` 和最终 `verdict`。
- warning 摘要：确认挖矿后的单行摘要，写入 `warnings.log`，方便快速查看 PID、进程名、证据数量和建议动作。

### 输出文件含义

| 输出 | 路径 | 含义 | 什么时候产生 |
|---|---|---|---|
| 候选状态 | `results/candidate_state.json` | CPU/网络初筛后的候选进程状态 | 每轮扫描后更新 |
| 观测记录 | `results/observations/*.json` | 探针看到的流量证据和判定结果 | 候选进程触发短窗口探针后产生 |
| 随机观测 | `results/random_observations/*.json` | 每半小时随机抽取一个进程探测，输出 `normal` 或 `abnormal` | 在线检测启动后按间隔产生 |
| 异常流量关联 | `results/traffic_alerts.jsonl` | 发现异常协议流量时输出进程、端点、证据和关联 ID | 看到 `job` 或 `submit` 等异常流量标记时产生 |
| 正式告警 | `results/alerts.jsonl` | 已确认挖矿的 JSON 告警 | 只有 `confirmed_mining_live` 时产生 |
| warning 摘要 | `results/warnings.log` | 已确认挖矿的单行可读摘要 | 正式告警产生时同步写入 |
| 后台日志 | `results/layerminerd.log` | 后台运行日志和扫描摘要 | 后台检测运行期间持续追加 |

### 观测记录字段

`observations/*.json` 是流量探针的主要输出。常用字段包括：

```text
verdict                         本次观测判定结果
confidence                      置信度
visibility_mode                 可见性模式，例如 plaintext/tls/fallback
visibility_boundary             未看到完整协议证据时的边界原因
evidence.compute_evidence_present    是否存在 CPU 计算证据
evidence.cpu_avg_percent             观测窗口内平均 CPU
evidence.job_marker_count            看到的 mining job 数量
evidence.submit_marker_count         看到的 submit/share 数量
evidence.associated_submit_count     能与 job 关联的 submit 数量
observation.actual_observe_duration_sec  实际观测时长
observation.early_confirmed             是否提前确认后停止探针
```

如果 `job/submit/association` 不完整，观测记录可能只是 `protocol_suspicious`、`fallback_suspicious` 或 `benign_or_unconfirmed`，不会写入正式告警。

### 异常流量关联记录

当探针看到异常协议流量标记，例如 mining job 或 submit/share，系统会额外写入异常流量关联记录：

```text
results/traffic_alerts.jsonl
```

该文件一行一条 JSON，可用于前端表格展示：

```text
timestamp              时间
server                 服务器
src_ip                 源 IP
dst_ip                 目标 IP
dst_port               目标端口
protocol               协议，例如 tcp/udp
pid                    进程 PID
process                进程名
level                  等级 high/medium
action                 建议动作
traffic_correlation_id 与 observation/alert 关联的 ID
evidence               job/submit/association 证据计数
links.observation_json 对应观测记录路径
links.formal_alert_jsonl 对应正式告警文件路径，如果有
```

注意：这里保存的是连接元数据和证据计数，不保存原始 payload、钱包、job_id、nonce、result 或 blob。

配置位置：

```yaml
traffic_alerts:
  enabled: true
  filename: traffic_alerts.jsonl
  save_endpoint_raw: true
  max_connections: 8
```

查看命令：

```bash
sudo env PYTHONPATH="$PWD" python3 server_tool/bin/lmgctl.py \
  --config server_tool/config/live.yaml traffic-alerts
```

### 随机观测记录

在线检测启动后，系统会按配置每半小时随机选择一个进程进行短窗口探测。该功能不改变原有候选筛选、证据链确认和正式告警规则；随机探测结果只写入单独 JSON 文件：

```text
results/random_observations/*.json
```

关键字段：

```text
record_type      periodic_random_observation
result           normal 或 abnormal
is_abnormal      true/false
pid              被随机探测的进程 PID
process_name     被随机探测的进程名
verdict          本次探测判定，例如 benign_or_unconfirmed / fallback_suspicious / confirmed_mining_live
evidence         CPU 与流量证据计数
note             说明该记录不影响正式告警策略
```

配置位置：

```yaml
random_observer:
  enabled: true
  interval_sec: 1800
  run_at_start: true
  probe_duration_sec: 300
  probe_timeout_sec: 360
  retention_keep_days: 30
  retention_trigger_days: 40
```

保留策略：随机观测记录默认保留最近 30 天。当目录中最老记录达到 40 天时，系统会自动删除 30 天以前的记录，也就是在稳定运行时清掉最老 10 天记录。

时间说明：后台日志 `layerminerd.log` 面向人工查看，默认显示 `Asia/Shanghai` 时间；JSON 记录中的 `timestamp` 使用带时区的 UTC 时间，便于程序排序、跨机器关联和审计。

### warning 摘要格式

`warnings.log` 只在正式确认挖矿后写入，一行一个摘要，格式类似：

```text
时间 verdict=confirmed_mining_live severity=high pid=1234 process=xmrig user=xxx visibility=plaintext job=1 submit=1 assoc=1 action=inspect_or_stop_process alert_json=/var/log/layerminer/alerts.jsonl
```

它是给人快速看的摘要，不保存原始流量、钱包、job_id、nonce、result 或 blob。

默认主输出位置：

```text
/var/log/layerminer/alerts.jsonl
/var/log/layerminer/warnings.log
/var/lib/layerminer/candidate_state.json
/var/lib/layerminer/observations/
```

同时，以上结果会同步写入项目目录下的 `results/`：

```text
results/alerts.jsonl
results/warnings.log
results/candidate_state.json
results/observations/
results/random_observations/
results/traffic_alerts.jsonl
results/layerminerd.pid
results/layerminerd.log
```

更多服务端配置、判定等级和隐私边界说明见 `server_tool/README_SERVER.md`。
