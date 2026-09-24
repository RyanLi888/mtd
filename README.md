# MTD 挖矿流量检测管理系统

MTD（Mining Traffic Detection）用于集中查看 Linux 主机上的挖矿检测结果，并提供流量记录、检测规则、科研成果及系统权限管理。项目包含 Windows 桌面客户端、Java 管理后端、Vue 管理界面和 Linux 检测工具。

当前远程检测的主要流程是：**Linux 工具独立运行并生成结果 → Windows 客户端通过 SSH / SFTP 读取结果 → 界面展示进程候选、流量告警和随机观测**。界面中的“获取全部结果”刷新远端文件，不会启动探针或自动终止进程。浏览器可以使用管理后台，但 SSH 功能依赖 Electron，只在桌面客户端中可用。

本文件统一维护整个仓库的项目说明、启动方法、配置、检测原理与验证方式。

## 1. 功能与边界

| 功能 | 当前实现 |
| --- | --- |
| 检测仪表盘 | 汇总服务器状态、候选进程、流量告警和随机探测结果 |
| 服务器管理 | SSH 地址、端口、认证方式、主机指纹、结果路径及刷新周期 |
| 进程监测 | 展示 PID、命中次数、时间、进程标识和筛选原因 |
| 流量告警 | 读取 JSON / JSONL，展示端点、协议、关联进程和等级 |
| 随机探测 | 查看独立随机观测，区分正常、异常和解析失败 |
| 流量记录管理 | 查询、新增、编辑、删除、Excel 导入导出 |
| 检测规则与科研成果 | 维护数据库中的规则内容、成果内容及时间等信息 |
| 系统管理 | 用户、角色、菜单、部门、岗位、字典、参数和通知公告 |
| 运维与开发 | 操作日志、登录日志、在线用户、缓存、服务信息、定时任务、Swagger、代码生成、表单构建 |
| 人工处置接口 | 受限 IPC 调用固定脚本，支持终止进程、封禁 IP、隔离文件，必须传入确认标志 |

远端检测结果和 Java 数据库中的业务记录属于不同的数据通道：客户端读取的告警保存在当前进程的内存中，不会自动写入 `malicious_traffic` 或 `research_result`。数据库检测规则也不会自动下发给 Linux 探针；检测行为由 Linux 配置和代码决定。处置接口已保留，但不代表所有页面都已接入相应操作。

## 2. 架构

```text
Windows 桌面客户端
├── Vue 2 + Element UI：登录、管理页面、远程结果展示
├── Electron 预加载脚本：向页面暴露受限 IPC 接口
├── Electron 主进程
│   ├── 启动和关闭本地 Java 服务
│   ├── 保存服务器配置、加密 SSH 密码
│   └── SSH 心跳、重连、结果轮询、SFTP 读取
└── Spring Boot：账号、权限、业务 CRUD、日志和调度
    ├── desktop 配置：H2 文件数据库 + 进程内缓存
    └── druid 配置：MySQL + Redis，供独立 Web 部署使用

Electron ── SSH / SFTP ── Linux 被监测主机
                         ├── LayerMinerGuard：扫描 → 探针 → 证据链判断
                         │   └── results/：候选、观测、流量、正式告警
                         └── mtd-agent：可选的单次检测和人工处置脚本
```

两套 Linux 组件用途不同，均保留源码：

- `MTD/LayerMinerGuard-PaperClean` 生成当前桌面界面读取的结果，包含持续扫描、eBPF / BCC 探针、协议证据关联及测试。
- `mtd-agent` 提供轻量检测命令和处置脚本。`detector.py` 输出单次 JSON，不生成 LayerMinerGuard 的 `results/` 文件树。仅安装它不能让当前监测页面获得完整数据。

## 3. 技术栈与环境

| 部分 | 仓库使用的技术 |
| --- | --- |
| 后端 | Java 17、Spring Boot 2.5.15、Spring Security 5.7.12、MyBatis、JWT、Druid、Quartz |
| 前端 | Vue 2.6.12、Vue CLI 4.4.6、Element UI 2.15.14、Vue Router、Vuex、Axios、ECharts |
| 桌面端 | Electron 31、ssh2、electron-builder 25、Windows x64 NSIS 安装包 |
| 桌面存储 | H2 2.2.224、进程内缓存、`mtd-client.json` |
| 独立 Web 存储 | MySQL、Redis |
| Linux 工具 | Python 3.10+、psutil、PyYAML；真实协议探针需要 Linux BCC / eBPF 环境 |
| 构建与验证 | Maven、Node.js / npm、pytest |

从源码开发 Windows 客户端需要 JDK 17、Maven 和 Node.js / npm，准备安装包还需要 JDK 自带的 `jlink`。安装包包含精简 Java 运行时，最终用户无需另装 Java、MySQL 或 Redis。

前端使用 Vue CLI 4 / webpack 4。较新 Node.js 如报 `ERR_OSSL_EVP_UNSUPPORTED`，可仅在当前构建终端设置 `$env:NODE_OPTIONS = '--openssl-legacy-provider'` 后重试。

## 4. 目录结构

```text
mtd/
├── pom.xml                      Maven 聚合工程及依赖版本
├── mtd-admin/                   Spring Boot 入口、Web 控制器、运行配置
├── mtd-common/                  通用模型、工具、注解、缓存封装
├── mtd-framework/               认证授权、过滤器、数据源、H2 初始化
├── mtd-system/                  用户、角色、菜单等系统业务
├── mtd-detector/                流量、检测规则、科研成果业务
├── mtd-generator/               数据表代码生成和模板
├── mtd-quartz/                  定时任务管理和执行
├── mtd-ui/                      Vue 界面
│   ├── src/views/remote/        仪表盘、服务器、进程、告警、随机观测
│   ├── src/api/desktop.js       Electron 桥接接口
│   └── vue.config.js           构建、开发服务器及代理
├── mtd-desktop/
│   ├── src/main/               主进程、SSH、结果处理、配置和静态服务
│   ├── src/preload/            IPC 桥接
│   ├── scripts/                Windows 打包资源准备脚本
│   └── build/                  安装包图标源资源
├── mtd-agent/                   单次检测、YARA 规则、处置和安装脚本
├── MTD/LayerMinerGuard-PaperClean/
│   ├── layerminer/             证据结构、关联与判定
│   ├── probes/                 明文 Stratum、OpenSSL TLS 探针及 I/O 审计
│   ├── server_tool/            持续检测、配置、控制命令和服务安装
│   ├── scripts/                实验会话与烟雾验证入口
│   ├── workloads/              本地明文 / TLS 模拟矿池
│   └── tests/                  检测、隐私、协议和清理测试
├── sql/                        系统、Quartz 和检测业务初始化 SQL
├── bin/                        Windows Maven / 启动辅助脚本
├── mtd.bat / mtd.sh             后端启动管理脚本
├── LICENSE                     MIT 许可证及原始版权声明
└── README.md                   统一项目说明
```

`target/`、`node_modules/`、`dist/`、桌面端 `release/` 和 `resources/generated/` 是可再生成产物，不提交到 Git。临时数据库、Python 缓存、PID 文件及 LayerMinerGuard 的 `results/` 也已忽略；运行时按需要创建结果目录。

## 5. Windows 桌面端开发

以下 PowerShell 命令从仓库根目录开始执行。

### 5.1 构建后端

```powershell
java -version
mvn -version
mvn clean install -DskipTests
```

主程序生成在 `mtd-admin/target/mtd-admin.jar`。首次初始化所需的三个 SQL 文件作为 `db/` 资源打入 JAR。

### 5.2 启动前端开发服务

在第一个终端执行：

```powershell
cd mtd-ui
npm install
$env:MTD_BACKEND_URL = 'http://127.0.0.1:18080'
npm run dev
```

前端默认监听 `80` 端口。`MTD_BACKEND_URL` 控制 `/dev-api` 代理目标，桌面开发时需指向 Electron 启动的 `18080`。

### 5.3 启动 Electron

在仓库根目录打开第二个终端：

```powershell
cd mtd-desktop
npm ci
npm run dev
```

Electron 加载 `http://localhost:80`，以 `desktop` 配置启动 Java 后端，随后轮询启用的服务器。开发机器需能通过 `JAVA_HOME` 或 `PATH` 找到 Java。

如果前端换了端口，可设置 `$env:MTD_UI_URL = 'http://localhost:你的端口'`，再执行 `npm start`。若自行运行桌面配置后端，可设置 `MTD_SKIP_BACKEND=true` 跳过自动启动，此时仍需自行保证接口地址和配置一致。

### 5.4 登录与持久化

初始化管理员为 `admin`，密码为 `admin123`，首次登录后修改密码。

数据根目录由 Electron 的 `app.getPath('userData')` 决定，位于当前 Windows 用户的应用数据目录，具体应用目录名以实际安装版本为准：

| 相对位置 | 内容 |
| --- | --- |
| `database/mtd.mv.db` | H2 数据库，保存账号、角色和业务记录等 |
| `logs/` | 客户端预创建的日志目录；实际文件日志路径见下文 |
| `files/` | 上传文件 |
| `mtd-client.json` | SSH 配置、加密后的密码、客户端设置 |

数据库首次运行自动初始化，后续检测到 `sys_user` 表即跳过初始化；这不是数据库自动迁移机制。备份前应关闭客户端，再备份整个数据目录。进程内缓存及当前读取的远程结果随退出释放，重启后重新登录和读取。

当前 `logback.xml` 的文件 appender 将日志路径写为 `/home/mtd/logs`，并未引用桌面配置里的 `logging.file.name`。排查文件日志时需以该文件为准；部署时可按环境调整其 `log.path`，不能假定所有日志都已进入用户数据目录。

## 6. Windows 安装包

在 `mtd-desktop` 目录执行：

```powershell
npm ci
powershell -ExecutionPolicy Bypass -File scripts/prepare-resources.ps1 -JavaHome 'C:\Path\To\jdk-17'
npm run dist
```

资源准备脚本依次执行 Maven 构建、Vue 生产构建、资源复制和 `jlink`，生成 `resources/generated/` 下的 `backend/`、`ui/`、`runtime/`、`agent/`，分别保存 JAR、前端产物、精简 Java 和可选轻量代理。

安装程序输出为 `release/MTD-Setup-1.0.0-x64.exe`；`npm run pack` 生成未封装安装器的目录。安装包不会自动把 LayerMinerGuard 部署到远程主机。

正式客户端使用本机 `3090` 提供页面，将 `/prod-api` 转发至后端 `18080`。桌面图标与前端图标内容相同，但分别被两套独立打包流程引用，因此保留各自资源。

## 7. 独立 Web 管理端

此方式需要 MySQL 和 Redis。

1. 创建空的 `mtd` 数据库，在 MySQL 客户端按顺序导入 `sql/mtd_20250417.sql`、`sql/quartz.sql`、`sql/en_traffic.sql`。脚本含 `DROP TABLE`，用于新库初始化或明确需要重建的环境。
2. 修改 `application-druid.yml` 的数据库连接及 `application.yml` 的 Redis、上传路径、令牌密钥等配置，也可通过 Spring Boot 环境变量或参数覆盖。
3. 在根目录构建并启动后端：

```powershell
mvn clean package -DskipTests
java -jar mtd-admin/target/mtd-admin.jar --spring.profiles.active=druid
```

4. 在另一个终端启动前端：

```powershell
cd mtd-ui
npm install
$env:MTD_BACKEND_URL = 'http://localhost:8080'
npm run dev
```

默认访问 `http://localhost:80`，后端为 `http://localhost:8080`。业务菜单由后端权限接口返回；纯浏览器环境下，SSH 页面提示需要 Windows 客户端。

部署静态页面时执行 `npm run build:prod`，将 `dist/` 交给 Web 服务器。将 `/prod-api/` 转发给 Java 服务并去掉此前缀，同时为 Vue history 路由配置回退到 `index.html`。

### 关键配置入口

| 文件 / 参数 | 用途 |
| --- | --- |
| `mtd-admin/src/main/resources/application.yml` | 端口、Redis、上传路径、JWT、Swagger、MyBatis |
| `application-druid.yml` | MySQL 和 Druid 连接池 |
| `application-desktop.yml` | H2、桌面开关、进程内缓存和日志 |
| `mtd-ui/.env.development` / `.env.production` | `/dev-api` / `/prod-api` 前缀 |
| `MTD_BACKEND_URL` | 开发代理目标，默认 `http://localhost:8080` |
| `MTD_UI_URL` | Electron 加载的开发页面地址 |
| `MTD_SKIP_BACKEND` | `true` 时跳过 Electron 自动启动后端 |

后端主要接口前缀包括 `/login`、`/getInfo`、`/getRouters`、`/system/*`、`/monitor/*`、`/tool/gen/*` 和 `/detector/*`。权限以各控制器的 `@PreAuthorize` 为准。

## 8. Linux 持续检测：LayerMinerGuard

### 8.1 环境与启动

在 Linux 上部署 `MTD/LayerMinerGuard-PaperClean` 完整目录。需要 Python 3.10+、psutil、PyYAML；真实探针还需要适配当前内核的 BCC / eBPF 环境和相应权限。按发行版提供的方法安装 BCC，并确认实际运行的 Python 能执行 `from bcc import BPF`。普通 Python 依赖安装成功不代表探针环境已就绪。

从该目录运行无真实探针的单轮扫描：

```bash
python3 server_tool/bin/layerminerd.py --config server_tool/config/server.yaml --once
```

`server.yaml` 默认是 dry-run。实时检测使用 `live.yaml`，需要提升权限；以下命令也在 LayerMinerGuard 根目录执行：

```bash
sudo env PYTHONPATH="$PWD" python3 -u server_tool/bin/layerminerd.py \
  --config server_tool/config/live.yaml
```

实时配置默认后台运行；前台调试追加 `--foreground`。工具由管理员手动启动，不自动处置进程。

可选的 `server_tool/packaging/install.sh` 将项目复制到 `/opt/layerminer`，配置放到 `/etc/layerminer/server.yaml` 并安装 systemd 单元，但不会启动或启用开机自启。该配置仍为 dry-run。若让 systemd 管理实时配置，需要关闭配置中的后台化，让进程保持前台运行。

### 8.2 检测证据链

持续扫描根据 CPU、运行时长、网络活动及白名单选出候选进程，再启动短窗口探针。当前实时配置每 10 秒扫描一次，候选 CPU 阈值为 70%，至少连续命中 2 次；探针窗口为 300 秒，并发观测数为 1，冷却时间为 600 秒。具体筛选与调度行为以配置及代码为准。

| 证据 | 含义 |
| --- | --- |
| compute | 观测窗口中存在 CPU 计算证据 |
| job | 观察到矿池下发任务标记 |
| submit | 观察到提交 share 的标记 |
| association | 提交能够与任务关联 |

正式确认要求计算证据成立，且 job、submit 和关联计数均大于零；满足条件时可提前结束探针。

| 判定 | 解释 |
| --- | --- |
| `confirmed_mining_live` | 证据链完整，默认产生正式告警 |
| `protocol_suspicious` | 协议可疑，但提交或关联证据不完整 |
| `fallback_suspicious` | 存在计算证据，协议可见性不足 |
| `benign_or_unconfirmed` | 当前证据不足以确认 |

明文探针分析 Stratum 标记，TLS 探针依赖进程中的动态 OpenSSL 映射。静态链接 OpenSSL、无法挂载的 TLS 实现或观测窗口不完整，可能只能得到可疑或未确认结果。需结合 `visibility_mode`、`visibility_boundary` 和证据计数判断。

### 8.3 输出与随机观测

| 项目内路径 | 内容 |
| --- | --- |
| `results/candidate_state.json` | 候选进程状态，每轮扫描更新 |
| `results/observations/*.json` | 按需探针观测、证据计数和判定 |
| `results/traffic_alerts.jsonl` | 异常协议流量与进程、端点的关联记录 |
| `results/alerts.jsonl` | 完整证据链确认后的正式告警 |
| `results/warnings.log` | 正式告警的可读摘要 |
| `results/random_observations/*.json` | 独立随机观测结果 |
| `results/layerminerd.pid` / `layerminerd.log` | 后台进程标识及运行日志 |

日志和状态默认也写入 `/var/log/layerminer`、`/var/lib/layerminer`，项目内 `results/` 提供镜像。没有发生对应事件时，告警文件可能尚未创建；“文件不存在”和“文件存在但没有告警”需要区分。

随机观测在启动时执行一次，此后每 1800 秒一次，单独输出 `normal` / `abnormal`，不改变正式告警策略。默认保留最近 30 天，最老记录达到 40 天时触发清理。日志显示时区为 `Asia/Shanghai`，JSON 使用带时区的 UTC。

记录保留证据计数及必要元数据，不持久化原始协议载荷、钱包、job ID、nonce、result 或 blob。流量关联配置 `save_endpoint_raw: true` 会保存原始端点 IP / 端口，它与其他隐私开关分别控制。

### 8.4 控制命令

```bash
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml status
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml alerts
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml traffic-alerts
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml observations
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml warnings
sudo python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml stop
```

读取命令需要文件权限，停止命令需要操作目标进程的权限。`clear-alerts`、`clear-state`、`clear-warnings`、`clear-observations`、`clear-all` 用于清理历史输出，执行前确认不再需要对应记录。

## 9. 将 Linux 结果接入桌面端

在“远程检测 → 服务器管理”配置：

| 配置项 | 示例 / 说明 |
| --- | --- |
| 主机和端口 | Linux 地址、SSH 端口，默认 22 |
| 用户 | 有权限读取结果文件的 SSH 用户 |
| 认证 | 私钥文件或密码；密码由 Electron 系统安全存储加密 |
| 项目路径 | Linux 上的 LayerMinerGuard 绝对路径，例如 `/opt/layerminer` |
| 进程候选状态文件 | `results/candidate_state.json` |
| 流量告警文件 | 查看异常端点关联时填 `results/traffic_alerts.jsonl` |
| 随机探测目录 | `results/random_observations` |
| 刷新周期 | 单位为秒，默认 5，可设置 2–300 |
| 主机指纹 | 当前实现直接比较 ssh2 的 SHA-256 十六进制摘要 |

项目路径和结果相对路径会拼接成最终路径。客户端历史默认项目路径是 `/opt/miner_detector`，默认告警文件是 `results/alerts.jsonl`，接入时要按实际部署修改，尤其要区分正式告警与异常流量关联文件。

当前指纹输入不是 OpenSSH 常见的 `SHA256:...` Base64 显示格式。可在可信服务器控制台获取对应主机公钥的十六进制摘要，例如 Ed25519 公钥：

```bash
awk '{print $2}' /etc/ssh/ssh_host_ed25519_key.pub | base64 -d | sha256sum
```

填写输出的 64 位十六进制摘要，必须与 SSH 实际协商的主机密钥匹配。未填指纹时默认拒绝连接，只有显式允许未验证主机才会跳过验证。

JSON / JSONL 命令输出限制为 2 MiB；随机观测目录每次读取按修改时间排序的最近 200 个 JSON 文件。遇到解析失败时检查原文件格式和大小。实时探针的高权限运行与客户端的只读 SSH 账号应分别配置。

## 10. 可选轻量代理与人工处置

`mtd-agent/detector.py` 根据进程名称、CPU 和可疑端口评分，`full` 模式还调用 YARA 检查进程可执行文件。它是启发式报告，不等同于完整协议证据确认。

在 Linux 的 `mtd-agent` 目录安装：

```bash
sudo apt install python3 python3-venv iproute2 yara
sudo bash install.sh
/opt/miner_detector/.venv/bin/python /opt/miner_detector/detector.py --mode=quick --server-id=test-01
/opt/miner_detector/.venv/bin/python /opt/miner_detector/detector.py --mode=full --server-id=test-01
```

默认安装目录为 `/opt/miner_detector`，用户为 `monitor`，可用 `MTD_INSTALL_DIR`、`MTD_MONITOR_USER` 覆盖。处置脚本和 sudoers 仍有默认绝对路径，自定义安装时需要同步核对。

有效检测参数位于 `config/settings.yaml`：CPU 阈值、进程 CPU 阈值、采样时长和可疑端口。进程保护名单定义在 `detector.py`。命令最后一行输出包含 `status`、`timestamp`、`server_id`、`result`、`error_msg` 的 JSON。

| 脚本 | 行为 |
| --- | --- |
| `remediate_kill.sh` | 校验 PID 和受保护进程，先 TERM，必要时 KILL |
| `remediate_ip.sh` | 校验地址后通过 iptables 添加出站封禁 |
| `remediate_isolate.sh` | 校验普通文件及系统路径后移入隔离目录 |

这些脚本不是检测所必需的。启用 sudo 处置前，应让脚本及其父目录由 root 控制，防止调用者改写被提权执行的脚本；安装脚本默认将安装树交给 monitor，因此管理员需要调整这部分权限。按实际账号和路径审查 `sudoers.d/mtd-monitor`，通过 `visudo -cf` 校验后再安装。审计记录写入 `/var/log/miner_detector_response.log`。

## 11. 验证与维护

### 构建检查

```powershell
# 仓库根目录
mvn clean verify

# 前端
cd mtd-ui
npm run build:prod
```

当前 Java 模块没有单独的测试源码，Maven 成功主要验证编译、资源和打包，不代表接口集成测试全部通过。

### Python 检查

在 LayerMinerGuard 根目录执行：

```bash
python3 -m pytest tests server_tool/tests -q
```

测试依赖 pytest、psutil、PyYAML，覆盖证据链、隐私、无标签泄漏、候选状态、观测调度、告警策略、模拟观测和进程清理。部分测试需要 Linux 的 `/proc`、进程组、`sleep` 等能力，Windows 不能替代完整 Linux 验证；真实 eBPF 探针需在有 BCC 和权限的 Linux 上单独验证。

本次整理在 Windows、JDK 17、Node.js 22、Python 3.13 环境验证：Maven 构建和 Vue 生产构建通过，桌面结果解析、并发刷新、路径校验和处置确认检查通过；Python 测试为 235 项通过、19 项失败。失败涉及 `/proc`、`geteuid`、Linux 命令和权限模型等环境假设，尚未完成 Linux 上的完整测试及真实探针验证。前端构建仍有资源体积提示。

`scripts/run_plaintext_positive.py`、`run_tls_positive.py`、`run_real_pool_smoke.py`、`run_single_session.py` 是实验入口。执行前查看 `--help`，配置目标程序、证书和输出位置。这些实验不由普通构建自动执行；`workloads/` 的模拟矿池用于协议验证，属于有效测试资源。

### 常见问题

| 现象 | 排查位置 |
| --- | --- |
| 找不到后端 JAR | 先构建，确认 `mtd-admin/target/mtd-admin.jar` 存在 |
| 桌面开发登录失败 | 前端启动前将 `MTD_BACKEND_URL` 指向 `18080` |
| 本地服务启动失败 | 检查 JDK、18080 端口占用、控制台及 `logback.xml` 指定的日志目录 |
| 浏览器无法使用 SSH | 使用 Electron，浏览器没有预加载 IPC 接口 |
| SSH 成功但没有结果 | 检查 Linux 工具是否运行、结果路径和读取权限 |
| CPU 高但无正式告警 | 查看观测记录中的 job、submit、关联证据 |
| TLS 仅得到可疑结果 | 检查动态 libssl、探针权限、`visibility_boundary` |
| 编辑规则后远端行为未变 | 数据库规则不自动下发，需要维护 Linux 配置 |

本次整理移除历史运行快照和测试数据库、旧统计演示首页、无引用素材、随机模拟上报脚本、课程示例 SQL、Swagger 示例测试接口及注释配置；保留实际业务、检测实验、测试和独立引用的图标。后续说明统一维护在本 README。

## 12. 来源与许可证

项目采用 [MIT License](LICENSE)，保留原始开源代码版权声明。管理后台基于原有开源框架进行 MTD 业务定制，LayerMinerGuard 子目录保留检测框架、探针、实验入口和测试。

LayerMinerGuard 历史迁移关系：旧 `l1_scorer.py` / `l3_confirmer.py` 合并到 `layerminer/detector.py`，`l2_analyzer.py` 对应 `evidence_chain.py`，`event_schema.py` 对应 `schema.py`，旧 BCC Stratum / TLS 原型对应当前 `probes/`。旧阶段实验结果和未迁移设想不属于当前实现能力。
