# MTD 挖矿流量检测管理系统

MTD（Mining Traffic Detection）是一套面向挖矿流量分析、威胁研判和安全运营的 Windows 桌面检测系统。Windows 客户端通过 SSH 安全通道调度部署在 Linux 服务器上的检测代理，聚合展示检测结果，并在人工二次确认后执行受控处置。

## 总体架构

```text
Windows 客户端
├─ Electron 主进程：SSH、心跳、重连、任务调度、安全处置
├─ Vue 界面：仪表盘、服务器管理、告警和检测报告
├─ Spring Boot 本地服务：账号、权限及全部 Web 业务接口
└─ H2 文件数据库 / 本地缓存：免安装、自动初始化、持久化数据
                 │
                 └──── SSH 安全通道 ──── Linux 检测代理
                                           ├─ CPU / 进程采集
                                           ├─ 网络连接分析
                                           ├─ Yara 完整检测
                                           └─ 白名单处置脚本
```

## 核心能力

- 流量管理：查询、维护和导出网络流量检测记录。
- 远程检测：通过 SSH 对一台或多台 Linux 服务器执行快速或完整检测。
- 实时监控：心跳保活、断线指数退避重连、周期检测和流式日志通道。
- 告警响应：展示统一 JSON 报告，二次确认后终止进程、封禁 IP 或隔离文件。
- 规则管理：集中维护检测规则及其启停状态。
- 结果管理：归档检测与研究结果，便于复核和追踪。
- 权限管理：提供用户、角色、菜单和数据权限控制。
- 运行监控：覆盖在线用户、任务调度、日志、缓存和服务状态。
- 开发支持：包含接口文档、代码生成和表单构建工具。

## 技术栈

- 后端：Java 17、Spring Boot、Spring Security、MyBatis、JWT
- 前端：Vue 2、Element UI、Axios、ECharts
- 数据库：桌面端 H2（内置）；服务器部署可使用 MySQL、Redis
- 构建：Maven、npm

## 项目结构

```text
mtd-admin       应用入口与 Web 接口
mtd-common      通用模型、注解和工具
mtd-framework   安全、配置和基础设施
mtd-system      用户、角色、菜单等系统能力
mtd-detector    流量检测业务模块
mtd-generator   代码生成模块
mtd-quartz      定时任务模块
mtd-ui          前端管理界面
mtd-desktop     Electron Windows 客户端、SSH 与打包流程
mtd-agent       Linux 服务器检测代理和受控处置脚本
sql             数据库初始化脚本
```

## 本地启动

1. 创建 MySQL 数据库 `mtd`，导入 `sql/mtd_20250417.sql`、`sql/quartz.sql` 和业务 SQL。
2. 按本地环境调整 `mtd-admin/src/main/resources/application-druid.yml` 与 Redis 配置。
3. 启动后端：`mvn clean package -DskipTests`，然后运行 `mtd-admin` 模块。
4. 启动前端：进入 `mtd-ui`，执行 `npm install` 和 `npm run dev`。

默认开发地址：前端 `http://localhost:80`，后端 `http://localhost:8080`。

## Windows 客户端开发与打包

1. 启动 Vue 开发服务；Electron 会自动启动桌面配置的 Java 后端。
2. 进入 `mtd-desktop`，执行 `npm install`、`npm run dev`。
3. 发布前在 `mtd-desktop` 中执行 `powershell -ExecutionPolicy Bypass -File scripts/prepare-resources.ps1 -JavaHome "JDK 17 路径"`。
4. 执行 `npm run dist` 生成 Windows 安装包。

正式安装包无需另装 Java、MySQL 或 Redis。首次启动会自动建库，默认管理员账号为 `admin`、密码为 `admin123`；登录后应立即修改密码。业务数据库、日志和上传文件保存在 Electron 的 Windows 用户数据目录，升级应用不会覆盖这些数据。

Linux 检测代理的安装方式见 `mtd-agent/README.md`。

## 许可证与来源说明

本项目以 MIT License 发布。项目包含基于 MIT 许可修改的开源代码，原始版权声明保留在 `LICENSE` 中；当前项目的业务设计、品牌与后续修改归 MTD 项目维护者所有。
