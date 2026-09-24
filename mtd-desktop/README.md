# MTD Windows 客户端

Electron 主进程负责本地 Java 服务生命周期、SSH 连接、检测调度和安全处置；Vue 渲染进程只能通过预加载脚本暴露的受限接口调用这些能力。

客户端内置 Spring Boot、H2 文件数据库和本地缓存，不需要用户安装 MySQL、Redis 或 Java。用户、角色、菜单、日志、规则等数据保存在 Windows 用户数据目录；SSH 密码由 Windows 安全存储加密，服务器配置和检测告警保存在本地配置中。

桌面端启动时会先启动本地后端。首次运行自动创建数据库，随后进入与浏览器版一致的登录、权限和业务流程。初始管理员账号为 `admin`，密码为 `admin123`。

每台 SSH 服务器需要配置检测模型的项目绝对路径，以及项目内的结果位置：进程候选状态文件、流量告警文件和随机探测目录。默认分别为 `/opt/miner_detector/results/candidate_state.json`、`/opt/miner_detector/results/alerts.jsonl` 与 `/opt/miner_detector/results/random_observations`；客户端分别在进程监测、流量告警、随机探测界面展示这些只读结果，随机探测不参与正式告警策略。

## 开发启动

1. 在仓库根目录执行 `mvn clean install -DskipTests`。
2. 在 `mtd-ui` 执行 `npm run dev`。
3. 在本目录执行 `npm install` 和 `npm run dev`。

开发模式默认加载 `http://localhost:80`。Electron 会使用 `desktop` 配置启动 `mtd-admin/target/mtd-admin.jar`，本地后端端口为 `18080`。

## Windows 安装包

```powershell
npm install
powershell -ExecutionPolicy Bypass -File scripts/prepare-resources.ps1 -JavaHome "D:\Program Files\java\jdk-17.0.10"
npm run dist
```

安装包输出到 `release`。准备脚本会打包后端 JAR、初始化 SQL、Vue 生产产物和通过 `jlink` 生成的 Java 17 运行时。

## 安全约束

- SSH 密码使用 Windows 安全存储加密；推荐使用私钥认证。
- 默认要求配置服务器 SHA-256 主机指纹。
- 渲染进程不能执行任意 SSH 命令。
- 进程终止、IP 封禁和文件隔离必须二次确认，并只调用服务器端固定脚本。
