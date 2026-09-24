# MTD Linux 检测代理

该代理部署在被监控 Linux 服务器，由 Windows 客户端通过 SSH 调用。标准输出的最后一行始终为通信协议 JSON。

## 安装

```bash
sudo apt install python3 python3-venv iproute2 yara
sudo bash install.sh
```

为 `monitor` 用户配置仅允许公钥认证的 SSH 登录，然后校验并安装最小化 sudo 规则：

```bash
sudo visudo -cf sudoers.d/mtd-monitor
sudo install -m 0440 sudoers.d/mtd-monitor /etc/sudoers.d/mtd-monitor
```

## 验证

```bash
/opt/miner_detector/.venv/bin/python /opt/miner_detector/detector.py --mode=quick --server-id=test-01
/opt/miner_detector/.venv/bin/python /opt/miner_detector/detector.py --mode=full --server-id=test-01
```

## 安全原则

- 检测用户不授予通用 `sudo` 或 shell 权限。
- 处置脚本对 PID、IP 和文件路径再次校验，并记录独立审计日志。
- 自动处置默认关闭，高风险操作由客户端二次确认。
- 生产环境必须在客户端固定 SSH 主机 SHA-256 指纹。
