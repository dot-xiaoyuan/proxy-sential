# 设备特征库离线更新

30 机器默认使用离线模式，不主动访问 IEEE、GitHub 或 Fingerbank，也不会上传现场 MAC、UA、DHCP 或主机名。

在可联网开发机生成并校验离线包：

```bash
scripts/device-fingerprint/build-offline-bundle.sh /tmp/device-fingerprint-bundle.tar.gz
```

管理员可以在“规则配置 → 设备特征库”上传该文件，也可以通过 SSH 同步：

```bash
scripts/device-fingerprint/sync-offline-bundle.sh root@192.168.0.30 /tmp/device-fingerprint-bundle.tar.gz
```

脚本会在本地隐藏读取管理员密码，登录目标机回环地址上的控制面后携带会话与 CSRF 令牌导入；密码不会写入命令行、Shell 历史或普通日志。管理员账号不是 `admin` 时设置 `PROXY_SENTINEL_ADMIN_USER`。无人值守环境可临时通过 `PROXY_SENTINEL_ADMIN_PASSWORD` 提供密码，脚本读取后会立即清除该变量。

离线包包含 IEEE MA-L/MA-M/MA-S、固定提交版本的 uap-core、Fingerbank 公开历史快照、品牌别名和许可文件。Fingerbank 快照采用 ODbL/DbCL，仅作为 DHCP 辅助证据；其版本较旧，不代表新设备的完整覆盖率。

导入过程会校验文件白名单、规范路径、重复文件、压缩前后大小、SHA-256、三类上游与许可声明、规则格式和正则编译结果。验证全部通过后才原子切换版本，并异步回填终端画像。PostgreSQL 按特征库版本持久化回填进度，每批最多 500 条且画像与进度同事务提交；服务中断或失败后再次导入同版本会从已完成批次恢复。当前版本及最近两个有效版本会保留，失败不会覆盖当前有效版本。
