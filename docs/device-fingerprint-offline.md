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

离线包 v4 包含 IEEE MA-L/MA-M/MA-S、固定提交版本的 uap-core、Fingerbank 公开历史快照、NextDNS 八类原生跟踪域名、HaGeZi 六类厂商清单、Apple 设备服务规则、品牌别名和许可文件。NextDNS 数据采用 MIT 许可，只作为 Alexa、Apple、Huawei、Roku、Samsung、Sonos、Windows、Xiaomi 的“品牌生态线索”；访问相关服务不等于硬件品牌确认。Fingerbank 快照采用 ODbL/DbCL，仅作为 DHCP 辅助证据；其版本较旧，不代表新设备的完整覆盖率。

导入过程会校验文件白名单、规范路径、重复文件、压缩前后大小、SHA-256、四类上游与许可声明、规则格式和正则编译结果。验证全部通过后才原子切换版本；系统先通过 ClickHouse 游标回填最近 7 天域名证据，再以每批最多 500 台终端重算画像。PostgreSQL 按特征库版本持久化两段回填进度，服务中断或失败后会从游标恢复。当前版本及最近两个有效版本会保留，失败不会覆盖当前有效版本。


设备域名推测的门槛、来源审核、诊断、上线和回滚步骤见 [设备域名与推测品牌](device-brand-inference.md)。v1–v3 包仍可读取；v4 要求域名规则非空，并保留 HaGeZi GPL-3.0 许可及原始清单（`sources/hagezi.json`）。域名规则只用于画像推测，不增加风险分数或处罚动作。
