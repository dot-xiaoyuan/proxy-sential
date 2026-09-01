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

离线包包含 IEEE MA-L/MA-M/MA-S、固定提交版本的 uap-core、Fingerbank 公开历史快照、品牌别名和许可文件。Fingerbank 快照采用 ODbL/DbCL，仅作为 DHCP 辅助证据；其版本较旧，不代表新设备的完整覆盖率。

导入过程会校验文件白名单、大小、SHA-256、规则格式和正则编译结果。验证全部通过后才原子切换版本，并异步回填终端画像；失败不会覆盖当前有效版本。
