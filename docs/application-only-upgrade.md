# 已安装现场的应用版本更新

`upgrade-application.sh` 用于已有完整数据库与配置的现场，仅切换已验证的应用发布包。它不会创建、执行或跳过数据库迁移。候选包中的全部 PostgreSQL、ClickHouse 迁移，必须已在现场迁移账本中执行且校验值完全一致；缺失或修改迁移时立即拒绝。需要数据库升级时使用原完整安装器及备份流程。

发布前在现场隔离数据库回放候选版本，完成 Go 与前端验收。用 `build-release.sh` 构建 Linux amd64 发布包；发布清单记录 Git 版本和工作区是否含未提交改动，包外和包内均有 SHA256 校验。

```bash
scripts/deploy/build-release.sh --version VERSION --output proxy-sentinel-VERSION.tar.gz
```

将发布包、`.sha256`、`upgrade-application.sh` 与 `verify-applied-migrations.py` 放入现场同一暂存目录，执行：

```bash
bash upgrade-application.sh --version VERSION \
  --archive proxy-sentinel-VERSION.tar.gz \
  --checksum proxy-sentinel-VERSION.tar.gz.sha256
```

更新脚本持有安装锁，验证包成员路径、逐文件校验、平台和版本，以及两套数据库的已应用迁移。确认通过后保留原发布目录，原子切换 `current`，重启当前启用的常驻应用服务，再检查所有服务和 `/readyz`。失败时切回原目录并重启应用；成功时原版本记入 `previous`。业务数据库不参与切换，也不需要在空间不足的根盘复制一份完整数据库。

该流程沿用已有 systemd 单元与现场配置。需要更改采集器启动、可信来源登记或运行参数时，另存一份对应配置与单元备份，并单独验证重启后的采集。不要把未验证的新配置当成程序回退即可自动恢复的内容。

回退前确认 `previous` 对应受测版本，并检查附加配置的兼容性。`proxy-sentinelctl rollback` 会切换链接并重启启用的控制面、入库、风险、设备、读模型、识别和发现服务。数据库迁移不会反向执行。
