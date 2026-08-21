# 影子评估与每日人工复核

影子评估只读取标准风险快照、证据和人工标签，不执行降速、踢线或封禁。正式验收要求连续运行至少 7 天，并对每天实际出现的 `confirmed`、`high`、`suspicious`、`normal` 分桶进行人工复核。

## 每日自动产物

部署脚本会安装 `proxy-sentinel-shadow-evaluation.timer`，每小时第 5 分钟刷新；每日抽样文件按日期覆盖更新：

- `data/shadow/evaluation/latest.json`：当前窗口评估报告。
- `data/shadow/review-exports/YYYY-MM-DD-review-samples.json`：按风险等级分层抽样的复核清单。

手工执行方式：

```bash
proxy-sentinel evaluate shadow \
  --shadow-dir data/shadow \
  --required-days 7 \
  --samples-per-level 10 \
  --daily-export-dir data/shadow/review-exports \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --output data/shadow/evaluation/latest.json
```

加上 `--strict` 后，只要连续运行天数、每日复核覆盖或采集质量不满足要求，命令就返回失败。报告按“主体 × 日期”去重，避免每 10 分钟重复快照放大统计结果。文件模式读取 `labels.jsonl`；DB/dual 模式通过 `--postgres-dsn` 合并 PostgreSQL labels，部署定时器已自动带入该参数。

## 开启人工复核写入

默认部署保持控制面只读。需要运营人员提交 `confirmed`、`false_positive`、`benign` 或 `needs_more_data` 时，显式开启复核写入：

```bash
scripts/deploy/deploy-shadow-30.sh --enable-review-writes
```

该选项只开放 labels 和 endpoint 登记接口；风险引擎仍仅输出 `record`、`shadow_watch`、`shadow_manual_review`、`shadow_confirm_review`，不会执行处罚。

复核要求：

- 每条标注必须填写理由并引用标准证据 ID。
- 每天对实际存在的各等级样本完成复核；没有对应等级样本时无需人为补样。
- 企业 VPN、视频会议、系统更新、下载器、测试设备、基础设施和白名单流量应在理由中明确写出类别，便于自动汇总误报来源。

## 报告判定

`ready=true` 必须同时满足：

- 连续影子运行不少于 7 天。
- 不少于 7 天存在人工复核。
- 每个有样本的日期/等级分桶至少有一条复核。
- 窗口内没有截断运行或畸形标准事件。
- 窗口内存在可评估风险样本。

报告同时输出各等级人工确认率、Top 10 误报原因、Top 10 误报证据类型和下一轮规则/负证据调整建议。

## 2026-08-21 现场基线

对 `192.168.0.30` 的只读实测结果：

- 2026-08-14 至 2026-08-21 连续 8 天，共 1007 次 shadow run。
- 41,728,439 条标准事件，42,749 条证据，24,596 份原始风险快照。
- 按主体和日期去重后为 715 个评估样本。
- 截断运行和畸形事件均为 0。
- 当前 `labels.jsonl` 为 0 条，因此 `ready=false`；剩余工作是人工复核，而不是继续等待流量积累。
