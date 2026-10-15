-- 设备信号事件（PG 迁移 138）为增量维护样本提供有界的 top-20 读取。
--
-- upsertDeviceSignalFactsBatch 原先每批对涉及信号的全部历史事件 count + row_number 重算
-- seen_count 与 20 条样本；device_signal_events 无保留期（184 约 300 万行），单批在持有全局
-- 身份写锁时耗时 30 秒以上，其余身份写入方全部排队。改为只累加本批新插入的事件数，样本按
-- 本索引读取每个信号最近 20 条。
--
-- 读取收益：样本读取由全量扫描排序变为每信号 20 条的索引范围读。写入成本：每插入一个信号
-- 事件多维护一条索引项（与主键同量级）。保留与失效：随 device_signal_events 行删除失效。
CREATE INDEX IF NOT EXISTS device_signal_events_recent ON device_signal_events(sensor_id, signal_id, first_seen DESC, event_id);
