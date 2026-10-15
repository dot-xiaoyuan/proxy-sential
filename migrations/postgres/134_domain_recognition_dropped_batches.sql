-- 域名识别队列（PG 迁移 134）记录丢弃批次数。
--
-- 队列满时批次被直接丢弃，日志却声称"会由对账补齐"，而对账只回读 dns/tls/quic/http，
-- 设备名称、软件与协议归属不会被补回。累计丢弃数落库后，运维与健康检查可以看到损失，
-- 不再被伪装成已对账。
ALTER TABLE domain_recognition_state ADD COLUMN IF NOT EXISTS dropped_batches bigint NOT NULL DEFAULT 0;
