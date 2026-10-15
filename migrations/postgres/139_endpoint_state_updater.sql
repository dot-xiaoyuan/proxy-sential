-- 终端列表读模型改由"终端状态更新器"按变更集合批量维护（PG 迁移 139）。
--
-- 旧投影由 8 张源表上的逐行触发器驱动：每改一行身份数据就写一条 delta 并非 HOT 更新一次
-- 任务行，再由投影 worker 逐 origin 往返重算（184 现场 13.5 小时 delta 插入 512 万、任务
-- 更新 589 万次，单设备积压可达 55 万条）。终端列表只需要每个终端一行当前状态，
-- endpoint_inventory_lookup 与 endpoint_inventory_accounts 已是这个形状，保留它们，换掉生产方：
-- 更新器按 (变更时间, endpoint_id) 水位从源表取受影响终端，整批一条语句重算并 upsert。
--
-- 1. 删除旧投影触发器（delta、任务通知、快照通知）；旧 endpoint_inventory_* 队列与贡献表
--    不再写入，清理留给后续迁移。
DROP TRIGGER IF EXISTS inventory_projection_change ON endpoint_entities;
DROP TRIGGER IF EXISTS inventory_projection_delta_endpoint_entities ON endpoint_entities;
DROP TRIGGER IF EXISTS inventory_projection_change ON account_sessions;
DROP TRIGGER IF EXISTS inventory_projection_delta_account_sessions ON account_sessions;
DROP TRIGGER IF EXISTS inventory_projection_change ON identity_ip_mac_history;
DROP TRIGGER IF EXISTS inventory_projection_delta_identity_ip_mac_history ON identity_ip_mac_history;
DROP TRIGGER IF EXISTS inventory_projection_change ON identity_access_history;
DROP TRIGGER IF EXISTS inventory_projection_delta_identity_access_history ON identity_access_history;
DROP TRIGGER IF EXISTS inventory_snapshot_change ON identity_full_snapshots;
DROP TRIGGER IF EXISTS inventory_projection_change ON device_name_notes;
DROP TRIGGER IF EXISTS inventory_projection_delta_device_name_notes ON device_name_notes;
DROP TRIGGER IF EXISTS inventory_projection_change ON endpoint_recognition_summary;
DROP TRIGGER IF EXISTS inventory_projection_delta_endpoint_recognition_summary ON endpoint_recognition_summary;
DROP TRIGGER IF EXISTS inventory_projection_change ON account_identity_session_projection;
DROP TRIGGER IF EXISTS inventory_projection_delta_account_identity_session_projection ON account_identity_session_projection;
DROP TRIGGER IF EXISTS inventory_projection_change ON endpoint_inventory_snapshot_facts;
DROP TRIGGER IF EXISTS inventory_projection_delta_snapshot ON endpoint_inventory_snapshot_facts;

-- 2. 校园维度筛选改读当前会话维度，存为结构化 jsonb，并用 jsonb_path_ops GIN 做 @> 匹配。
--    读取收益：维度筛选不再对 97 万行会话做 EXISTS 扫描；写入成本：每次终端状态变化重写一次；
--    失效：随终端行更新。
ALTER TABLE endpoint_inventory_lookup ADD COLUMN IF NOT EXISTS dimensions jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS inventory_lookup_dimensions ON endpoint_inventory_lookup USING gin (dimensions jsonb_path_ops);

-- 3. 更新器的变更水位读取与按终端/IP 的有界读取。每个索引只服务一类读取：
--    *_changed：按 (时间, endpoint_id) 键集取变更终端；写入成本为每次源行更新多一条索引项。
--    *_endpoint/*_ip：终端当前状态重算、精确 IP 检索与详情关联，替代 ip_points/sessions 投影。
CREATE INDEX IF NOT EXISTS endpoint_entities_changed ON endpoint_entities (updated_at, endpoint_id);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_changed ON endpoint_recognition_summary (updated_at, endpoint_id);
CREATE INDEX IF NOT EXISTS account_sessions_changed ON account_sessions (updated_at, endpoint_id) WHERE endpoint_id IS NOT NULL AND endpoint_id <> '';
CREATE INDEX IF NOT EXISTS account_sessions_ip_lookup ON account_sessions (ip, started_at DESC) INCLUDE (endpoint_id, ended_at) WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS device_address_leases_changed ON device_address_leases (observed_at, endpoint_id);
CREATE INDEX IF NOT EXISTS device_address_leases_endpoint ON device_address_leases (endpoint_id, observed_at DESC) INCLUDE (ip, action, valid_until);
CREATE INDEX IF NOT EXISTS device_address_leases_ip ON device_address_leases (ip, observed_at DESC) INCLUDE (endpoint_id);

-- 4. 更新器水位：每个源一组 (时间, endpoint_id) 键集游标，外加首次全量填充的终端游标。
CREATE TABLE IF NOT EXISTS endpoint_state_watermark (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 cursors jsonb NOT NULL DEFAULT '{}'::jsonb,
 bootstrap_cursor text NOT NULL DEFAULT '',
 bootstrap_complete boolean NOT NULL DEFAULT false,
 refreshed_endpoints bigint NOT NULL DEFAULT 0,
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO endpoint_state_watermark(singleton) VALUES (true) ON CONFLICT DO NOTHING;
