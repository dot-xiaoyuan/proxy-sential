-- 删除零扫描索引：6 天统计周期内 idx_scan=0、idx_tup_read=0，
-- 所有索引在 Go 代码中无显式引用，查询计划器从未选择。
-- 现场先以 DROP INDEX CONCURRENTLY 执行，本迁移只记账本。

-- 热写入表（policy_identity_observations: 5→2 索引）
DROP INDEX IF EXISTS policy_identity_ip_scope_time;
DROP INDEX IF EXISTS policy_identity_scope_time;
DROP INDEX IF EXISTS policy_identity_account_time;

-- policy_decision_records: 删除 2 个零扫描索引
DROP INDEX IF EXISTS policy_decisions_ip_time;
DROP INDEX IF EXISTS policy_decision_records_account_time;

-- account_identity_session_projection: 11→8 索引
DROP INDEX IF EXISTS account_identity_projection_ip;
DROP INDEX IF EXISTS shared_device_profile_projection_endpoint_history;
DROP INDEX IF EXISTS account_identity_projection_account;

-- account_sessions: 12→10 索引
DROP INDEX IF EXISTS device_center_current_session_lookup;
DROP INDEX IF EXISTS account_sessions_current_endpoint_lookup;

-- endpoint_entities: 旧列表排序索引，被 endpoint_inventory_lookup 替代
DROP INDEX IF EXISTS idx_endpoint_page_order;

-- shared_behavior_observations: 共享访问列表分页，功能未启用
DROP INDEX IF EXISTS shared_behavior_observations_confidence_page_idx;
DROP INDEX IF EXISTS shared_behavior_observations_page;

-- endpoint_recognition_summary: 6 个零扫描索引（两代设计都零扫描）
DROP INDEX IF EXISTS endpoint_recognition_summary_page;
DROP INDEX IF EXISTS endpoint_recognition_summary_os;
DROP INDEX IF EXISTS endpoint_recognition_summary_brand;
DROP INDEX IF EXISTS endpoint_recognition_summary_filter_os;
DROP INDEX IF EXISTS endpoint_recognition_summary_filter_brand;

-- endpoint_device_profiles: 旧品牌筛选索引
DROP INDEX IF EXISTS idx_endpoint_device_profiles_brand;

-- ingest_batches: 来源查找索引
DROP INDEX IF EXISTS idx_ingest_batches_source_started;
