-- 共享设备档案任务已由 Go 层批量标记，删除逐行触发器。
-- 现场先 DISABLE TRIGGER 执行，本迁移 DROP TRIGGER 记账本。
DROP TRIGGER IF EXISTS shared_device_profile_session_dirty ON account_sessions;
DROP TRIGGER IF EXISTS shared_device_profile_account_projection_dirty ON account_identity_session_projection;
