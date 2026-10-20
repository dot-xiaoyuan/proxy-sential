-- shared_device_profile_jobs 已由 Go 层批量标记，移除逐行触发器。
DROP TRIGGER IF EXISTS shared_device_profile_shared_dirty ON shared_behavior_observations;
