-- 账号会话不再逐行触发终端识别脏标记（PG 迁移 140）。
--
-- endpoint_recognition_session_dirty 在每次会话写入时锁住 endpoint_recognition_jobs 对应行，
-- 并一直持有到写入事务提交。认证车道的会话批量插入在 184 冷页上耗时 25–30 秒，期间设备车道与
-- 名称证据写入同一终端的识别作业行全部排队，两条车道游标随之停滞。
-- 终端状态更新器（endpoint_state.go）已按水位读取会话变化，改由它每轮对变更终端集合
-- 一次性、按序标记识别脏，不再在会话写入事务内加锁。
DROP TRIGGER IF EXISTS endpoint_recognition_session_dirty ON account_sessions;
