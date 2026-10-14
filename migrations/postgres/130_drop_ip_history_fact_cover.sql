-- inventory_ip_history_fact_cover 是 (endpoint_id,last_seen DESC) INCLUDE(ip,source,...) 的覆盖索引，
-- 只服务两处按 endpoint_id 读取身份地址历史的路径：初始回填播种（inventory_projection.go:449 经
-- endpoint_inventory_observation_facts 视图）与设备详情页。两者都可以回落到同样以
-- (endpoint_id,last_seen DESC) 为前缀的 idx_ip_history_endpoint_list_cover，代价只是少量堆回表。
--
-- 现场实测该索引在全库生命周期内只被扫描 5,443 次，而第 10 轮激活的窗口延长语句
-- (extendIPMACHistoryWindows，约 10 次/秒、每批 1000 行) 因为 last_seen 是索引列无法 HOT 更新，
-- 每次都要为它重写索引条目 —— 写代价约为读收益的 25 倍。删除后 identity_ip_mac_history 的索引
-- 从 7.2 GB 降到 5.3 GB，延长语句少维护约四分之一的索引。
DROP INDEX IF EXISTS inventory_ip_history_fact_cover;
