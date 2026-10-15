-- 路由器信号流扩展路由器品牌关键词（ClickHouse 迁移 042）。
--
-- HTTP/TLS 事件只在 payload 含少量厂商词时进入路由器信号流，UniFi、MikroTik、Synology 等
-- 路由器自报标题或证书名不在其中，开源库（Recog 自报规则）无从匹配。这里补上 Recog 路由器
-- 自报规则里的品牌词；SNMP 本就全量进入流（迁移 033）。
--
-- 读取收益：开源库可以对更多 HTTP/TLS 管理面事件做路由器自报匹配。
-- 写入成本：只对 HTTP/TLS/X509/QUIC 中出现新增关键词的事件增加写入，行数随 L7 采集量线性增长。
-- 保留与失效：沿用流表 8 天 TTL；关键词是 MV 的 SELECT，修改后只影响新写入的事件。
-- 184 现场当前没有 L7 采集（Zeek/Suricata 的 BPF 只放行控制协议），本迁移在该部署上没有写入。
DROP VIEW IF EXISTS router_signal_events_v1_mv;

CREATE MATERIALIZED VIEW router_signal_events_v1_mv
TO router_signal_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','software','lldp','cdp','ssdp','snmp')
 OR (source_event_type IN ('http','ssl','tls','x509','quic')
  AND multiSearchAnyCaseInsensitiveUTF8(payload_json,
   ['huawei','honor','h3c','new h3c','comware','airengine','secpath','msr','magic ',
    'tp-link technologies','tplinkcloud.com.cn',
    'routeros','mikrotik','unifi','ubiquiti','amplifi','synology','zyxel','netgear',
    'd-link','tenda','fortinet','ruijie','openwrt','miwifi','mi wifi'])>0);

-- Refill only rows the previous keyword list did not admit, over the last 24 hours, so a
-- row that the old view already wrote is never duplicated.
INSERT INTO router_signal_events_v1
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE timestamp>=now()-INTERVAL 24 HOUR
 AND source_event_type IN ('http','ssl','tls','x509','quic')
 AND multiSearchAnyCaseInsensitiveUTF8(payload_json,
  ['routeros','mikrotik','unifi','ubiquiti','amplifi','synology','zyxel','netgear',
   'd-link','tenda','fortinet','ruijie','openwrt','miwifi','mi wifi'])>0
 AND NOT multiSearchAnyCaseInsensitiveUTF8(payload_json,
  ['huawei','honor','h3c','new h3c','comware','airengine','secpath','msr','magic ',
   'tp-link technologies','tplinkcloud.com.cn'])>0;
