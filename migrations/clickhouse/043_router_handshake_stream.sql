-- 路由器信号流纳入握手摘要（ClickHouse 迁移 043）。
--
-- 轻量握手采集（device-signal --handshake-only）每个设备每个时间桶输出一条摘要：
-- TLS ClientHello 的 SNI/ALPN 与 HTTP 请求的 Host/User-Agent，已按设备去重且有上限。
-- 摘要量与 TTL 事件同一数量级，因此全部进入路由器信号流，不做逐包过滤。
-- 保留与失效：沿用流表 8 天 TTL；只影响新写入的摘要事件。
DROP VIEW IF EXISTS router_signal_events_v1_mv;

CREATE MATERIALIZED VIEW router_signal_events_v1_mv
TO router_signal_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','software','lldp','cdp','ssdp','snmp','handshake')
 OR (source_event_type IN ('http','ssl','tls','x509','quic')
  AND multiSearchAnyCaseInsensitiveUTF8(payload_json,
   ['huawei','honor','h3c','new h3c','comware','airengine','secpath','msr','magic ',
    'tp-link technologies','tplinkcloud.com.cn',
    'routeros','mikrotik','unifi','ubiquiti','amplifi','synology','zyxel','netgear',
    'd-link','tenda','fortinet','ruijie','openwrt','miwifi','mi wifi'])>0);
