# Candidate-only metadata. Packet filter and scope table come from the discovery
# state projection; no payloads from unlisted endpoints are logged.
@load base/frameworks/input
@load base/frameworks/packet-filter
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/mqtt
module SentinelIoT;
export {
 redef enum Log::ID += { LOG };
 const candidate_path = "/var/lib/proxy-sentinel/discovery-spool/zeek-candidates.tsv" &redef;
 const filter_path = "/var/lib/proxy-sentinel/discovery-spool/zeek-filter.tsv" &redef;
 const enabled_path = "/var/lib/proxy-sentinel/discovery-spool/zeek-enabled.tsv" &redef;
 type EnabledIndex: record {protocol: string;};
 global enabled: set[string];
 type Index: record { ip: addr; vlan: string; };
 type Scope: record { domain: string; interface_name: string; site: string; };
 type FilterIndex: record { id: string; };
 type Filter: record { expression: string; };
 global candidates: table[addr,string] of Scope;
 global filters: table[string] of Filter;
 type Info: record {ts: time &log; ip: addr &log; vlan: string &log; domain: string &log; interface_name: string &log; site: string &log; protocol: string &log; metadata: string &log; parser_version: string &log &default="iot-metadata-v2";};
 type Product: record {manufacturer: string &optional; model: string &optional; name: string &optional; identifiers: vector of string &optional;};
 type MQTTDoc: record {device: Product &optional;};
}
redef MQTT::max_payload_size = 16384;
redef tcp_content_delivery_ports_resp += { [554/tcp]=T };
redef record connection += { iot_header: string &default=""; iot_done: bool &default=F; iot_ipp: bool &default=F; iot_body: string &default=""; iot_overflow: bool &default=F; };
function vlan(c: connection): string {if(c?$inner_vlan && c?$vlan)return fmt("%d/%d",c$vlan,c$inner_vlan);if(c?$vlan)return fmt("%d",c$vlan);return "";}
function eligible(c: connection,ip: addr): bool {return [ip,vlan(c)] in candidates;}
function emit(c: connection,ip: addr,protocol: string,metadata: string) {
 if(protocol !in enabled || !eligible(c,ip) || |metadata|>32768)return;
 local scope=candidates[ip,vlan(c)];Log::write(LOG,[$ts=network_time(),$ip=ip,$vlan=vlan(c),$domain=scope$domain,$interface_name=scope$interface_name,$site=scope$site,$protocol=protocol,$metadata=metadata]);
}
event zeek_init() {
 Log::create_stream(LOG,[$columns=Info,$path="iot_metadata"]);
 Input::add_table([$source=enabled_path,$name="iot-enabled",$idx=EnabledIndex,$destination=enabled,$mode=Input::REREAD]);
 Input::add_table([$source=candidate_path,$name="iot-candidates",$idx=Index,$val=Scope,$destination=candidates,$mode=Input::REREAD]);
 Input::add_table([$source=filter_path,$name="iot-filter",$idx=FilterIndex,$val=Filter,$destination=filters,$mode=Input::REREAD]);
}
event Input::end_of_data(name: string,source: string) {if(name=="iot-filter" && "candidate" in filters) {capture_filters["sentinel-iot"]=filters["candidate"]$expression;PacketFilter::install();}}
event http_header(c: connection,is_orig: bool,name: string,value: string) {
 if(is_orig || !eligible(c,c$id$resp_h))return;
 if(name=="SERVER" && |value|<=512)emit(c,c$id$resp_h,"http",value);
 if(name=="CONTENT-TYPE" && /^application\/ipp/ in value)c$iot_ipp=T;
}
event http_entity_data(c: connection,is_orig: bool,length: count,data: string) {
 if(is_orig || !c$iot_ipp || !eligible(c,c$id$resp_h) || c$iot_overflow)return;
 if(|c$iot_body|+|data|>32768) {c$iot_overflow=T;c$iot_body="";return;}
 c$iot_body+=data;
}
event http_end_entity(c: connection,is_orig: bool) {if(!is_orig && c$iot_ipp && !c$iot_overflow)emit(c,c$id$resp_h,"ipp",encode_base64(c$iot_body));c$iot_ipp=F;c$iot_body="";c$iot_overflow=F;}
event SSL::log_ssl(rec: SSL::Info) {local c=lookup_connection(rec$id);if(c$uid!="" && eligible(c,c$id$resp_h) && rec?$version)emit(c,c$id$resp_h,"tls",rec$version);}
event mqtt_publish(c: connection,is_orig: bool,msg_id: count,msg: MQTT::PublishMsg) &priority=0 {
 if(!is_orig || !eligible(c,c$id$orig_h) || |msg$payload|>16384 || msg$payload_len!=|msg$payload| || !( /^homeassistant\/(sensor|binary_sensor)\// in msg$topic ) || !( /\/config$/ in msg$topic ))return;
 local parsed=from_json(msg$payload,MQTTDoc);if(!parsed$valid)return;local doc=parsed$v as MQTTDoc;
 if(!doc?$device || !doc$device?$manufacturer || !doc$device?$model)return;
 emit(c,c$id$orig_h,"mqtt",to_json(doc));
}
# Base MQTT must not retain telemetry or will payloads.
hook MQTT::log_policy_publish(rec: MQTT::PublishInfo,id: Log::ID,filter: Log::Filter) {break;}
hook MQTT::log_policy(rec: MQTT::ConnectInfo,id: Log::ID,filter: Log::Filter) {break;}
event tcp_contents(c: connection,is_orig: bool,seq: count,contents: string) {
 if(is_orig || c$iot_done || c$id$resp_p!=554/tcp || !eligible(c,c$id$resp_h))return;
 if(|c$iot_header|+|contents|>4096) {c$iot_done=T;c$iot_header="";return;}
 c$iot_header+=contents;
 if(/\r\n\r\n/ in c$iot_header) {
  if(/^RTSP\/1\.0 200 / in c$iot_header) {local lines=split_string(c$iot_header,/\r\n/);for(i in lines)if(/^Server: / in lines[i])emit(c,c$id$resp_h,"rtsp",sub(lines[i],/^Server: /,""));}
  c$iot_done=T;c$iot_header="";
 }
}
event content_gap(c: connection,is_orig: bool,seq: count,length: count) {if(!is_orig){c$iot_done=T;c$iot_header="";c$iot_overflow=T;}}
