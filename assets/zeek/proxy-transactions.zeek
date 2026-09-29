@load base/protocols/http
@load base/protocols/socks

module SentinelProxy;
export {
 redef enum Log::ID += { LOG };
 type Info: record {
  ts: time &log;
  uid: string &log;
  id: conn_id &log;
  protocol: string &log;
  transaction_id: string &log;
  request_at: time &log &optional;
  response_at: time &log &optional;
  method: string &log &optional;
  status: count &log &optional;
  version: count &log &optional;
  command: count &log &optional;
  reply: count &log &optional;
 };
}
global http_pending: table[string,count] of Info &create_expire=5min;
global socks_pending: table[string] of Info &create_expire=5min;
global socks_seen: set[string] &create_expire=5min;
global socks_ambiguous: set[string] &create_expire=5min;
event zeek_init() { Log::create_stream(LOG, [$columns=Info, $path="proxy_transactions"]); }
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=-5 {
 if ( method != "CONNECT" || ! c?$http ) return;
 local i: Info = [$ts=network_time(),$uid=c$uid,$id=c$id,$protocol="http_connect",$transaction_id=fmt("%d",c$http$trans_depth),$request_at=network_time(),$method=method];
 http_pending[c$uid,c$http$trans_depth]=i;
 Log::write(LOG,i);
}
event http_reply(c: connection, version: string, code: count, reason: string) &priority=-5 {
 if ( ! c?$http || [c$uid,c$http$trans_depth] !in http_pending || code < 200 ) return;
 local i=http_pending[c$uid,c$http$trans_depth];
 i$ts=network_time();i$response_at=network_time();i$status=code;
 Log::write(LOG,i);delete http_pending[c$uid,c$http$trans_depth];
}
event socks_request(c: connection, version: count, request_type: count, sa: SOCKS::Address, p: port, user: string) &priority=-5 {
 if ( c$uid in socks_seen ) { add socks_ambiguous[c$uid]; return; }
 add socks_seen[c$uid];
 local i: Info=[$ts=network_time(),$uid=c$uid,$id=c$id,$protocol="socks5",$transaction_id="1",$request_at=network_time(),$version=version,$command=request_type];
 socks_pending[c$uid]=i;Log::write(LOG,i);
}
event socks_reply(c: connection, version: count, reply: count, sa: SOCKS::Address, p: port) &priority=-5 {
 if ( c$uid !in socks_pending || c$uid in socks_ambiguous ) return;
 local i=socks_pending[c$uid];i$ts=network_time();i$response_at=network_time();i$reply=reply;
 if ( version != i$version ) i$command=0;
 Log::write(LOG,i);delete socks_pending[c$uid];
}
event connection_state_remove(c: connection) {
 if ( c$uid in socks_pending ) delete socks_pending[c$uid];
 if ( c$uid in socks_seen ) delete socks_seen[c$uid];
 if ( c$uid in socks_ambiguous ) delete socks_ambiguous[c$uid];
}
