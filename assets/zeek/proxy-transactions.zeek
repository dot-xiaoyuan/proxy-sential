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
type HTTPTransaction: record {
 info: Info;
 request_headers_at: time &optional;
 response_request_ready: bool &default=F;
};
type HTTPTransactions: table[count] of HTTPTransaction;
global http_pending_limit: count=100;
const proxy_transaction_window=5min;
redef record connection += {
 sentinel_http: HTTPTransactions &optional;
 sentinel_http_invalid: bool &default=F;
 sentinel_http_orig_depth: count &default=0;
 sentinel_http_resp_depth: count &default=0;
};
global socks_pending: table[string] of Info &create_expire=5min;
global socks_seen: set[string] &create_expire=5min;
global socks_ambiguous: set[string] &create_expire=5min;
event zeek_init() {
 Log::create_stream(LOG, [$columns=Info, $path="proxy_transactions"]);
 if ( HTTP::max_pending_requests > 0 && HTTP::max_pending_requests < http_pending_limit ) http_pending_limit=HTTP::max_pending_requests;
}
function invalidate_http(c: connection) {
 c$sentinel_http_invalid=T;
 if ( c?$sentinel_http ) c$sentinel_http=table();
}
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=-5 {
 if ( method != "CONNECT" || ! c?$http || c$sentinel_http_invalid ) return;
 if ( ! c?$sentinel_http ) {
  # Expiry attributes on a type alias do not configure a table() value.
  local pending: HTTPTransactions = table() &create_expire=5min;
  c$sentinel_http=pending;
 }
 if ( |c$sentinel_http| >= http_pending_limit ) {
  invalidate_http(c);
  Reporter::conn_weird("Sentinel_CONNECT_pending_limit",c);
  return;
 }
 local i: Info = [$ts=network_time(),$uid=c$uid,$id=c$id,$protocol="http_connect",$transaction_id=fmt("%d",c$http$trans_depth),$request_at=network_time(),$method=method];
 c$sentinel_http[c$http$trans_depth]=[$info=i];
 Log::write(LOG,i);
}
event http_reply(c: connection, version: string, code: count, reason: string) &priority=0 {
 if ( code < 200 || ! c?$http || ! c?$sentinel_http || c$http$trans_depth !in c$sentinel_http ) return;
 local depth=c$http$trans_depth;
 c$sentinel_http[depth]$response_request_ready=c$sentinel_http[depth]?$request_headers_at;
}
event http_begin_entity(c: connection, is_orig: bool) {
 if ( ! c?$sentinel_http ) return;
 if ( is_orig ) ++c$sentinel_http_orig_depth;
 else ++c$sentinel_http_resp_depth;
}
event http_end_entity(c: connection, is_orig: bool) {
 if ( ! c?$sentinel_http ) return;
 if ( is_orig && c$sentinel_http_orig_depth > 0 ) --c$sentinel_http_orig_depth;
 if ( ! is_orig && c$sentinel_http_resp_depth > 0 ) --c$sentinel_http_resp_depth;
}
# Native MIME EOF handling synthesizes http_all_headers before reporting a
# missing header terminator. Commit after already queued parser diagnostics,
# retaining the original header timestamp and request readiness snapshot.
event connect_headers_validated(c: connection, depth: count, response_at: time, status: count, request_ready: bool) {
 if ( ! request_ready || c$sentinel_http_invalid || ! c?$sentinel_http || depth !in c$sentinel_http ) return;
 local i=c$sentinel_http[depth]$info;
 # Timer-driven eviction can be delayed. Check the actual evidence window too.
 if ( response_at < i$request_at || response_at-i$request_at > proxy_transaction_window ) {
  delete c$sentinel_http[depth];
  return;
 }
 i$ts=response_at;i$response_at=response_at;i$status=status;
 Log::write(LOG,i);delete c$sentinel_http[depth];
}
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=0 {
 if ( ! c?$http || ! c?$sentinel_http || c$http$trans_depth !in c$sentinel_http ) return;
 local depth=c$http$trans_depth;
 if ( is_orig ) {
  if ( c$sentinel_http_orig_depth == 1 ) c$sentinel_http[depth]$request_headers_at=network_time();
  return;
 }
 if ( c$sentinel_http_resp_depth != 1 || ! c$http?$status_code || c$http$status_code < 200 ) return;
 local ready=c$sentinel_http[depth]$response_request_ready && c$sentinel_http[depth]?$request_headers_at && c$sentinel_http[depth]$request_headers_at <= network_time();
 event connect_headers_validated(c,depth,network_time(),c$http$status_code,ready);
}
event http_event(c: connection, category: string, detail: string) {
 # Request-line diagnostics precede http_request, before pending state exists.
 if ( category == "Sentinel_HTTP_invalid_header" || category == "bad_HTTP_version" || category == "crud after HTTP version is ignored" ) { invalidate_http(c); return; }
 if ( c?$sentinel_http && category == "illegal format" && detail == "entity body missing" ) invalidate_http(c);
}
event conn_weird(name: string, c: connection, addl: string, source: string) &priority=5 {
 # Native queue flushing destroys reliable request/response correspondence,
 # including when non-CONNECT requests consumed the native queue capacity.
 if ( c?$sentinel_http && name == "HTTP_excessive_pipelining" ) invalidate_http(c);
}
event socks_request(c: connection, version: count, request_type: count, sa: SOCKS::Address, p: port, user: string) &priority=-5 {
 if ( c$uid in socks_seen ) { add socks_ambiguous[c$uid]; return; }
 add socks_seen[c$uid];
 local i: Info=[$ts=network_time(),$uid=c$uid,$id=c$id,$protocol="socks5",$transaction_id="1",$request_at=network_time(),$version=version,$command=request_type];
 socks_pending[c$uid]=i;Log::write(LOG,i);
}
event socks_reply(c: connection, version: count, reply: count, sa: SOCKS::Address, p: port) &priority=-5 {
 if ( c$uid !in socks_pending || c$uid in socks_ambiguous ) return;
 local i=socks_pending[c$uid];
 if ( network_time() < i$request_at || network_time()-i$request_at > proxy_transaction_window ) {
  delete socks_pending[c$uid];
  return;
 }
 i$ts=network_time();i$response_at=network_time();i$reply=reply;
 if ( version != i$version ) i$command=0;
 Log::write(LOG,i);delete socks_pending[c$uid];
}
event connection_state_remove(c: connection) {
 if ( c$uid in socks_pending ) delete socks_pending[c$uid];
 if ( c$uid in socks_seen ) delete socks_seen[c$uid];
 if ( c$uid in socks_ambiguous ) delete socks_ambiguous[c$uid];
}
