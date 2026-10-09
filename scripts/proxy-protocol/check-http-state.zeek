# Controlled PCAP-only state probe, never loaded into the live collector.
@load base/protocols/http
global connect_peak: table[string] of count &default=0;
global first_reply_seen: set[string];
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=-10 {
 if ( method != "CONNECT" || ! c?$sentinel_http ) return;
 if ( |c$sentinel_http| > connect_peak[c$uid] ) connect_peak[c$uid]=|c$sentinel_http|;
}
event http_reply(c: connection, version: string, code: count, reason: string) &priority=10 {
 if ( ! c?$sentinel_http || c$uid in first_reply_seen ) return;
 add first_reply_seen[c$uid];
 print fmt("{\"kind\":\"reply\",\"client_port\":%d,\"first_reply_pending\":%d}",port_to_count(c$id$orig_p),|c$sentinel_http|);
}
event connection_state_remove(c: connection) &priority=-10 {
 if ( ! c?$sentinel_http ) return;
 print fmt("{\"kind\":\"final\",\"client_port\":%d,\"peak_pending\":%d,\"remaining_pending\":%d,\"ambiguous\":%s}",port_to_count(c$id$orig_p),connect_peak[c$uid],|c$sentinel_http|,c$sentinel_http_invalid ? "true" : "false");
 delete connect_peak[c$uid];
 delete first_reply_seen[c$uid];
}
