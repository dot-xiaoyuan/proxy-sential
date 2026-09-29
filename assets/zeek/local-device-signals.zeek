@load ./device-dhcp
@load base/protocols/dns

module ProxySentinel;

export {
    redef enum Log::ID += { LOG_MDNS, LOG_NBNS, LOG_LLMNR };
    type Info: record {
        ts: time &log;
        src_ip: addr &log;
        dst_ip: addr &log;
        is_response: bool &log &default=F;
        record_type: string &log &optional;
        record_name: string &log &optional;
        record_address: addr &log &optional;
        record_ttl: count &log &optional;
        service_target: string &log &optional;
        record_text: string &log &optional;
        parser_version: string &log &default="device-names/v1";
        query: string &log &optional;
        name: string &log &optional;
        proto: string &log &default="udp";
        direction: string &log &default="outbound";
    };
}

redef record connection += { device_dns_is_orig: bool &default=T; };
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=10
    { c$device_dns_is_orig = is_orig; }

event zeek_init()
    {
    Log::create_stream(LOG_MDNS, [$columns=Info, $path="mdns"]);
    Log::create_stream(LOG_NBNS, [$columns=Info, $path="nbns"]);
    Log::create_stream(LOG_LLMNR, [$columns=Info, $path="llmnr"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_DNS, set(137/udp, 5353/udp, 5355/udp));
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local item = Info($ts=network_time(), $src_ip=c$id$orig_h, $dst_ip=c$id$resp_h, $query=query);
    if ( c$id$resp_p == 5353/udp )
        Log::write(LOG_MDNS, item);
    else if ( c$id$resp_p == 137/udp )
        Log::write(LOG_NBNS, item);
    else if ( c$id$resp_p == 5355/udp )
        Log::write(LOG_LLMNR, item);
    }

# Each answer is recorded independently. A query never identifies its sender.
function mdns_is_multicast(a: addr): bool
    { return a in 224.0.0.0/4 || a in [ff00::]/8; }
function mdns_response_source(c: connection): addr
    {
    if ( mdns_is_multicast(c$id$orig_h) ) return c$id$resp_h;
    if ( mdns_is_multicast(c$id$resp_h) ) return c$id$orig_h;
    return c$device_dns_is_orig ? c$id$orig_h : c$id$resp_h;
    }
function mdns_response_destination(c: connection): addr
    {
    if ( mdns_is_multicast(c$id$orig_h) ) return c$id$orig_h;
    if ( mdns_is_multicast(c$id$resp_h) ) return c$id$resp_h;
    return c$device_dns_is_orig ? c$id$resp_h : c$id$orig_h;
    }
function log_mdns_address(c: connection, msg: dns_msg, ans: dns_answer, a: addr, kind: string)
    {
    if ( ! msg$QR || (c$id$resp_p != 5353/udp && c$id$orig_p != 5353/udp) ) return;
    Log::write(LOG_MDNS, [$ts=network_time(), $src_ip=mdns_response_source(c), $dst_ip=mdns_response_destination(c),
        $is_response=T, $record_type=kind, $record_name=ans$query,
        $record_address=a, $record_ttl=double_to_count(interval_to_double(ans$TTL))]);
    }
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    { log_mdns_address(c, msg, ans, a, "A"); }
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    { log_mdns_address(c, msg, ans, a, "AAAA"); }
event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
    {
    if ( ! msg$QR || (c$id$resp_p != 5353/udp && c$id$orig_p != 5353/udp) ) return;
    Log::write(LOG_MDNS, [$ts=network_time(), $src_ip=mdns_response_source(c), $dst_ip=mdns_response_destination(c),
        $is_response=T, $record_type="SRV", $record_name=ans$query, $service_target=target,
        $record_ttl=double_to_count(interval_to_double(ans$TTL))]);
    }
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    if ( ! msg$QR || (c$id$resp_p != 5353/udp && c$id$orig_p != 5353/udp) ) return;
    Log::write(LOG_MDNS, [$ts=network_time(), $src_ip=mdns_response_source(c), $dst_ip=mdns_response_destination(c),
        $is_response=T, $record_type="PTR", $record_name=ans$query, $service_target=name,
        $record_ttl=double_to_count(interval_to_double(ans$TTL))]);
    }
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, txt: string_vec)
    {
    if ( ! msg$QR || (c$id$resp_p != 5353/udp && c$id$orig_p != 5353/udp) ) return;
    Log::write(LOG_MDNS, [$ts=network_time(), $src_ip=mdns_response_source(c), $dst_ip=mdns_response_destination(c),
        $is_response=T, $record_type="TXT", $record_name=ans$query, $record_text=join_string_vec(txt, " "),
        $record_ttl=double_to_count(interval_to_double(ans$TTL))]);
    }
