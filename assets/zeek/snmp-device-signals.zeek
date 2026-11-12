@load base/protocols/snmp

module ProxySentinelSNMP;

export {
    const enabled = F &redef;
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log;
        source_h: addr &log;
        source_p: port &log;
        destination_h: addr &log;
        destination_p: port &log;
        vlan: string &log &optional;
        inner_vlan: string &log &optional;
        is_response: bool &log &default=T;
        parser_version: string &log &default="snmp-device/v1";
        version: string &log;
        system_description: string &log &optional;
        system_object_id: string &log &optional;
        snmp_varbinds: string &log;
    };
}

# These values may already be present in mirrored responses. This script sends
# no SNMP requests and never logs community, security headers or arbitrary OIDs.
# Keep this allowlist aligned with internal/adapter/zeek/passive_identity.go.
function allowed_identity_oid(oid: string): bool
    {
    return oid in set("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.39165.1.1.0",
        "1.3.6.1.4.1.318.1.4.2.2.1.2.1", "1.3.6.1.4.1.21239.5.2.1.8.0") ||
        /^1\.3\.6\.1\.2\.1\.47\.1\.1\.1\.1\.(2|12|13)\.[0-9]+$/ in oid ||
        /^1\.3\.6\.1\.2\.1\.43\.5\.1\.1\.16\.[0-9]+$/ in oid;
    }

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
    {
    if ( ! enabled || pdu$error_status != 0 || |pdu$bindings| > 128 ) return;
    local values: table[string] of string = table();
    local total: count = 0;
    local item = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
        $source_h=is_orig ? c$id$orig_h : c$id$resp_h,
        $source_p=is_orig ? c$id$orig_p : c$id$resp_p,
        $destination_h=is_orig ? c$id$resp_h : c$id$orig_h,
        $destination_p=is_orig ? c$id$resp_p : c$id$orig_p,
        $version=header$version == 0 ? "1" : (header$version == 1 ? "2c" : "3"), $snmp_varbinds="");
    # A Zeek connection can span the same tuple on multiple VLANs; c$vlan is
    # the first packet's tag. Take this UDP response's actual packet scope.
    local packet = get_current_packet_header();
    if ( ! packet?$udp || packet$udp$sport != item$source_p || packet$udp$dport != item$destination_p ) return;
    if ( packet?$ip )
        {
        if ( packet$ip$src != item$source_h || packet$ip$dst != item$destination_h || packet$ip$MF || packet$ip$offset != 0 ) return;
        }
    else if ( packet?$ip6 )
        {
        if ( packet$ip6$src != item$source_h || packet$ip6$dst != item$destination_h ) return;
        }
    else return;
    if ( packet$l2?$vlan ) item$vlan = fmt("%d", packet$l2$vlan);
    if ( packet$l2?$inner_vlan ) item$inner_vlan = fmt("%d", packet$l2$inner_vlan);
    for ( i in pdu$bindings )
        {
        local b = pdu$bindings[i];
        if ( ! allowed_identity_oid(b$oid) ) next;
        local value = "";
        if ( b$value$tag == SNMP::OBJ_OCTETSTRING_TAG && b$value?$octets ) value = b$value$octets;
        else if ( b$value$tag == SNMP::OBJ_OID_TAG && b$value?$oid ) value = b$value$oid;
        else next;
        if ( |value| == 0 ) next;
        local limit: count = b$oid == "1.3.6.1.2.1.1.1.0" ? 2048 : 512;
        total += |value| + |b$oid|;
        if ( |value| > limit || |b$oid| > 128 || total > 8192 || |values| >= 32 ) return;
        if ( b$oid in values && values[b$oid] != value ) return;
        values[b$oid] = value;
        if ( b$oid == "1.3.6.1.2.1.1.1.0" ) item$system_description = value;
        if ( b$oid == "1.3.6.1.2.1.1.2.0" ) item$system_object_id = value;
        }
    if ( |values| == 0 ) return;
    item$snmp_varbinds = to_json(values);
    Log::write(LOG, item);
    }

# Only retain SNMP responses that carry sysDescr. Transaction-only rows do not
# add device identity evidence and would dominate the pilot's write volume.
hook SNMP::log_policy(rec: SNMP::Info, id: Log::ID, filter: Log::Filter)
    {
    if ( ! rec?$display_string )
        break;
    }

# SNMP v1/v2c community strings are credentials. Exclude the field in Zeek's
# logging layer so it never reaches a raw log, adapter, diagnostic, or database.
event zeek_init() &priority=4
    {
    if ( enabled ) Log::create_stream(LOG, [$columns=Info, $path="snmp_device"]);
    local snmp_filter = Log::get_filter(SNMP::LOG, "default");
    if ( snmp_filter$name == "<not found>" )
        return;
    if ( ! snmp_filter?$exclude )
        snmp_filter$exclude = set();
    add snmp_filter$exclude["community"];
    Log::add_filter(SNMP::LOG, snmp_filter);
    }
