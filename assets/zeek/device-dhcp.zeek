# Standard DHCP options retained for passive device recognition and lease ownership.
@load base/protocols/dhcp
# DHCP broadcasts from different VLANs often have the same five-tuple.
# Keep the VLAN/QinQ tags in Zeek's connection key before reading c$vlan.
@load policy/frameworks/conn_key/vlan_fivetuple
module DHCP;
export {
    redef record DHCP::Info += {
        capture_vlan: string &log &optional;
        discovery_scope_conflict: bool &log &default=F;
        requested_options: string &log &optional;
        vendor_class: string &log &optional;
        lease_observed_at: time &log &optional;
    };

    # Zeek's standard dhcp.log groups messages by transaction ID alone.
    # A per-message record preserves the observed VLAN and client hardware
    # address even when that aggregate joins simultaneous clients or VLANs.
    redef enum Log::ID += { DEVICE_MESSAGE_LOG };
    type DeviceMessageInfo: record {
        ts: time &log;
        uid: string &log;
        xid: count &log;
        msg_types: string &log;
        capture_vlan: string &log;
        mac: string &log &optional;
        requested_addr: addr &log &optional;
        assigned_addr: addr &log &optional;
        client_addr: addr &log &optional;
        server_addr: addr &log &optional;
        lease_time: interval &log &optional;
        host_name: string &log &optional;
        vendor_class: string &log &optional;
        requested_options: string &log &optional;
    };
    redef enum Log::ID += { DEVICE_BINDING_LOG };
    type DeviceBindingInfo: record {
        ts: time &log;
        request_uid: string &log;
        ack_uid: string &log;
        xid: count &log;
        msg_types: string &log;
        capture_vlan: string &log;
        mac: string &log;
        assigned_addr: addr &log;
        lease_time: interval &log &optional;
        host_name: string &log &optional;
        vendor_class: string &log &optional;
        requested_options: string &log &optional;
    };

    # aggregate_msgs runs on the manager, where worker connections do not
    # exist. Carry capture scope in the message already sent by Zeek's DHCP
    # aggregator. An absent field is different from observed untagged traffic.
    redef record DHCP::Msg += {
        sentinel_capture_vlan: string &optional;
    };
}

type SentinelRequestInfo: record {
    ts: time;
    uid: string;
    host_name: string &default="";
    vendor_class: string &default="";
    requested_options: string &default="";
};

# The standard Zeek DHCP join is keyed only by xid. This small join is keyed
# by xid, client MAC and observed VLAN; an ACK from another scope is not a
# device address binding. The unjoined per-message log remains available for
# diagnosing incomplete or conflicting exchanges.
global sentinel_requests: table[string] of SentinelRequestInfo &write_expire=30secs;

event zeek_init() &priority=4
    {
    Log::create_stream(DHCP::DEVICE_MESSAGE_LOG,
        Log::Stream($columns=DHCP::DeviceMessageInfo, $path="device_dhcp_message"));
    Log::create_stream(DHCP::DEVICE_BINDING_LOG,
        Log::Stream($columns=DHCP::DeviceBindingInfo, $path="device_dhcp_binding"));
    }

# Zeek publishes the message at priority -5, after this worker-side enrichment.
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
    {
    local vlan = "";
    if ( c?$inner_vlan && c?$vlan )
        vlan = fmt("%d/%d", c$vlan, c$inner_vlan);
    else if ( c?$vlan )
        vlan = fmt("%d", c$vlan);
    msg$sentinel_capture_vlan = vlan;

    local info = DHCP::DeviceMessageInfo($ts=network_time(), $uid=c$uid,
        $xid=msg$xid, $msg_types=DHCP::message_types[msg$m_type],
        $capture_vlan=vlan);
    if ( options?$client_id && options$client_id$hwtype == 1 )
        info$mac = options$client_id$hwaddr;
    else if ( msg$chaddr != "" )
        info$mac = msg$chaddr;
    if ( options?$addr_request )
        info$requested_addr = options$addr_request;
    if ( msg$yiaddr != 0.0.0.0 )
        info$assigned_addr = msg$yiaddr;
    local is_client = is_orig && (c$id$orig_h == 0.0.0.0 || c$id$orig_p == 68/udp || c$id$resp_p == 67/udp);
    if ( is_client )
        {
        if ( c$id$orig_h != 0.0.0.0 && c$id$orig_h != 255.255.255.255 )
            info$client_addr = c$id$orig_h;
        if ( options?$host_name )
            info$host_name = options$host_name;
        if ( options?$vendor_class )
            info$vendor_class = options$vendor_class;
        if ( options?$param_list )
            {
            local values = "";
            for ( i in options$param_list )
                values = fmt("%s%s%d", values, values == "" ? "" : ",", options$param_list[i]);
            info$requested_options = values;
            }
        }
    else
        {
        if ( c$id$orig_p == 67/udp )
            info$server_addr = c$id$orig_h;
        else
            info$server_addr = c$id$resp_h;
        if ( options?$lease )
            info$lease_time = options$lease;
        }
    Log::write(DHCP::DEVICE_MESSAGE_LOG, info);
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
# log_info is initialized at priority 1000. Enrich it before the base handler
# at priority 5 can write and retire a transaction at its message/UID limit.
event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=6
    {
    if ( msg?$sentinel_capture_vlan )
        {
        local vlan = msg$sentinel_capture_vlan;
        if ( log_info?$capture_vlan && log_info$capture_vlan != vlan )
            log_info$discovery_scope_conflict = T;
        log_info$capture_vlan = vlan;
        }

    local is_client = is_orig && (id$orig_h == 0.0.0.0 || id$orig_p == 68/udp || id$resp_p == 67/udp);
    local mac = msg$chaddr;
    if ( options?$client_id && options$client_id$hwtype == 1 )
        mac = options$client_id$hwaddr;
    if ( mac != "" && msg?$sentinel_capture_vlan )
        {
        local key = fmt("%d|%s|%s", msg$xid, mac, msg$sentinel_capture_vlan);
        if ( is_client && msg$m_type == 3 )
            {
            local new_request = SentinelRequestInfo($ts=ts, $uid=uid);
            if ( options?$host_name )
                new_request$host_name = options$host_name;
            if ( options?$vendor_class )
                new_request$vendor_class = options$vendor_class;
            if ( options?$param_list )
                {
                local sentinel_values = "";
                for ( i in options$param_list )
                    sentinel_values = fmt("%s%s%d", sentinel_values, sentinel_values == "" ? "" : ",", options$param_list[i]);
                new_request$requested_options = sentinel_values;
                }
            sentinel_requests[key] = new_request;
            }
        if ( ! is_client && msg$m_type == 5 && msg$yiaddr != 0.0.0.0 && key in sentinel_requests )
            {
            local prior_request = sentinel_requests[key];
            if ( ts >= prior_request$ts && ts - prior_request$ts <= 30secs )
                {
                local binding = DHCP::DeviceBindingInfo($ts=ts, $request_uid=prior_request$uid,
                    $ack_uid=uid, $xid=msg$xid, $msg_types="ACK",
                    $capture_vlan=msg$sentinel_capture_vlan, $mac=mac,
                    $assigned_addr=msg$yiaddr);
                if ( options?$lease )
                    binding$lease_time = options$lease;
                if ( prior_request$host_name != "" )
                    binding$host_name = prior_request$host_name;
                if ( prior_request$vendor_class != "" )
                    binding$vendor_class = prior_request$vendor_class;
                if ( prior_request$requested_options != "" )
                    binding$requested_options = prior_request$requested_options;
                Log::write(DHCP::DEVICE_BINDING_LOG, binding);
                }
            }
        }
    if ( is_client && options?$param_list )
        {
        local values = "";
        for ( i in options$param_list )
            values = fmt("%s%s%d", values, values == "" ? "" : ",", options$param_list[i]);
        log_info$requested_options = values;
        }
    if ( is_client && options?$vendor_class )
        log_info$vendor_class = options$vendor_class;
    if ( ! is_client && msg$m_type == 5 )
        log_info$lease_observed_at = ts;
    }
@endif
