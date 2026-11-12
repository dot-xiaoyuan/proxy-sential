# BACnet native parser: CISA ICSNPP 72d1572ec170e16e0676de7f07d903f63b87ba31.
# Modbus identity response schema/decoding derived from CISA ICSNPP
# 6dd3dab173169e454a73925d0426d3c019104852 (BSD-3-Clause, see license below).
# No polling, requests, register history, device-control passwords or file data.
@load base/misc/version
@if (! Version::at_least("6.1.0"))
@error Passive industrial identity requires Zeek >= 6.1
@endif
@load base/protocols/modbus
@load-plugin ICSNPP::BACnet
@load icsnpp/bacnet/main
@load-sigs icsnpp/bacnet/dpd.sig

module ProxySentinelIndustrial;

export {
    redef enum Log::ID += { MODBUS_IDENTITY };
    type ModbusIdentity: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        is_orig: bool &log &default=F;
        source_h: addr &log;
        source_p: port &log;
        destination_h: addr &log;
        destination_p: port &log;
        vlan: string &log &optional;
        inner_vlan: string &log &optional;
        request_response: string &log &default="RESPONSE";
        mei_type: string &log &default="READ-DEVICE-IDENTIFICATION";
        unit: count &log;
        tid: count &log;
        object_id_code: string &log;
        object_value: string &log;
    };
}

redef record Bacnet::BACnet_Property += {
    vlan: string &log &optional;
    inner_vlan: string &log &optional;
};

# The upstream BACnet parser also emits control operations and arbitrary
# property values. These streams are unnecessary for inventory and can contain
# passwords. Suppress them before any packet is processed.
event zeek_init() &priority=-10
    {
    Files::register_protocol(Analyzer::ANALYZER_BACNET,
        [$get_file_handle=function(c: connection, is_orig: bool): string { return ""; }]);
    Log::disable_stream(Bacnet::LOG_BACNET);
    Log::disable_stream(Bacnet::LOG_BACNET_DISCOVERY);
    Log::disable_stream(Bacnet::LOG_BACNET_DEVICE_CONTROL);
    Log::create_stream(MODBUS_IDENTITY, [$columns=ModbusIdentity, $path="modbus_read_device_identification"]);
    }

hook Bacnet::log_policy_property(rec: Bacnet::BACnet_Property, id: Log::ID, filter: Log::Filter)
    {
    if ( rec$object_type != "device" || rec$pdu_service !in set("read-property-ack", "read-property-multiple-ack") ||
         rec$property !in set("model-name", "vendor-name", "vendor-identifier", "object-name") ||
         |rec$value| == 0 || |rec$value| > 512 ) break;
    local packet = get_current_packet_header();
    if ( packet$l2?$vlan ) rec$vlan = fmt("%d", packet$l2$vlan);
    if ( packet$l2?$inner_vlan ) rec$inner_vlan = fmt("%d", packet$l2$inner_vlan);
    }

event modbus_encap_interface_transport_response(c: connection, headers: ModbusHeaders, mei_type: count, data: string)
    {
    if ( mei_type != 14 || |data| < 5 || |data| > 8192 ) return;
    # TCP reassembly is connection-scoped. If the current packet crosses the
    # connection's original VLAN, its assembled product cannot be attributed.
    local packet = get_current_packet_header();
    if ( c?$vlan != packet$l2?$vlan || c?$inner_vlan != packet$l2?$inner_vlan ) return;
    if ( c?$vlan && fmt("%d", c$vlan) != fmt("%d", packet$l2$vlan) ) return;
    if ( c?$inner_vlan && fmt("%d", c$inner_vlan) != fmt("%d", packet$l2$inner_vlan) ) return;
    local n = bytestring_to_count(data[4]);
    if ( n == 0 || n > 32 ) return;
    local values: table[count] of string = table();
    local at: count = 5;
    # First validate the complete PDU so malformed trailing objects never leave
    # a partial set of product evidence in the raw log.
    local i: count = 0;
    while ( i < n )
        {
        if ( at + 2 > |data| ) return;
        local object = bytestring_to_count(data[at]);
        local size = bytestring_to_count(data[at + 1]);
        at += 2;
        if ( at + size > |data| ) return;
        if ( object in set(0, 1, 2, 4, 5) && size > 0 )
            {
            local value = data[at:at+size];
            if ( object in values && values[object] != value ) return;
            values[object] = value;
            }
        at += size;
        ++i;
        }
    if ( at != |data| ) return;
    for ( object_id in values )
        {
        local item = ModbusIdentity($ts=network_time(), $uid=c$uid, $id=c$id,
            $source_h=c$id$resp_h, $source_p=c$id$resp_p,
            $destination_h=c$id$orig_h, $destination_p=c$id$orig_p,
            $unit=headers$uid, $tid=headers$tid,
            $object_id_code=fmt("0x%02x", object_id), $object_value=values[object_id]);
        if ( c?$vlan ) item$vlan = fmt("%d", c$vlan);
        if ( c?$inner_vlan ) item$inner_vlan = fmt("%d", c$inner_vlan);
        Log::write(MODBUS_IDENTITY, item);
        }
    }
