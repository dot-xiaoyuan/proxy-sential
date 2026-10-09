@load base/protocols/snmp

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
    local snmp_filter = Log::get_filter(SNMP::LOG, "default");
    if ( snmp_filter$name == "<not found>" )
        return;
    if ( ! snmp_filter?$exclude )
        snmp_filter$exclude = set();
    add snmp_filter$exclude["community"];
    Log::add_filter(SNMP::LOG, snmp_filter);
    }
