# SIP Server header evidence: a phone or PBX names its stack in responses.
@load base/protocols/sip

module ProxySentinel;

export {
    redef enum Log::ID += { LOG_SIP_SERVER };

    type SIPServerInfo: record {
        ts: time &log;
        uid: string &log;
        orig_h: addr &log;
        orig_p: port &log;
        resp_h: addr &log;
        resp_p: port &log;
        server: string &log;
    };
}

event zeek_init()
    {
    Log::create_stream(ProxySentinel::LOG_SIP_SERVER,
        Log::Stream($columns=ProxySentinel::SIPServerInfo, $path="sip_server"));
    }

# A Server header in a response belongs to the responder. Request headers are
# handled by the User-Agent path in the standard SIP log.
event sip_header(c: connection, is_request: bool, name: string, value: string) &priority=5
    {
    if ( is_request || value == "" )
        return;
    if ( to_lower(name) != "server" )
        return;
    Log::write(ProxySentinel::LOG_SIP_SERVER, ProxySentinel::SIPServerInfo($ts=network_time(),
        $uid=c$uid, $orig_h=c$id$orig_h, $orig_p=c$id$orig_p, $resp_h=c$id$resp_h,
        $resp_p=c$id$resp_p, $server=value));
    }
