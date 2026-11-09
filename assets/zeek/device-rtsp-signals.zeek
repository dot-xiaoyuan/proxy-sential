# RTSP device evidence: Zeek parses RTSP as HTTP on the camera ports; this
# stream keeps only the client User-Agent and responder Server headers.
@load base/protocols/http

module ProxySentinel;

export {
    redef enum Log::ID += { LOG_RTSP_DEVICE };

    type RTSPDeviceInfo: record {
        ts: time &log;
        uid: string &log;
        src_h: addr &log;
        src_p: port &log;
        dst_h: addr &log;
        dst_p: port &log;
        method: string &log &optional;
        url: string &log &optional;
        direction: string &log;
        value: string &log;
    };
}

global rtsp_methods: table[string] of string &create_expire=5min;
global rtsp_urls: table[string] of string &create_expire=5min;

function rtsp_port(c: connection): bool
    {
    return c$id$resp_p == 554/tcp || c$id$resp_p == 8554/tcp;
    }

event zeek_init() &priority=4
    {
    Log::create_stream(ProxySentinel::LOG_RTSP_DEVICE,
        Log::Stream($columns=ProxySentinel::RTSPDeviceInfo, $path="rtsp_device"));
    Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, set(554/tcp, 8554/tcp));
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=5
    {
    if ( ! rtsp_port(c) )
        return;
    rtsp_methods[c$uid] = method;
    rtsp_urls[c$uid] = original_URI;
    }

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=4
    {
    if ( ! rtsp_port(c) || value == "" )
        return;
    local lower = to_lower(name);
    local direction = "";
    if ( is_orig && lower == "user-agent" )
        direction = "client";
    else if ( ! is_orig && lower == "server" )
        direction = "server";
    if ( direction == "" )
        return;
    local info = ProxySentinel::RTSPDeviceInfo($ts=network_time(), $uid=c$uid,
        $src_h=c$id$orig_h, $src_p=c$id$orig_p, $dst_h=c$id$resp_h, $dst_p=c$id$resp_p,
        $direction=direction, $value=value);
    if ( c$uid in rtsp_methods )
        info$method = rtsp_methods[c$uid];
    if ( c$uid in rtsp_urls )
        info$url = rtsp_urls[c$uid];
    Log::write(ProxySentinel::LOG_RTSP_DEVICE, info);
    }
