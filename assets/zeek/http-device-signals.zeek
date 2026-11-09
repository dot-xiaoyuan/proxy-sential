# HTTP response evidence for device identification: the Server header of a
# response served by a LAN device (printer/router/camera web UI) and the first
# HTML <title>. Only the response side is logged; the request is linked by the
# connection tuple the ingest already knows.
module ProxySentinel;

export {
    redef enum Log::ID += { LOG_HTTP_DEVICE };
    type HTTPDeviceInfo: record {
        ts: time &log;
        orig_h: addr &log;
        resp_h: addr &log;
        host: string &log &optional;
        server: string &log &optional;
        status: count &log &optional;
        user_agent: string &log &optional;
        title: string &log &optional;
        parser_version: string &log &default = "http-device/v1";
    };
}

redef record connection += {
    ps_http_server: string &optional;
    ps_http_title: string &optional;
    ps_http_title_seen: bool &default = F;
    ps_http_title_body: string &default = "";
    ps_http_html: bool &default = F;
};

event zeek_init()
    {
    Log::create_stream(LOG_HTTP_DEVICE, [$columns=HTTPDeviceInfo, $path="http-device"]);
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    c$ps_http_server = "";
    c$ps_http_title = "";
    c$ps_http_title_seen = F;
    c$ps_http_title_body = "";
    c$ps_http_html = F;
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig )
        return;
    local upper = to_upper(name);
    if ( upper == "SERVER" )
        c$ps_http_server = value;
    else if ( upper == "CONTENT-TYPE" && strstr(to_lower(value), "html") >= 0 )
        c$ps_http_html = T;
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig || c$ps_http_title_seen || ! c?$http || ! c$http?$status_code || c$http$status_code != 200 )
        return;
    if ( ! c$ps_http_html )
        return;
    local keep = 4096;
    local remaining = keep - |c$ps_http_title_body|;
    if ( remaining <= 0 )
        return;
    if ( |data| > remaining )
        data = data[:remaining];
    c$ps_http_title_body = c$ps_http_title_body + data;
    local text = to_lower(c$ps_http_title_body);
    local start = strstr(text, "<title");
    if ( start < 0 )
        return;
    local from = strstr(text[start:], ">");
    if ( from < 0 )
        return;
    local rest = c$ps_http_title_body[start + from + 1:];
    local stop = strstr(to_lower(rest), "</title>");
    if ( stop < 0 )
        {
        if ( |rest| > 120 )
            rest = rest[:120];
        c$ps_http_title = rest;
        return;
        }
    c$ps_http_title = rest[:stop];
    c$ps_http_title_seen = T;
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( is_orig )
        return;
    local item = HTTPDeviceInfo($ts=network_time(), $orig_h=c$id$orig_h, $resp_h=c$id$resp_h);
    if ( c?$http )
        {
        if ( c$http?$host )
            item$host = c$http$host;
        if ( c$http?$status_code )
            item$status = c$http$status_code;
        if ( c$http?$user_agent )
            item$user_agent = c$http$user_agent;
        }
    if ( c?$ps_http_server && c$ps_http_server != "" )
        item$server = c$ps_http_server;
    if ( c?$ps_http_title && c$ps_http_title != "" )
        {
        local title = strip(c$ps_http_title);
        if ( |title| > 120 )
            title = title[:120];
        item$title = title;
        }
    Log::write(LOG_HTTP_DEVICE, item);
    }
