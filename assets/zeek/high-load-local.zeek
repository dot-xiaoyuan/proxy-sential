# Single-node capture policy: keep logs consumed by Proxy Sentinel and expose
# capture health. This file is loaded by workers through ZeekControl local.zeek.
@load policy/misc/stats
@load policy/misc/capture-loss
@load base/protocols/conn
@load base/frameworks/files
@load base/frameworks/notice/weird
@load ./local-device-signals

event zeek_init() &priority=-5
    {
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(Weird::LOG);
    Log::disable_stream(Files::LOG);
    }
