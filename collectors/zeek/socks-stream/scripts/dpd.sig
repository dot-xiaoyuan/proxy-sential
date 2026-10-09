signature sentinel_socks5_stream_client {
 ip-proto == tcp
 tcp-state originator
 payload /^\x05[\x01-\xff]./
}
signature sentinel_socks5_stream_server {
 ip-proto == tcp
 tcp-state responder
 requires-reverse-signature sentinel_socks5_stream_client
 payload /^\x05[\x00\x02]/
 enable "Sentinel_SOCKS_Stream"
}
signature sentinel_socks4_stream_client {
 ip-proto == tcp
 tcp-state originator
 payload /^\x04[\x01\x02].{0,32}\x00/
}
signature sentinel_socks4_stream_server {
 ip-proto == tcp
 tcp-state responder
 requires-reverse-signature sentinel_socks4_stream_client
 payload /^\x00[\x5a-\x5d]/
 enable "Sentinel_SOCKS_Stream"
}
signature sentinel_socks4_stream_reverse_client {
 ip-proto == tcp
 tcp-state responder
 payload /^\x04[\x01\x02].{0,32}\x00/
}
signature sentinel_socks4_stream_reverse_server {
 ip-proto == tcp
 tcp-state originator
 requires-reverse-signature sentinel_socks4_stream_reverse_client
 payload /^\x00[\x5a-\x5d]/
 enable "Sentinel_SOCKS_Stream"
}
