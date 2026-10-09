@load base/protocols/socks

# The child native analyzer receives complete PDUs; do not also start an
# unframed native analyzer on the same connection.
redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SOCKS };
event zeek_init() &priority=4 {
 Analyzer::register_for_ports(Analyzer::ANALYZER_SENTINEL_SOCKS_STREAM, set(1080/tcp));
 # Preserve protocol diagnostics without retaining authentication credentials.
 for (name in Log::get_filter_names(SOCKS::LOG)) {
  local filter = Log::get_filter(SOCKS::LOG, name);
  if ( ! filter?$exclude ) filter$exclude = set();
  add filter$exclude["user"];
  add filter$exclude["password"];
  Log::add_filter(SOCKS::LOG, filter);
 }
}
