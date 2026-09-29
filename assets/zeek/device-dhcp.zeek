# Standard DHCP options retained for passive device recognition and lease ownership.
@load base/protocols/dhcp
module DHCP;
export {
 redef record DHCP::Info += {
  requested_options: string &log &optional;
  vendor_class: string &log &optional;
  lease_observed_at: time &log &optional;
 };
}
event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=4
 {
 local is_client = is_orig && (id$orig_h == 0.0.0.0 || id$orig_p == 68/udp || id$resp_p == 67/udp);
 if ( is_client && options?$param_list )
  {
  local values = "";
  for ( i in options$param_list )
   values = fmt("%s%s%d", values, values == "" ? "" : ",", options$param_list[i]);
  log_info$requested_options = values;
  }
 if ( is_client && options?$vendor_class )
  log_info$vendor_class = options$vendor_class;
 if ( !is_client && msg$m_type == 5 )
  log_info$lease_observed_at = ts;
 }
