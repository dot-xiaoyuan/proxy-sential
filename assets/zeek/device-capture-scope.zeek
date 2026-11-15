# Capture tags belong to the observed connection, including QinQ order.
@load policy/frameworks/conn_key/vlan_fivetuple
module ProxySentinel;
export {
    global device_capture_vlan: function(c: connection): string;
}
function device_capture_vlan(c: connection): string
    {
    if ( c?$vlan && c?$inner_vlan ) return fmt("%d/%d", c$vlan, c$inner_vlan);
    if ( c?$vlan ) return fmt("%d", c$vlan);
    return "";
    }
