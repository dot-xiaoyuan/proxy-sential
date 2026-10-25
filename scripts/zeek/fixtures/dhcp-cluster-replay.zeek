# Synthetic worker messages exercise Broker transport without registering any
# connection in the manager (or in the worker's packet engine).
# Keep all test logs local; no ZeekControl archive/delete commands on shutdown.
redef Log::default_rotation_interval = 0secs;
redef Log::default_rotation_postprocessor_cmd = "";

global replay_finished: event();
global replay_stop: event();
global replay_started = F;
global received_messages: count = 0;

function fixture_conn(name: string, outer: int, inner: int): connection
    {
    local ep = endpoint($size=0, $state=0, $flow_label=0);
    local c = connection($id=[$orig_h=192.0.2.10, $orig_p=68/udp,
                             $resp_h=192.0.2.1, $resp_p=67/udp, $proto=17],
                         $orig=ep, $resp=ep, $start_time=network_time(),
                         $duration=0secs, $service=set(), $history="", $uid=name);
    if ( outer >= 0 ) c$vlan = outer;
    if ( inner >= 0 ) c$inner_vlan = inner;
    return c;
    }

function fixture_msg(xid: count, kind: count): DHCP::Msg
    {
    return DHCP::Msg($op=kind == 3 ? 1 : 2, $m_type=kind, $xid=xid,
                     $secs=0secs, $flags=0, $ciaddr=0.0.0.0,
                     $yiaddr=kind == 5 ? 192.0.2.10 : 0.0.0.0,
                     $siaddr=192.0.2.1, $giaddr=0.0.0.0,
                     $chaddr="02:00:00:00:00:10");
    }

function replay_case(name: string, xid: count, outer: int, inner: int,
                     broadcast: bool, reply_outer: int, reply_inner: int)
    {
    local c = fixture_conn(cat(name, "-client"), outer, inner);
    local request = fixture_msg(xid, 3);
    local client_opts = DHCP::Options($host_name=name,
        $param_list=vector(1, 3, 6, 15, 119, 252), $vendor_class="sentinel-fixture");
    event dhcp_message(c, T, request, client_opts);

    local server = fixture_conn(cat(name, "-server"), reply_outer, reply_inner);
    if ( broadcast )
        server$id = [$orig_h=192.0.2.1, $orig_p=67/udp,
                      $resp_h=255.255.255.255, $resp_p=68/udp, $proto=17];
    local ack = fixture_msg(xid, 5);
    # Server options must not overwrite the client's fingerprint.
    local server_opts = DHCP::Options($lease=600secs,
        $param_list=vector(254), $vendor_class="server-must-not-overwrite");
    event dhcp_message(server, broadcast, ack, server_opts);
    }

function replay()
    {
    if ( replay_started ) return;
    replay_started = T;
    replay_case("untagged-unicast", 1001, -1, -1, F, -1, -1);
    replay_case("untagged-broadcast", 1002, -1, -1, T, -1, -1);
    replay_case("single-vlan", 1003, 42, -1, T, 42, -1);
    replay_case("double-vlan", 1004, 100, 42, F, 100, 42);
    replay_case("different-vlan", 1006, 42, -1, T, 43, -1);
    replay_case("untagged-to-tagged", 1007, -1, -1, T, 42, -1);
    replay_case("tagged-to-untagged", 1008, 42, -1, T, -1, -1);
    replay_case("different-inner-vlan", 1009, 100, 42, T, 100, 43);
    event replay_finished();
    }

event Cluster::node_up(name: string, id: string)
    {
    if ( Cluster::local_node_type() == Cluster::WORKER && name == "manager" )
        replay();
    }

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string,
                          is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=2000
    {
    if ( connection_exists(id) )
        Reporter::error("fixture unexpectedly has a local connection");
    ++received_messages;
    }

event replay_finished()
    {
    if ( Cluster::local_node_type() == Cluster::WORKER )
        {
        Cluster::publish(Cluster::manager_topic, replay_finished);
        return;
        }

    # A directly delivered aggregate with no worker VLAN metadata must still
    # retain options/ACK time without inventing an untagged capture scope.
    local c = fixture_conn("missing-metadata", -1, -1);
    event DHCP::aggregate_msgs(network_time(), c$id, c$uid, T,
        fixture_msg(1010, 3), DHCP::Options($host_name="missing-metadata",
            $param_list=vector(1, 3, 6, 15, 119, 252), $vendor_class="sentinel-fixture"));
    event DHCP::aggregate_msgs(network_time(), c$id, c$uid, F,
        fixture_msg(1010, 5), DHCP::Options($lease=600secs));
    schedule 1sec { replay_stop() };
    }

event replay_stop()
    {
    if ( Cluster::local_node_type() == Cluster::MANAGER )
        Cluster::publish(Cluster::worker_topic, replay_stop);
    terminate();
    }

event zeek_done() &priority=-10
    {
    if ( Cluster::local_node_type() == Cluster::MANAGER )
        print fmt("fixture received %d DHCP messages without local connections", received_messages);
    }
