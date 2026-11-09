package store

import "testing"

func TestPassiveRecognitionSignalsKeepsDHCPMessageType(t *testing.T) {
	if protocol, direction := recognitionProtocolDirection("dhcp_message_type"); protocol != "dhcp" || direction != "device" {
		t.Fatalf("direction=%s/%s", protocol, direction)
	}
	if protocol, direction := recognitionProtocolDirection("sip_user_agent"); protocol != "sip" || direction != "client" {
		t.Fatalf("sip direction=%s/%s", protocol, direction)
	}
	if protocol, direction := recognitionProtocolDirection("sip_server"); protocol != "sip" || direction != "server" {
		t.Fatalf("sip server direction=%s/%s", protocol, direction)
	}
	signals := passiveRecognitionSignals([]DiscoveryRecognitionHint{{
		Field: "dhcp_message_type", Origin: "dhcp", Value: "discover,offer,request,ack", ObservationID: "obs-1",
	}})
	if len(signals) != 1 {
		t.Fatalf("signals=%d", len(signals))
	}
	got := signals[0]
	if got.Protocol != "dhcp" || got.Direction != "device" || got.Field != "dhcp_message_type" || got.Value != "discover,offer,request,ack" {
		t.Fatalf("unexpected signal: %+v", got)
	}
}
