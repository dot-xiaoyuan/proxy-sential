package eventbus

import (
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

func reliableTopicFixtures() (*kmsg.MetadataResponse, *kmsg.DescribeConfigsResponse) {
	topic := DefaultDiscoveryTopic
	value := func(s string) *string { return &s }
	metadata := &kmsg.MetadataResponse{Topics: []kmsg.MetadataResponseTopic{{
		Topic: &topic, Partitions: []kmsg.MetadataResponseTopicPartition{{
			Partition: 0, Leader: 1, Replicas: []int32{1}, ISR: []int32{1},
		}},
	}}}
	configs := &kmsg.DescribeConfigsResponse{Resources: []kmsg.DescribeConfigsResponseResource{{
		ResourceType: kmsg.ConfigResourceTypeTopic, ResourceName: topic,
		Configs: []kmsg.DescribeConfigsResponseResourceConfig{
			{Name: "retention.ms", Value: value("604800000")},
			{Name: "retention.bytes", Value: value("-1")},
			{Name: "cleanup.policy", Value: value("delete")},
			{Name: "min.insync.replicas", Value: value("1")},
		},
	}}}
	return metadata, configs
}

func TestReliableTopicPreflightRequiresExistingBoundedTopic(t *testing.T) {
	metadata, configs := reliableTopicFixtures()
	status, err := validateReliableTopic(DefaultDiscoveryTopic, metadata, configs)
	if err != nil {
		t.Fatal(err)
	}
	if status.Partitions != 1 || status.Replicas != 1 || status.Retention != 7*24*time.Hour || !status.SingleReplica {
		t.Fatalf("wrong topic contract: %+v", status)
	}

	t.Run("missing topic", func(t *testing.T) {
		m, c := reliableTopicFixtures()
		m.Topics = nil
		if _, err := validateReliableTopic(DefaultDiscoveryTopic, m, c); err == nil || !strings.Contains(err.Error(), "existing topic") {
			t.Fatalf("missing topic accepted: %v", err)
		}
	})
	t.Run("unavailable replica", func(t *testing.T) {
		m, c := reliableTopicFixtures()
		m.Topics[0].Partitions[0].ISR = nil
		if _, err := validateReliableTopic(DefaultDiscoveryTopic, m, c); err == nil || !strings.Contains(err.Error(), "in-sync") {
			t.Fatalf("out-of-sync topic accepted: %v", err)
		}
	})
	for _, tc := range []struct {
		name, config, value, want string
	}{
		{"short retention", "retention.ms", "3600000", "retention.ms"},
		{"unbounded retention", "retention.ms", "-1", "retention.ms"},
		{"size cap", "retention.bytes", "1073741824", "retention.bytes"},
		{"compaction", "cleanup.policy", "compact", "cleanup.policy"},
		{"bad minimum ISR", "min.insync.replicas", "2", "min.insync.replicas"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := reliableTopicFixtures()
			for i := range c.Resources[0].Configs {
				if c.Resources[0].Configs[i].Name == tc.config {
					c.Resources[0].Configs[i].Value = &tc.value
				}
			}
			if _, err := validateReliableTopic(DefaultDiscoveryTopic, m, c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bad topic config accepted: %v", err)
			}
		})
	}
}
