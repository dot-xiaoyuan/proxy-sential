package eventbus

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// ReliableTopicStatus describes the finite replay window actually configured
// for one existing topic. A one-replica topic has no broker failure protection.
type ReliableTopicStatus struct {
	Partitions    int
	Replicas      int
	Retention     time.Duration
	SingleReplica bool
}

// PreflightReliableTopic is called before a durable source begins capture.
// Metadata requests explicitly disallow topic creation, even if a future
// producer option accidentally allows it. A topic may still change after this
// check; continuous broker and consumer watermarks remain operational gates.
func (p *KafkaProducer) PreflightReliableTopic(ctx context.Context, topic string) (ReliableTopicStatus, error) {
	if p == nil || p.client == nil || topic == "" {
		return ReliableTopicStatus{}, errors.New("reliable event bus topic preflight requires a producer and topic")
	}
	metadataReq := kmsg.NewPtrMetadataRequest()
	metadataReq.Topics = []kmsg.MetadataRequestTopic{{Topic: &topic}}
	metadataReq.AllowAutoTopicCreation = false
	metadata, err := metadataReq.RequestWith(ctx, p.client)
	if err != nil {
		return ReliableTopicStatus{}, fmt.Errorf("reliable event bus topic metadata: %w", err)
	}
	configsReq := kmsg.NewPtrDescribeConfigsRequest()
	configsReq.Resources = []kmsg.DescribeConfigsRequestResource{{
		ResourceType: kmsg.ConfigResourceTypeTopic, ResourceName: topic,
		ConfigNames: []string{"retention.ms", "retention.bytes", "cleanup.policy", "min.insync.replicas"},
	}}
	configs, err := configsReq.RequestWith(ctx, p.client)
	if err != nil {
		return ReliableTopicStatus{}, fmt.Errorf("reliable event bus topic config: %w", err)
	}
	return validateReliableTopic(topic, metadata, configs)
}

func validateReliableTopic(topic string, metadata *kmsg.MetadataResponse, configs *kmsg.DescribeConfigsResponse) (ReliableTopicStatus, error) {
	if metadata == nil || len(metadata.Topics) != 1 || metadata.Topics[0].Topic == nil || *metadata.Topics[0].Topic != topic || metadata.Topics[0].ErrorCode != 0 || len(metadata.Topics[0].Partitions) == 0 {
		return ReliableTopicStatus{}, fmt.Errorf("reliable event bus requires existing topic %s with partitions", topic)
	}
	if configs == nil || len(configs.Resources) != 1 || configs.Resources[0].ResourceType != kmsg.ConfigResourceTypeTopic || configs.Resources[0].ResourceName != topic || configs.Resources[0].ErrorCode != 0 {
		return ReliableTopicStatus{}, fmt.Errorf("reliable event bus topic %s config is unavailable", topic)
	}
	values := make(map[string]string, len(configs.Resources[0].Configs))
	for _, entry := range configs.Resources[0].Configs {
		if entry.Value != nil {
			values[entry.Name] = strings.TrimSpace(*entry.Value)
		}
	}
	retentionMS, err := strconv.ParseInt(values["retention.ms"], 10, 64)
	if err != nil || retentionMS < int64((7*24*time.Hour)/time.Millisecond) || retentionMS > (1<<63-1)/int64(time.Millisecond) {
		return ReliableTopicStatus{}, errors.New("reliable event bus topic requires finite retention.ms of at least seven days")
	}
	if values["retention.bytes"] != "-1" {
		return ReliableTopicStatus{}, errors.New("reliable event bus topic requires retention.bytes=-1 so size pressure cannot silently shorten replay")
	}
	if values["cleanup.policy"] != "delete" {
		return ReliableTopicStatus{}, errors.New("reliable event bus topic requires cleanup.policy=delete")
	}
	minISR, err := strconv.Atoi(values["min.insync.replicas"])
	if err != nil || minISR < 1 {
		return ReliableTopicStatus{}, errors.New("reliable event bus topic requires a valid min.insync.replicas")
	}
	replicas := 0
	for _, partition := range metadata.Topics[0].Partitions {
		if partition.ErrorCode != 0 || partition.Leader < 0 || len(partition.Replicas) == 0 || len(partition.ISR) != len(partition.Replicas) {
			return ReliableTopicStatus{}, fmt.Errorf("reliable event bus topic partition %d lacks an in-sync replica or leader", partition.Partition)
		}
		if replicas == 0 {
			replicas = len(partition.Replicas)
		}
		if len(partition.Replicas) != replicas {
			return ReliableTopicStatus{}, errors.New("reliable event bus topic has inconsistent partition replica counts")
		}
		if minISR > len(partition.ISR) {
			return ReliableTopicStatus{}, fmt.Errorf("reliable event bus topic partition %d cannot meet min.insync.replicas", partition.Partition)
		}
	}
	return ReliableTopicStatus{Partitions: len(metadata.Topics[0].Partitions), Replicas: replicas, Retention: time.Duration(retentionMS) * time.Millisecond, SingleReplica: replicas == 1}, nil
}
