package discovery

import (
	_ "embed"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

const DeviceSNIKind = "device_sni"
const deviceSNIRuleVersion = "sni-device-services/2026-11-25.1"

//go:embed sni_brand_rules.json
var deviceSNIRules []byte

var deviceSNILibrary = func() *fingerprint.Library {
	library, err := fingerprint.LoadDomainLibrary(deviceSNIRuleVersion, deviceSNIRules)
	if err != nil {
		panic(err)
	}
	return library
}()

// PassiveDeviceSNI returns the reviewed hostname so only catalog values enter
// the behavior projection, including when a service uses many subdomains.
func PassiveDeviceSNI(host string) string {
	if len(host) > 254 || strings.Contains(host, ":") {
		return ""
	}
	match, _ := deviceSNILibrary.MatchDomain(host)
	return match.RuleDomain
}

func summarizeSNIBrand(items []PassiveBehaviorEvidence, knownBrand string, at time.Time) fingerprint.BrandInference {
	type serviceBucket struct {
		service string
		bucket  time.Time
	}
	// Alternate hostnames for the same service within a five-minute bucket
	// count as one observation, just like retransmissions of a handshake.
	type timedEvidence struct {
		at   time.Time
		item fingerprint.DomainEvidence
	}
	byBucket := make(map[serviceBucket]timedEvidence)
	for _, item := range items {
		if item.Kind != DeviceSNIKind {
			continue
		}
		match, ok := deviceSNILibrary.MatchDomain(item.Value)
		if !ok || !match.BrandEligible {
			continue
		}
		bucket := serviceBucket{match.Service, item.BucketAt.UTC()}
		if previous, exists := byBucket[bucket]; !exists || item.ObservedAt.After(previous.at) {
			stamp := item.ObservedAt.UTC().Format(time.RFC3339Nano)
			byBucket[bucket] = timedEvidence{at: item.ObservedAt, item: fingerprint.DomainEvidence{
				RuleVersion: deviceSNIRuleVersion, Match: match, Count: 1, FirstSeen: stamp, LastSeen: stamp,
			}}
		}
	}
	evidence := make([]fingerprint.DomainEvidence, 0, len(byBucket))
	for _, item := range byBucket {
		evidence = append(evidence, item.item)
	}
	return fingerprint.InferBrand(evidence, deviceSNIRuleVersion, at, knownBrand, 1)
}
