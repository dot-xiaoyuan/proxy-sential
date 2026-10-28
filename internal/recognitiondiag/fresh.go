// Package recognitiondiag contains compact forward-only diagnostics. It never
// changes evidence, enqueues recognition work or treats storage as HTTP proof.
package recognitiondiag

import (
	"strings"
	"time"

	"proxy-sentinel/internal/streamidentity"
)

type Input struct {
	Protocol       string    `json:"protocol"`
	Parsed         bool      `json:"parsed"`
	Features       int       `json:"features"`
	MAC            string    `json:"mac,omitempty"`
	IP             string    `json:"ip,omitempty"`
	Sensor         string    `json:"sensor,omitempty"`
	Site           string    `json:"site,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	VLAN           string    `json:"vlan,omitempty"`
	VRF            string    `json:"vrf,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	AddressBinding bool      `json:"address_binding,omitempty"`
	Observed       time.Time `json:"observed"`
	ValidUntil     time.Time `json:"valid_until"`
	Withdrawn      bool      `json:"withdrawn,omitempty"`
	EvidenceEvent  string    `json:"evidence_event,omitempty"`
	Targets        []Target  `json:"targets,omitempty"`
}
type Target struct {
	Endpoint   string `json:"endpoint_id"`
	Generation int64  `json:"generation"`
}
type Job struct {
	Endpoint    string             `json:"endpoint_id"`
	Processed   int64              `json:"processed"`
	CompletedAt time.Time          `json:"completed_at"`
	Error       string             `json:"error,omitempty"`
	Candidates  int                `json:"candidates"`
	Conclusions int                `json:"conclusions"`
	Reason      string             `json:"reason"`
	Timings     map[string]float64 `json:"timings,omitempty"`
}
type Decision struct {
	Status      string             `json:"status"`
	CompletedAt time.Time          `json:"-"`
	Overdue     bool               `json:"overdue"`
	Candidates  int                `json:"candidates"`
	Conclusions int                `json:"conclusions"`
	Error       string             `json:"last_error,omitempty"`
	Timings     map[string]float64 `json:"timings,omitempty"`
}

// Evaluate uses the original receipt acceptance and the job completion fence.
// A later observer run cannot turn an on-time completion into a timeout.
func Evaluate(input Input, jobs []Job, accepted, now time.Time) Decision {
	d := Decision{Status: "processing", Overdue: now.Sub(accepted) > 5*time.Second}
	if len(input.Targets) == 0 {
		d.Status = "unattributed"
		if !input.ValidUntil.IsZero() && !input.ValidUntil.After(now) {
			d.Status = "unattributed_expired"
		}
		return d
	}
	completed := accepted
	allDone := true
	conflict := false
	for _, target := range input.Targets {
		found := false
		for _, job := range jobs {
			if job.Endpoint != target.Endpoint {
				continue
			}
			found = true
			if job.Error != "" {
				d.Error = truncate(job.Error, 256)
			}
			if job.Processed < target.Generation || job.CompletedAt.IsZero() {
				allDone = false
				continue
			}
			if job.CompletedAt.After(completed) {
				completed = job.CompletedAt
			}
			d.Candidates += job.Candidates
			if len(job.Timings) > 0 {
				if d.Timings == nil {
					d.Timings = map[string]float64{}
				}
				for key, value := range job.Timings {
					d.Timings[key] += value
				}
			}
			d.Conclusions += job.Conclusions
			conflict = conflict || job.Reason == "conflict"
		}
		if !found {
			allDone = false
		}
	}
	if !allDone {
		d.Candidates, d.Conclusions = 0, 0
		d.Timings = nil
		return d
	}
	d.CompletedAt = completed
	d.Overdue = completed.Sub(accepted) > 5*time.Second
	switch {
	case input.Withdrawn:
		d.Status = "withdrawn"
		d.Candidates, d.Conclusions = 0, 0
	case !input.ValidUntil.IsZero() && !input.ValidUntil.After(completed):
		d.Status = "expired"
		d.Candidates, d.Conclusions = 0, 0
	case conflict:
		d.Status = "conflict"
	case d.Conclusions > 0:
		d.Status = "concluded"
	default:
		d.Status = "insufficient_evidence"
	}
	return d
}
func truncate(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// TargetsLateralSQL runs only in the background observer. Old annotations that
// lack physical scope cannot acquire IP ownership through a wildcard match.
// Materialize the resolved MAC once per receipt so PostgreSQL can use the MAC
// index rather than inline the resolver into a full endpoint scan.
const TargetsLateralSQL = `LEFT JOIN LATERAL (
 SELECT CASE WHEN count(*)=1 THEN jsonb_agg(jsonb_build_object('endpoint_id',endpoint_id,'generation',dirty_generation)) ELSE '[]'::jsonb END AS targets
 FROM (
  SELECT e.endpoint_id,j.dirty_generation
  FROM (
   WITH resolved_mac AS MATERIALIZED (
    SELECT identity.mac
    FROM (SELECT v.recognition_input AS association) v ` + streamidentity.MACLateralSQL + `
   )
   SELECT mac FROM resolved_mac
  ) identity
  JOIN endpoint_entities e ON e.primary_mac=identity.mac
  JOIN endpoint_recognition_jobs j USING(endpoint_id)
  WHERE jsonb_array_length(COALESCE(v.recognition_input->'targets','[]'::jsonb))=0
   AND e.entity_role='endpoint'
  ORDER BY e.endpoint_id LIMIT 2
 ) owners
) ownership ON true`

type Protocol struct {
	Name    string
	Purpose string
}

// An interface is not field coverage: zero fresh input is reported explicitly.
var Protocols = []Protocol{
	{"dhcp", "product"}, {"dhcpv6", "product"}, {"lldp", "product"}, {"cdp", "product"},
	{"dns_sd", "product"}, {"mdns", "product"}, {"ssdp", "product"}, {"snmp", "product"},
	{"http", "server"}, {"tls", "server"}, {"ipp", "product"}, {"onvif", "product"},
	{"ws_discovery", "product"}, {"ssh", "server"}, {"sip", "server"}, {"mqtt", "product"},
	{"coap", "product"}, {"bacnet", "product"}, {"rtsp", "fields_pending"},
	{"arp", "association"}, {"ndp", "association"}, {"ieee1905", "association"},
}
