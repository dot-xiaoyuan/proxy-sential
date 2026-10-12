// Package devicehistory provides paginated presentation summaries. Raw evidence
// is never rewritten or deleted. Runs are consecutive within an identity stream.
package devicehistory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Query struct {
	Kind, ID, Group string
	Keys            []string
	Limit, Offset   int
	AsOf            time.Time
}
type Item struct {
	ID        string          `json:"id"`
	Stream    string          `json:"stream"`
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
	Count     int             `json:"count"`
	Content   json.RawMessage `json:"content"`
}
type Page struct {
	Items  []Item    `json:"items"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
	AsOf   time.Time `json:"as_of"`
}

// Explicit semantic fields prevent heartbeat metadata from becoming changes.
// Unknown raw fields remain available through the raw page; identity, rule,
// score, conflict and withdrawal fields are intentionally included here.
func projection(alias string, keys ...string) string {
	out := "jsonb_build_object("
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		value := alias + "->'" + k + "'"
		switch k {
		case "addresses", "capabilities", "conflicts", "signal_groups", "assigned_ips":
			value = "(SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]'::jsonb) FROM (SELECT DISTINCT value v FROM jsonb_array_elements(CASE WHEN jsonb_typeof(" + value + ")='array' THEN " + value + " ELSE '[]'::jsonb END)) a)"
		}
		out += "'" + k + "'," + value
	}
	return out + ")"
}
func source(q Query) (string, any, error) {
	switch q.Kind {
	case "router_evidence":
		semantic := projection("data", "source", "source_family", "source_event_type", "kind", "ip", "mac", "vlan", "brand", "model", "role", "raw_value", "strength", "score", "rule_id", "rule_version", "conflict", "conflict_code", "exclusion", "association_quality", "explanation")
		return `SELECT evidence_id id,last_seen at,concat_ws(':',assessment_id,source,source_family,kind) stream,data payload,` + semantic + ` semantic FROM router_evidence_facts WHERE assessment_id=$1`, q.ID, nil

	case "router":
		return `SELECT lpad(history_id::text,20,'0') id,changed_at at,assessment_id stream,to_jsonb(h) payload,
 jsonb_build_object('status',status,'confidence',confidence,'rule_version',rule_version,'conflicts',conflicts) semantic
 FROM router_assessment_history h WHERE assessment_id=$1`, q.ID, nil
	case "profile":
		semantic := projection("payload", "endpoint_id", "mac", "ip", "vlan", "addresses", "display_name", "brand", "model", "role", "role_source", "router_status", "confidence", "identity_conflict", "identity_state", "identity_current", "identity_basis", "address_state", "current_shared", "shared_confidence", "latest_account_id", "latest_account_active", "latest_account_match_basis", "account_conflict", "rule_version")
		semantic += " || jsonb_build_object('auth_bindings',(SELECT coalesce(jsonb_agg(binding ORDER BY binding::text),'[]'::jsonb) FROM (SELECT DISTINCT " + projection("value", "account_id", "assigned_ips", "mac", "vlan", "nas_ip", "access_id", "match_basis", "ambiguous", "source") + " binding FROM jsonb_array_elements(CASE WHEN jsonb_typeof(payload->'auth_bindings')='array' THEN payload->'auth_bindings' ELSE '[]'::jsonb END)) bindings))"
		return `SELECT lpad(history_id::text,20,'0') id,observed_at at,profile_id stream,payload,` + semantic + ` semantic FROM shared_device_profile_history WHERE profile_id=$1`, q.ID, nil
	case "shared":
		semantic := projection("h.observation", "endpoint_id", "ip", "status", "confidence", "signal_groups", "coverage_state", "rule_version", "conflicts", "strong_anchor", "device_lower_bound", "router")
		return `SELECT lpad(h.history_id::text,20,'0') id,h.observed_at at,concat_ws(':',o.sensor_id,o.campus_id,o.access_domain,host(o.ip)) stream,h.observation payload,` + semantic + ` semantic FROM shared_behavior_observation_history h JOIN shared_behavior_observations o USING(observation_id) JOIN shared_behavior_observations target ON target.observation_id=$1 AND o.sensor_id=target.sensor_id AND o.campus_id=target.campus_id AND o.access_domain=target.access_domain AND o.ip=target.ip`, q.ID, nil
	case "endpoint_discovery":
		base, _, _ := source(Query{Kind: "discovery"})
		base = strings.Replace(base, "device_key IN(SELECT jsonb_array_elements_text($1::jsonb))", "id IN(SELECT observation_id FROM discovery_identity_links WHERE endpoint_id=$1)", 1)
		return base, q.ID, nil

	case "discovery":
		keys, _ := json.Marshal(q.Keys)
		semantic := projection("data", "node", "site", "domain", "vlan", "vrf", "ip", "mac", "name", "manufacturer", "model_name", "origin", "port", "interface", "device_type", "capabilities", "confidence", "rule_version", "config_version", "withdrawn")
		return `SELECT id,observed_at at,concat_ws(':',device_key,source_id,origin,coalesce(data->'evidence'->'payload'->>'service_type',''),coalesce(data->>'port','')) stream,data payload,` + semantic + ` || jsonb_build_object('service',data->'evidence'->'payload'->'service_type','target',data->'evidence'->'payload'->'service_target','instance',data->'evidence'->'payload'->'service_instance') semantic FROM discovery_observations WHERE device_key IN(SELECT jsonb_array_elements_text($1::jsonb))`, string(keys), nil
	case "access":
		return `SELECT lpad(history_id::text,20,'0') id,last_seen at,concat_ws(':',endpoint_id,source) stream,to_jsonb(h) payload,jsonb_build_object('access_id',access_id,'account_id',account_id,'ap',ap,'switch_id',switch_id,'switch_port',switch_port,'vlan',vlan,'source',source) semantic FROM identity_access_history h WHERE endpoint_id=$1`, q.ID, nil

	case "endpoint":
		return `SELECT lpad(history_id::text,20,'0') id,last_seen at,concat_ws(':',endpoint_id,source) stream,to_jsonb(h) payload,jsonb_build_object('ip',host(ip),'mac',mac,'account_id',account_id,'entity_role',entity_role,'source',source) semantic FROM identity_ip_mac_history h WHERE endpoint_id=$1`, q.ID, nil
	default:
		return "", nil, fmt.Errorf("invalid history kind")
	}
}

// The window order includes a stable event ID. Group IDs are stream + run start,
// not a content hash: A → B → A must have three distinct runs. Counts and pages
// both use the same grouped relation, including empty/out-of-range pages.
func groupedSQL(raw string) string {
	return `WITH raw AS (` + raw + `), bounded AS(SELECT * FROM raw WHERE at<=$2), changes AS(
 SELECT *,CASE WHEN lag(semantic) OVER(PARTITION BY stream ORDER BY at,id)=semantic THEN 0 ELSE 1 END changed FROM bounded
), runs AS(SELECT *,sum(changed) OVER(PARTITION BY stream ORDER BY at,id) run FROM changes), grouped AS(
 SELECT md5(stream||':'||min(id) FILTER(WHERE changed=1)) id,stream,min(at) first_seen,max(at) last_seen,count(*) count,
 min(semantic::text)::jsonb content,run FROM runs GROUP BY stream,run
) `
}
func Read(ctx context.Context, db *sql.DB, q Query) (Page, error) {
	if q.Limit < 1 || q.Limit > 100 {
		q.Limit = 20
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.AsOf.IsZero() {
		q.AsOf = time.Now().UTC()
	}
	page := Page{Items: []Item{}, Limit: q.Limit, Offset: q.Offset, AsOf: q.AsOf}
	raw, arg, err := source(q)
	if err != nil {
		return page, err
	}
	cte := groupedSQL(raw)
	relation := "SELECT id,stream,first_seen,last_seen,count,content FROM grouped"
	args := []any{arg, q.AsOf, q.Limit, q.Offset}
	if q.Group != "" {
		relation = `SELECT r.id,r.stream,r.at first_seen,r.at last_seen,1::bigint count,r.payload content FROM runs r JOIN grouped g USING(stream,run) WHERE g.id=$5`
		args = append(args, q.Group)
	}
	// A single statement gives one MVCC snapshot for count and page.
	var data []byte
	err = db.QueryRowContext(ctx, cte+`, selected AS (`+relation+`), page AS(SELECT * FROM selected ORDER BY last_seen DESC,id LIMIT $3 OFFSET $4)
 SELECT coalesce((SELECT jsonb_agg(to_jsonb(page) ORDER BY last_seen DESC,id) FROM page),'[]'::jsonb),(SELECT count(*) FROM selected)`, args...).Scan(&data, &page.Total)
	if err != nil {
		return page, err
	}
	err = json.Unmarshal(data, &page.Items)
	return page, err
}
