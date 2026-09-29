package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"proxy-sentinel/internal/store"
	"strconv"
	"strings"
)

// The legacy document writer may coexist with scoped writers. It must never
// upsert organization rows that it merely read before a concurrent save.
func organizationFingerprints(doc operationsDocument) map[[2]string]string {
	out := map[[2]string]string{}
	add := func(kind, id string, v any) { raw, _ := json.Marshal(v); out[[2]string{kind, id}] = string(raw) }
	for id, v := range doc.Campuses {
		add("campuses", id, v)
	}
	for id, v := range doc.Buildings {
		add("buildings", id, v)
	}
	for id, v := range doc.NetworkZones {
		add("network_zones", id, v)
	}
	for id, v := range doc.AccessPoints {
		add("access_points", id, v)
	}
	return out
}
func (s *operationsState) changedOrganization() operationsDocument {
	out := emptyOperationsDocument()
	current := organizationFingerprints(s.doc)
	changed := func(kind, id string) bool {
		return current[[2]string{kind, id}] != s.organizationBaseline[[2]string{kind, id}]
	}
	for id, v := range s.doc.Campuses {
		if changed("campuses", id) {
			out.Campuses[id] = v
		}
	}
	for id, v := range s.doc.Buildings {
		if changed("buildings", id) {
			out.Buildings[id] = v
		}
	}
	for id, v := range s.doc.NetworkZones {
		if changed("network_zones", id) {
			out.NetworkZones[id] = v
		}
	}
	for id, v := range s.doc.AccessPoints {
		if changed("access_points", id) {
			out.AccessPoints[id] = v
		}
	}
	return out
}

var organizationTables = map[string]string{"campuses": "campus_id", "buildings": "building_id", "network_zones": "network_zone_id", "access_points": "access_point_id"}

func organizationRowDocument(kind string) string {
	if kind == "access_points" {
		return "to_jsonb(t)||jsonb_build_object('management_ip',coalesce(host(t.management_ip),''))"
	}
	return "to_jsonb(t)"
}

func organizationRows(ctx context.Context, q operationsQuerier, kind string, limit, offset int) (json.RawMessage, error) {
	id, ok := organizationTables[kind]
	if !ok {
		return nil, fmt.Errorf("unknown organization kind")
	}
	// Table/column identifiers are from the fixed whitelist, never request text.
	document := organizationRowDocument(kind)
	query := "SELECT COALESCE(jsonb_agg(" + document + " ORDER BY " + id + "),'[]'::jsonb) FROM (SELECT * FROM " + kind + " ORDER BY " + id
	if limit > 0 {
		query += " LIMIT $1 OFFSET $2"
	}
	query += ") t"
	var raw []byte
	var err error
	if limit > 0 {
		err = q.QueryRowContext(ctx, query, limit, offset).Scan(&raw)
	} else {
		err = q.QueryRowContext(ctx, query).Scan(&raw)
	}
	return json.RawMessage(raw), err
}

func (s *Server) handleOrganizationPostgres(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	fail := func(err error) { writeError(w, 500, "organization_database_failed", err.Error()) }
	if r.Method == http.MethodGet {
		kind := r.URL.Query().Get("kind")
		if kind == "" {
			result := map[string]json.RawMessage{}
			for _, k := range []string{"campuses", "buildings", "network_zones", "access_points"} {
				raw, err := organizationRows(ctx, s.operations.db, k, 0, 0)
				if err != nil {
					fail(err)
					return
				}
				result[k] = raw
			}
			writeJSON(w, 200, result)
			return
		}
		if _, ok := organizationTables[kind]; !ok {
			writeError(w, 400, "bad_organization_kind", "unknown organization kind")
			return
		}
		limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
		if err != nil {
			writeError(w, 400, "bad_page", err.Error())
			return
		}
		offset, err := cursorOffset(r.URL.Query().Get("cursor"))
		if err != nil {
			writeError(w, 400, "bad_page", err.Error())
			return
		}
		// One statement keeps total and rows consistent during concurrent saves.
		id := organizationTables[kind]
		query := "SELECT (SELECT count(*) FROM " + kind + "),COALESCE(jsonb_agg(" + organizationRowDocument(kind) + " ORDER BY " + id + "),'[]'::jsonb) FROM (SELECT * FROM " + kind + " ORDER BY " + id + " LIMIT $1 OFFSET $2) t"
		var total int
		var raw []byte
		if err = s.operations.db.QueryRowContext(ctx, query, limit, offset).Scan(&total, &raw); err != nil {
			fail(err)
			return
		}
		var next *string
		if offset+limit < total {
			v := strconv.Itoa(offset + limit)
			next = &v
		}
		writeJSON(w, 200, map[string]any{"items": json.RawMessage(raw), "page": store.Page{Limit: limit, Total: total, NextCursor: next}})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	kind := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/organization"), "/")
	doc := emptyOperationsDocument()
	var result any
	var campusID, target string
	decode := func(v any) bool { return json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v) == nil }
	switch kind {
	case "campuses":
		var v Campus
		if !decode(&v) || v.CampusID == "" || v.Name == "" {
			writeError(w, 400, "bad_campus", "campus_id and name are required")
			return
		}
		v.Enabled = true
		doc.Campuses[v.CampusID] = v
		target = v.CampusID
		result = v
	case "buildings":
		var v Building
		if !decode(&v) || v.BuildingID == "" || v.CampusID == "" {
			writeError(w, 400, "bad_building", "valid campus_id and building_id are required")
			return
		}
		v.Enabled = true
		doc.Buildings[v.BuildingID] = v
		campusID = v.CampusID
		target = v.BuildingID
		result = v
	case "network-zones":
		var v NetworkZone
		if !decode(&v) || v.NetworkZoneID == "" || v.CampusID == "" {
			writeError(w, 400, "bad_network_zone", "valid campus_id and network_zone_id are required")
			return
		}
		v.Enabled = true
		doc.NetworkZones[v.NetworkZoneID] = v
		campusID = v.CampusID
		target = v.NetworkZoneID
		result = v
	case "access-points":
		var v AccessPoint
		if !decode(&v) || v.AccessPointID == "" || v.CampusID == "" {
			writeError(w, 400, "bad_access_point", "valid campus_id and access_point_id are required")
			return
		}
		v.Enabled = true
		doc.AccessPoints[v.AccessPointID] = v
		campusID = v.CampusID
		target = v.AccessPointID
		result = v
	default:
		writeError(w, 404, "organization_endpoint_not_found", "organization endpoint not found")
		return
	}
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		fail(err)
		return
	}
	defer tx.Rollback()
	if campusID != "" {
		var found bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM campuses WHERE campus_id=$1)", campusID).Scan(&found); err != nil {
			fail(err)
			return
		}
		if !found {
			writeError(w, 400, "bad_organization_parent", "valid campus_id is required")
			return
		}
	}
	if err = saveOrganizationRows(ctx, tx, doc); err != nil {
		fail(err)
		return
	}
	if err = tx.Commit(); err != nil {
		fail(err)
		return
	}
	s.appendAudit(r.Context(), "organization.update", target, "succeeded")
	writeJSON(w, 201, result)
}
