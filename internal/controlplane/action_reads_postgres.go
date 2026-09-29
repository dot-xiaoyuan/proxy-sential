package controlplane

import (
	"database/sql"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

func (s *Server) actionReadPostgres(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		writeError(w, 503, "action_read_unavailable", err.Error())
		return
	}
	defer tx.Rollback()
	doc := emptyOperationsDocument()
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/actions"), "/")
	fail := func(err error) { writeError(w, 503, "action_read_unavailable", err.Error()) }
	if rest == "" {
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
		var total int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_actions`).Scan(&total); err != nil {
			fail(err)
			return
		}
		if err = loadActionsScoped(ctx, tx, &doc, ` ORDER BY created_at DESC,action_id DESC LIMIT $1 OFFSET $2`, []any{limit, offset}); err != nil {
			fail(err)
			return
		}
		items := mapValues(doc.Actions)
		sort.Slice(items, func(i, j int) bool {
			if items[i].CreatedAt == items[j].CreatedAt {
				return items[i].ActionID > items[j].ActionID
			}
			return items[i].CreatedAt > items[j].CreatedAt
		})
		var next *string
		if offset+limit < total {
			value := strconv.Itoa(offset + limit)
			next = &value
		}
		page := store.Page{Limit: limit, Total: total, NextCursor: next}
		writeJSON(w, 200, map[string]any{"items": items, "page": page})
		return
	}
	parts := strings.Split(rest, "/")
	if parts[0] == "connectors" {
		suffix := ""
		var args []any
		if len(parts) > 1 {
			suffix = ` WHERE connector_id=$1`
			args = []any{parts[1]}
		}
		if err = loadConnectorsScoped(ctx, tx, &doc, suffix, args); err != nil {
			fail(err)
			return
		}
		if len(parts) == 1 {
			for id, v := range doc.Connectors {
				v.ShadowCandidateCount, v.ShadowReviewedCount, v.ShadowAccuracy = 0, 0, 0
				v.ShadowReady = false
				if until, err := time.Parse(time.RFC3339Nano, v.CircuitOpenUntil); err == nil && !until.After(time.Now()) {
					v.CircuitOpenUntil = ""
					v.ConsecutiveFailures = 0
				}
				doc.Connectors[id] = v
			}
			// SQL computes reviewed shadow coverage without loading every action or
			// case document into an HTTP request.
			rows, err := tx.QueryContext(ctx, `SELECT a.connector_id,min(a.created_at),count(*),count(*) FILTER(WHERE c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data')),count(*) FILTER(WHERE c.disposition='confirmed_proxy'),bool_or(c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data','confirmed_proxy')) FROM enforcement_actions a JOIN enforcement_connectors e USING(connector_id) LEFT JOIN risk_cases c ON c.case_id=a.case_id WHERE a.mode='shadow' AND a.status='shadow' AND (e.shadow_validation_since IS NULL OR a.created_at>=e.shadow_validation_since) GROUP BY a.connector_id`)
			if err != nil {
				fail(err)
				return
			}
			for rows.Next() {
				var id string
				var earliest time.Time
				var candidates, reviewed, correct int
				var falseAction bool
				if err = rows.Scan(&id, &earliest, &candidates, &reviewed, &correct, &falseAction); err != nil {
					rows.Close()
					fail(err)
					return
				}
				v, ok := doc.Connectors[id]
				if !ok {
					continue
				}
				v.ShadowCandidateCount, v.ShadowReviewedCount = candidates, reviewed
				v.ShadowStartedAt = formatDBTime(earliest)
				if reviewed > 0 {
					v.ShadowAccuracy = float64(correct) / float64(reviewed)
				}
				v.ShadowReady = candidates > 0 && reviewed == candidates && time.Since(earliest) >= 7*24*time.Hour && v.ShadowAccuracy >= .95 && !falseAction
				doc.Connectors[id] = v
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				fail(err)
				return
			}
			items := mapValues(doc.Connectors)
			sort.Slice(items, func(i, j int) bool {
				if items[i].Name == items[j].Name {
					return items[i].ConnectorID < items[j].ConnectorID
				}
				return items[i].Name < items[j].Name
			})
			var stop bool
			if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT setting_value::text::boolean FROM control_plane_settings WHERE setting_key='global_emergency_stop'),false)`).Scan(&stop); err != nil {
				fail(err)
				return
			}
			writeJSON(w, 200, map[string]any{"items": items, "global_stop": stop})
			return
		}
	} else {
		if err = loadActionsScoped(ctx, tx, &doc, ` WHERE action_id=$1`, []any{parts[0]}); err != nil {
			fail(err)
			return
		}
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, doc: doc, readView: true}
	view.handleActions(w, r.WithContext(ctx))
}
