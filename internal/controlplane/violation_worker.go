package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/violation"
)

func (s *Server) startViolationWorker(ctx context.Context) {
	if s.operations == nil || s.operations.db == nil || s.operations.readView {
		return
	}
	// Router evidence can consume its entire bounded batch. Give the online
	// reminder cursor an independent budget so neither observation starves.
	for _, run := range []func(context.Context, time.Time){s.observeRouterCases, s.observeLongOnline} {
		run := run
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				run(runCtx, time.Now().UTC())
				cancel()
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
}

func (s *Server) observeViolationBatch(ctx context.Context, now time.Time) {
	s.observeRouterCases(ctx, now)
	s.observeLongOnline(ctx, now)
}

func (s *Server) nextViolationIDs(ctx context.Context, worker, query string) ([]string, error) {
	var cursor string
	err := s.operations.db.QueryRowContext(ctx, `SELECT cursor_value FROM violation_worker_state WHERE worker_key=$1`, worker).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	rows, err := s.operations.db.QueryContext(ctx, query, cursor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	next := ""
	if len(ids) > 0 {
		next = ids[len(ids)-1]
	}
	_, err = s.operations.db.ExecContext(ctx, `INSERT INTO violation_worker_state(worker_key,cursor_value) VALUES($1,$2)
		ON CONFLICT(worker_key) DO UPDATE SET cursor_value=EXCLUDED.cursor_value,updated_at=now()`, worker, next)
	return ids, err
}

func (s *Server) observeRouterCases(ctx context.Context, now time.Time) {
	reader, ok := s.reader.(store.RouterObservationReader)
	if !ok {
		return
	}
	ids, err := s.nextViolationIDs(ctx, "router", `SELECT assessment_id FROM router_assessments WHERE assessment_id>$1 AND role='router' ORDER BY assessment_id LIMIT 100`)
	if err != nil {
		return
	}
	for _, id := range ids {
		item, found, readErr := reader.GetRouterObservation(ctx, id)
		if readErr != nil || !found {
			continue
		}
		fresh := false
		if at, parseErr := time.Parse(time.RFC3339Nano, item.LastSeen); parseErr == nil {
			fresh = now.Sub(at) <= 24*time.Hour
		}
		accounts := []string{}
		for _, binding := range item.AuthBindings {
			confirmedAt, parseErr := time.Parse(time.RFC3339Nano, binding.LastConfirmedAt)
			if binding.AccountID != "" && !binding.Ambiguous && parseErr == nil && now.Sub(confirmedAt) <= 15*time.Minute {
				present := false
				for _, a := range accounts {
					if a == binding.AccountID {
						present = true
					}
				}
				if !present {
					accounts = append(accounts, binding.AccountID)
				}
			}
		}
		eligible := item.Current && violation.RouterEligible(item.Role, item.ConfirmedRouter && item.Status == "confirmed", item.Ambiguous, accounts, fresh)
		if !eligible {
			kind := "候选排除"
			switch {
			case !fresh || !item.Current:
				kind = "数据滞后"
			case len(accounts) != 1 || item.Ambiguous:
				kind = "身份待核实"
			}
			s.recordOutboundObservation(ctx, "classification:"+id+":"+now.Format("2006-01-02"), kind, id, map[string]any{"assessment_id": id, "rule_version": item.RuleVersion, "role": item.Role, "status": item.Status, "account_count": len(accounts), "reason": "observation_only"})
			_, _ = s.operations.db.ExecContext(ctx, `UPDATE violation_cases SET status='closed',updated_at=now() WHERE assessment_id=$1 AND status='open' AND $2`, id, fresh)
			continue
		}
		_, _ = s.operations.db.ExecContext(ctx, `UPDATE violation_cases SET status='closed',updated_at=now()
			WHERE assessment_id=$1 AND account_id<>$2 AND status='open'`, item.AssessmentID, accounts[0])
		s.advanceViolationCase(ctx, item.AssessmentID, accounts[0], item.RuleVersion, now)
		s.observeSanction(ctx, item.AssessmentID, accounts[0], now)
	}
}

func (s *Server) advanceViolationCase(ctx context.Context, assessmentID, accountID, evidenceVersion string, now time.Time) {
	caseID := "violation:" + assessmentID + ":" + accountID
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO violation_cases(case_id,account_id,assessment_id,status,first_seen,last_seen)
		VALUES($1,$2,$3,'open',$4,$4) ON CONFLICT(account_id,assessment_id) DO NOTHING`, caseID, accountID, assessmentID, now)
	if err != nil {
		return
	}
	var raw []byte
	var c violation.Case
	err = tx.QueryRowContext(ctx, `SELECT case_id,status,first_seen,last_seen,simulated_notice_times,prior_sanctions,COALESCE(last_violation,'epoch'::timestamptz)
		FROM violation_cases WHERE account_id=$1 AND assessment_id=$2 FOR UPDATE`, accountID, assessmentID).Scan(&c.CaseID, &c.Status, &c.FirstSeen, &c.LastSeen, &raw, &c.PriorSanctions, &c.LastViolation)
	if err != nil {
		return
	}
	c.AccountID, c.AssessmentID = accountID, assessmentID
	_ = json.Unmarshal(raw, &c.NoticeTimes)
	if c.Status == "closed" {
		c.Status = "open"
		c.NoticeTimes = nil
		c.FirstSeen = now
	}
	created := c.AdvanceNotice(now, true)
	encoded, _ := json.Marshal(c.NoticeTimes)
	_, err = tx.ExecContext(ctx, `UPDATE violation_cases SET status='open',first_seen=$2,last_seen=$3,simulated_notice_times=$4,updated_at=now() WHERE case_id=$1`, c.CaseID, c.FirstSeen, now, encoded)
	if err != nil {
		return
	}
	if created {
		n := len(c.NoticeTimes)
		facts, _ := json.Marshal(map[string]any{"case_id": c.CaseID, "assessment_id": assessmentID, "evidence_version": evidenceVersion, "sequence": n, "interval_hours": 48, "reason": "observation_only"})
		_, err = tx.ExecContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts) VALUES($1,'拟提醒',$2,$3,$4)
			ON CONFLICT(observation_key) DO NOTHING`, fmt.Sprintf("notice:%s:%d:%s", c.CaseID, n, c.FirstSeen.Format(time.RFC3339Nano)), accountID, c.CaseID, facts)
		if err != nil {
			return
		}
	}
	_ = tx.Commit()
}

func (s *Server) observeSanction(ctx context.Context, assessmentID, accountID string, now time.Time) {
	reader, ok := s.reader.(store.RouterObservationReader)
	if !ok {
		return
	}
	item, found, err := reader.GetRouterObservation(ctx, assessmentID)
	if err != nil || !found || !item.Current {
		return
	}
	lastSeen, err := time.Parse(time.RFC3339Nano, item.LastSeen)
	if err != nil {
		return
	}
	accounts := []string{}
	for _, binding := range item.AuthBindings {
		confirmedAt, parseErr := time.Parse(time.RFC3339Nano, binding.LastConfirmedAt)
		if !binding.Ambiguous && binding.AccountID != "" && parseErr == nil && now.Sub(confirmedAt) <= 5*time.Minute {
			accounts = append(accounts, binding.AccountID)
		}
	}
	unique := map[string]bool{}
	for _, account := range accounts {
		unique[account] = true
	}
	if len(unique) != 1 || !unique[accountID] || !violation.RouterEligible(item.Role, item.ConfirmedRouter && item.Status == "confirmed", item.Ambiguous, []string{accountID}, now.Sub(lastSeen) <= 5*time.Minute) {
		return
	}
	if health := identityPipelineHealth(ctx, s.operations.db); health.Status != "ready" {
		return
	}
	entries, err := s.whitelist.list(ctx)
	if err != nil {
		return
	}
	whitelisted := policy.MatchWhitelist(entries, policy.WhitelistSubject{AccountID: accountID, IP: item.IP}, now) != nil
	var c violation.Case
	var raw []byte
	err = s.operations.db.QueryRowContext(ctx, `SELECT case_id,status,first_seen,last_seen,simulated_notice_times,prior_sanctions,COALESCE(last_violation,'epoch'::timestamptz)
		FROM violation_cases WHERE account_id=$1 AND assessment_id=$2`, accountID, assessmentID).Scan(&c.CaseID, &c.Status, &c.FirstSeen, &c.LastSeen, &raw, &c.PriorSanctions, &c.LastViolation)
	if err != nil {
		return
	}
	c.AccountID, c.AssessmentID = accountID, assessmentID
	if json.Unmarshal(raw, &c.NoticeTimes) != nil {
		return
	}
	decision := c.Decide(now, true, whitelisted, false)
	if decision.Kind != "拟封禁" {
		return
	}
	facts, _ := json.Marshal(map[string]any{"decision": decision, "case_id": c.CaseID, "assessment_id": assessmentID, "evidence_version": item.RuleVersion, "reason": "observation_only"})
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var inserted string
	err = tx.QueryRowContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(observation_key) DO NOTHING RETURNING observation_key`, "sanction:"+c.CaseID+":"+c.FirstSeen.Format(time.RFC3339Nano), decision.Kind, accountID, c.CaseID, facts).Scan(&inserted)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO violation_observations(observation_key,kind,target,case_id,facts) VALUES($1,'拟下线',$2,$3,$4)
			ON CONFLICT(observation_key) DO NOTHING`, "disconnect:"+c.CaseID+":"+c.FirstSeen.Format(time.RFC3339Nano), accountID, c.CaseID, facts)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE violation_cases SET prior_sanctions=$2,last_violation=$3,updated_at=now() WHERE case_id=$1`, c.CaseID, decision.DurationDays, now)
		}
		if err == nil {
			_ = tx.Commit()
		}
	}
}

func (s *Server) observeLongOnline(ctx context.Context, now time.Time) {
	accounts, err := s.nextViolationIDs(ctx, "online7", `SELECT DISTINCT account_id FROM account_sessions
		WHERE account_id>$1 AND ended_at IS NULL AND updated_at>now()-interval '15 minutes' ORDER BY account_id LIMIT 100`)
	if err != nil {
		return
	}
	for _, account := range accounts {
		rows, qerr := s.operations.db.QueryContext(ctx, `SELECT session_id,started_at,COALESCE(ended_at,$2) FROM account_sessions
			WHERE account_id=$1 AND COALESCE(ended_at,$2)>=$2-interval '8 days' ORDER BY started_at DESC LIMIT 1000`, account, now)
		if qerr != nil {
			continue
		}
		intervals := []violation.Interval{}
		sessionIDs := []string{}
		for rows.Next() {
			var item violation.Interval
			var sessionID string
			if rows.Scan(&sessionID, &item.Start, &item.End) == nil {
				intervals = append(intervals, item)
				sessionIDs = append(sessionIDs, sessionID)
			}
		}
		rows.Close()
		if !violation.ContinuousOnline(intervals, now, 7*24*time.Hour, 10*time.Minute) {
			continue
		}
		var recent bool
		qerr = s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM violation_observations WHERE kind='拟核实提醒' AND target=$1 AND observed_at>$2-interval '7 days')`, account, now).Scan(&recent)
		if qerr != nil || recent {
			continue
		}
		s.recordOutboundObservation(ctx, "online7:"+account+":"+now.Format("2006-01-02"), "拟核实提醒", account, map[string]any{"duration_days": 7, "tolerated_gap_minutes": 10, "session_ids": sessionIDs, "reason": "observation_only"})
	}
}
