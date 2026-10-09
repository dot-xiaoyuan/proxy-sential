package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type actionPrecheckReadError struct{ cause error }

func (e actionPrecheckReadError) Error() string { return "动作投递前校验暂不可用" }
func (e actionPrecheckReadError) Unwrap() error { return e.cause }

// Lock only the local document, without opening the legacy global transaction.
// Context-aware waiting avoids extending a dispatch guard beyond its deadline.
func (s *Server) lockActionPrecheckDocument(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.operations.mu.Mutex.TryLock() {
			if err := ctx.Err(); err != nil {
				s.operations.mu.Mutex.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Server) actionPrecheckConnectorType(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.operations.db != nil && !s.operations.readView {
		var kind string
		err := s.operations.db.QueryRowContext(ctx, `SELECT connector_type FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&kind)
		if interrupted := ctx.Err(); interrupted != nil {
			return "", interrupted
		}
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", actionPrecheckReadError{cause: err}
		}
		return kind, nil
	}
	if err := s.lockActionPrecheckDocument(ctx); err != nil {
		return "", err
	}
	kind := s.operations.doc.Connectors[id].ConnectorType
	s.operations.mu.Mutex.Unlock()
	return kind, ctx.Err()
}

func (s *Server) srunEventChannelStatusContext(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.operations == nil || s.operations.db == nil {
		return false, nil
	}
	var state string
	err := s.operations.db.QueryRowContext(ctx, `SELECT event_channel_state FROM srun4k_integrations WHERE connector_id=$1`, id).Scan(&state)
	if interrupted := ctx.Err(); interrupted != nil {
		return false, interrupted
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, actionPrecheckReadError{cause: err}
	}
	return state == "healthy", nil
}

func (s *Server) readNativeActionAdmission(ctx context.Context, id string) (EnforcementAction, ActionConnector, bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return EnforcementAction{}, ActionConnector{}, false, false, err
	}
	if s.operations.db != nil && !s.operations.readView {
		doc := emptyOperationsDocument()
		if err := loadActionsScoped(ctx, s.operations.db, &doc, ` WHERE action_id=$1`, []any{id}); err != nil {
			return EnforcementAction{}, ActionConnector{}, false, false, actionPrecheckReadError{cause: err}
		}
		a, exists := doc.Actions[id]
		if !exists {
			return a, ActionConnector{}, false, false, nil
		}
		if err := loadConnectorsScoped(ctx, s.operations.db, &doc, ` WHERE connector_id=$1`, []any{a.ConnectorID}); err != nil {
			return a, ActionConnector{}, false, true, actionPrecheckReadError{cause: err}
		}
		if err := loadEmergencyStop(ctx, s.operations.db, &doc); err != nil {
			return a, ActionConnector{}, false, true, actionPrecheckReadError{cause: err}
		}
		return a, doc.Connectors[a.ConnectorID], doc.GlobalStop, true, ctx.Err()
	}
	if err := s.lockActionPrecheckDocument(ctx); err != nil {
		return EnforcementAction{}, ActionConnector{}, false, false, err
	}
	a, exists := s.operations.doc.Actions[id]
	connector := s.operations.doc.Connectors[a.ConnectorID]
	stopped := s.operations.doc.GlobalStop || s.operations.lockErr != nil
	s.operations.mu.Mutex.Unlock()
	return a, connector, stopped, exists, ctx.Err()
}
