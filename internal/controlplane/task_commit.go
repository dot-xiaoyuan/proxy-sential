package controlplane

import (
	"context"
	"database/sql"
	"sync/atomic"
	"time"
)

// Cancellation is checked again after verification, before rule activation.
// The short activation phase locks only its task row until the result commits;
// cancel requests use NOWAIT rather than claiming an activation was cancelled.
type operationTaskCommit struct {
	id, worker  string
	tx          *sql.Tx
	atomicPhase atomic.Bool
	cancel      context.CancelFunc
}
type operationTaskCommitKey struct{}

func (s *Server) operationCommitGuard(ctx context.Context) func() error {
	return func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		guard, ok := ctx.Value(operationTaskCommitKey{}).(*operationTaskCommit)
		if !ok {
			return nil
		}
		if guard.tx != nil {
			return nil
		}
		commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		tx, err := s.operations.db.BeginTx(commitCtx, nil)
		if err != nil {
			cancel()
			return err
		}
		var active bool
		err = tx.QueryRowContext(commitCtx, `SELECT status='running' AND worker_id=$2 FROM control_plane_tasks WHERE task_id=$1 FOR UPDATE`, guard.id, guard.worker).Scan(&active)
		if err != nil || !active {
			tx.Rollback()
			cancel()
			if err != nil {
				return err
			}
			return context.Canceled
		}
		guard.tx, guard.cancel = tx, cancel
		guard.atomicPhase.Store(true)
		return nil
	}
}
