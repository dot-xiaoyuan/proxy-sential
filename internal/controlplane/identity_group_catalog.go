package controlplane

import (
	"context"
	"fmt"
	"time"

	"proxy-sentinel/internal/store"
)

// refreshIdentityGroupCatalog republishes the groups observed in an identity
// snapshot into the compact group directory, so the policy scope selector never
// has to deserialize the full online inventory.
//
// Identity events carry a group id and no name, so entries are written without a
// name and the selector falls back to the id. The complete named directory, when
// a site has it, is written by the 4K northbound sync under a different source
// key and is never deactivated or blanked here.
//
// An empty observation is skipped on purpose: it must not replace a directory
// that already has entries.
func (s *Server) refreshIdentityGroupCatalog(ctx context.Context, snapshot store.IdentitySnapshot) error {
	if s == nil || s.operations == nil || s.operations.db == nil || snapshot.Source == "" {
		return nil
	}
	groups := observedIdentityGroups(snapshot)
	if len(groups) == 0 {
		return nil
	}
	observedAt := snapshot.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	key := identityGroupCatalogSource(snapshot.Source)
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE srun4k_group_catalog SET active=false,updated_at=now() WHERE source=$1`, key); err != nil {
		return err
	}
	for _, group := range groups {
		if _, err = tx.ExecContext(ctx, `INSERT INTO srun4k_group_catalog(source,group_id,name,parent_id,path,active,observed_at) VALUES($1,$2,$3,'','',true,$4) ON CONFLICT(source,group_id) DO UPDATE SET name=EXCLUDED.name,active=true,observed_at=EXCLUDED.observed_at,updated_at=now()`,
			key, group.ID, group.Name, observedAt); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,'identity-bridge','integration.identity.groups',$2,$3,now())`,
		"audit-identity-groups-"+shortToken(16), key, fmt.Sprintf("observed:%d", len(groups))); err != nil {
		return err
	}
	return tx.Commit()
}

// observedIdentityGroups returns the distinct group ids present in a snapshot.
func observedIdentityGroups(snapshot store.IdentitySnapshot) []fourKDirectoryItem {
	_, groups, _ := fourKIdentityDirectory(snapshot)
	return groups
}
