package controlplane

import (
	"context"
	"encoding/json"
)

func (s *Server) persistSharedObservationMappings(ctx context.Context) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Configuration changes are rare and small. Historical versions stay intact.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(184142)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE shared_observation_mappings SET active=false WHERE active`); err != nil {
		return err
	}
	raw, err := json.Marshal(s.sharedConfig.IdentityMappings)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_observation_mappings(config_version,sensor_id,campus_id,access_domain,identity_source,identity_sensor_id,identity_campus_id,identity_access_domain,valid_from,valid_until,health_bridge_id,active)
 SELECT $1,sensor_id,campus_id,access_domain,identity_source,identity_sensor_id,identity_campus_id,identity_access_domain,valid_from,valid_until,COALESCE(health_bridge_id,''),true FROM jsonb_to_recordset($2::jsonb) r(sensor_id text,campus_id text,access_domain text,identity_source text,identity_sensor_id text,identity_campus_id text,identity_access_domain text,valid_from timestamptz,valid_until timestamptz,health_bridge_id text)
 ON CONFLICT(config_version,sensor_id,campus_id,access_domain,valid_from) DO UPDATE SET active=true`, s.sharedConfig.ID(), raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}
