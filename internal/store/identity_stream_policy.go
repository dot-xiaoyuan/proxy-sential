package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/normalized"
)

type identityStreamPolicyInput struct {
	Event    normalized.Event
	Sequence int64
	Ordinal  int
	Accepted time.Time
}

// Fresh fragments already have a durable, ordered receipt in the inbox header.
// Selected policy facts use that same source position so repeated event IDs do
// not create random writes into the legacy global history and receipt indexes.
func writeIdentityStreamPolicyFacts(ctx context.Context, tx *sql.Tx, scope string, inputs []identityStreamPolicyInput) error {
	if len(inputs) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(inputs))
	for _, input := range inputs {
		encodedEvent, err := json.Marshal(input.Event)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(encodedEvent)
		for variant, session := range policyRows([]normalized.Event{input.Event}) {
			encodedSession, err := json.Marshal(session)
			if err != nil {
				return err
			}
			rows = append(rows, map[string]any{
				"batch_sequence": input.Sequence, "ordinal": input.Ordinal, "variant": variant,
				"event_id": input.Event.EventID, "campus_id": session.CampusID, "access_domain": session.AccessDomain,
				"observed_at": session.ConfirmedAt.UTC(),
				"accepted_at": input.Accepted.UTC(), "session_data": json.RawMessage(encodedSession),
				"content_sha256": hex.EncodeToString(hash[:]),
			})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_stream_policy_facts(scope_key,batch_sequence,ordinal,variant,event_id,campus_id,access_domain,observed_at,accepted_at,session_data,content_sha256)
SELECT $1,r.batch_sequence,r.ordinal,r.variant,r.event_id,r.campus_id,r.access_domain,r.observed_at,r.accepted_at,r.session_data,r.content_sha256
FROM jsonb_to_recordset($2::jsonb) r(batch_sequence bigint,ordinal integer,variant smallint,event_id text,campus_id text,access_domain text,observed_at timestamptz,accepted_at timestamptz,session_data jsonb,content_sha256 text)
	ORDER BY r.batch_sequence,r.ordinal,r.variant`, scope, encoded)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `SELECT shared_wake_identity_stream_batch($1::jsonb)`, encoded)
	return err
}
