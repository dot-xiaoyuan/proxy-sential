package controlplane

import "context"

// Request-local read documents never acquire the mutation lock, start write
// transactions, or decode unrelated case evidence. The shared repositories and
// services remain the same; only the transient operations document is replaced.
func (s *Server) operationsReadView(ctx context.Context) (*Server, error) {
	doc := emptyOperationsDocument()
	if err := loadCaseHeaders(ctx, s.operations.db, &doc); err != nil {
		return nil, err
	}
	if err := loadConnectors(ctx, s.operations.db, &doc); err != nil {
		return nil, err
	}
	if err := loadActions(ctx, s.operations.db, &doc); err != nil {
		return nil, err
	}
	var raw []byte
	err := s.operations.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT setting_value FROM control_plane_settings WHERE setting_key='global_emergency_stop'),'false'::jsonb)`).Scan(&raw)
	if err != nil {
		return nil, err
	}
	doc.GlobalStop = string(raw) == "true"
	view := *s
	view.operations = &operationsState{db: s.operations.db, doc: doc, readView: true}
	return &view, nil
}
