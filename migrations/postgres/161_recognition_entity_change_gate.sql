-- Entity heartbeat writes advance last_seen very frequently. Recognition reads the
-- same fingerprints until a material entity field or evidence source changes, so
-- enqueueing every heartbeat makes the recognition queue grow with traffic volume.
-- Keep a bounded hourly refresh of summary timestamps; endpoint_inventory_lookup
-- reads endpoint_entities.last_seen directly for current list freshness.
DROP TRIGGER IF EXISTS endpoint_recognition_entity_dirty ON endpoint_entities;
DROP TRIGGER IF EXISTS endpoint_recognition_entity_insert_dirty ON endpoint_entities;

CREATE TRIGGER endpoint_recognition_entity_insert_dirty
AFTER INSERT ON endpoint_entities
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

CREATE TRIGGER endpoint_recognition_entity_dirty
AFTER UPDATE ON endpoint_entities
FOR EACH ROW
WHEN (
 OLD.primary_mac IS DISTINCT FROM NEW.primary_mac
 OR OLD.entity_role IS DISTINCT FROM NEW.entity_role
 OR OLD.first_seen IS DISTINCT FROM NEW.first_seen
 OR OLD.identity_confidence IS DISTINCT FROM NEW.identity_confidence
 OR OLD.attributes IS DISTINCT FROM NEW.attributes
 OR OLD.registration_status IS DISTINCT FROM NEW.registration_status
 OR OLD.owner_account IS DISTINCT FROM NEW.owner_account
 OR OLD.owner_name IS DISTINCT FROM NEW.owner_name
 OR OLD.owner_department IS DISTINCT FROM NEW.owner_department
 OR OLD.asset_tag IS DISTINCT FROM NEW.asset_tag
 OR OLD.ownership_class IS DISTINCT FROM NEW.ownership_class
 OR OLD.registered_by IS DISTINCT FROM NEW.registered_by
 OR OLD.registered_at IS DISTINCT FROM NEW.registered_at
 OR OLD.registration_note IS DISTINCT FROM NEW.registration_note
 OR OLD.merge_status IS DISTINCT FROM NEW.merge_status
 OR OLD.merged_into_endpoint_id IS DISTINCT FROM NEW.merged_into_endpoint_id
 OR OLD.split_from_endpoint_id IS DISTINCT FROM NEW.split_from_endpoint_id
 OR OLD.registration_updated_by IS DISTINCT FROM NEW.registration_updated_by
 OR OLD.registration_updated_at IS DISTINCT FROM NEW.registration_updated_at
 OR date_trunc('hour', OLD.last_seen) IS DISTINCT FROM date_trunc('hour', NEW.last_seen)
)
EXECUTE FUNCTION enqueue_endpoint_recognition_job();
