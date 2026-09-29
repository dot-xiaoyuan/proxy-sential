CREATE FUNCTION invalidate_managed_identity_on_connector_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.endpoint_url IS DISTINCT FROM NEW.endpoint_url
 OR OLD.certificate_pem IS DISTINCT FROM NEW.certificate_pem
 OR OLD.connector_type IS DISTINCT FROM NEW.connector_type
 OR OLD.mode IS DISTINCT FROM NEW.mode
 OR OLD.enabled IS DISTINCT FROM NEW.enabled THEN
  UPDATE enforcement_identity_sources SET config_version=config_version+1,state='pending',blocker='connector_configuration_changed',observed_at=NULL,updated_at=now() WHERE connector_id=NEW.connector_id;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER enforcement_identity_connector_epoch AFTER UPDATE ON enforcement_connectors FOR EACH ROW EXECUTE FUNCTION invalidate_managed_identity_on_connector_change();

CREATE FUNCTION invalidate_managed_identity_on_authorization_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE enforcement_identity_sources SET config_version=config_version+1,state='pending',blocker='authorization_configuration_changed',observed_at=NULL,updated_at=now() WHERE connector_id=NEW.connector_id;
 RETURN NEW;
END;
$$;
CREATE TRIGGER enforcement_identity_authorization_epoch AFTER INSERT OR UPDATE ON enforcement_4k_databases FOR EACH ROW EXECUTE FUNCTION invalidate_managed_identity_on_authorization_change();
