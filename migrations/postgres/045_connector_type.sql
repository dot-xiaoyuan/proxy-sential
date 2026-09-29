ALTER TABLE enforcement_connectors ADD COLUMN connector_type text NOT NULL DEFAULT 'hmac' CHECK (connector_type IN ('hmac','srun4k'));
