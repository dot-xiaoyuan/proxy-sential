ALTER TABLE enforcement_connectors ADD COLUMN certificate_pem text NOT NULL DEFAULT '' CHECK (octet_length(certificate_pem)<=65536);
