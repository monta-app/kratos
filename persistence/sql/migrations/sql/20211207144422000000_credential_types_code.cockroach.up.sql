INSERT INTO identity_credential_types (id, name) SELECT 'ac8d8b0e-b7fd-47be-922f-a881a07fae34', 'code' WHERE NOT EXISTS ( SELECT * FROM identity_credential_types WHERE name = 'code');
