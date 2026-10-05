-- Run once as the PostgreSQL DBA, after migrations/bootstrap and before running
-- the service. Set a generated login password out-of-band; never check it in.
-- gateway_runtime is deliberately not the schema/object owner or a superuser.
-- Use a separate migration/installation credential for migrate/bootstrap.
-- The deployment uses a dedicated database; these grants target its public schema.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_runtime') THEN
        CREATE ROLE gateway_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END $$;
ALTER ROLE gateway_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='public' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname='gateway_runtime')
    ) OR EXISTS (
        SELECT 1 FROM pg_namespace
         WHERE nspname='public' AND nspowner=(SELECT oid FROM pg_roles WHERE rolname='gateway_runtime')
    ) OR EXISTS (
        SELECT 1 FROM pg_database WHERE datname=current_database()
         AND datdba=(SELECT oid FROM pg_roles WHERE rolname='gateway_runtime')
    ) THEN
        RAISE EXCEPTION 'runtime role must not own the database, schema or database objects';
    END IF;
END $$;
-- Temporary tables can shadow unqualified names in the reference trigger
-- functions. This dedicated database does not need application temp tables.
DO $$ BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM gateway_runtime', current_database());
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM gateway_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM gateway_runtime;
GRANT USAGE ON SCHEMA public TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON users, client_integrations TO gateway_runtime;
-- Retention removes revoked identities only after their last audit reference
-- expires. The audit composite FK rejects deleting identities still in use.
GRANT SELECT, INSERT, UPDATE, DELETE ON external_identities TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_credentials, admin_sessions TO gateway_runtime;
GRANT SELECT ON trusted_identity_settings, pseudonym_settings, detector_profile_versions TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_versions, policy_rules, policy_dictionaries,
    dictionary_versions, dictionary_entries TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON active_policy TO gateway_runtime;
GRANT SELECT, INSERT ON policy_activations TO gateway_runtime;
GRANT SELECT, UPDATE ON provider_config, audit_retention_settings TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_events TO gateway_runtime;
GRANT SELECT, INSERT ON audit_event_states, audit_findings TO gateway_runtime;
-- Cascaded retention deletion runs through the parent FK action. Direct state
-- history/findings mutation, configuration deletion, migration and trigger DDL
-- are intentionally unavailable to the application role.
