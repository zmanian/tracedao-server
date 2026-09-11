-- Immutable, tenant-scoped bundle lineage. Payloads stay in encrypted object storage.
CREATE TABLE trace_token_bundles (
 tenant_id TEXT NOT NULL REFERENCES trace_tenants(tenant_id),
 submission_id UUID NOT NULL, revision TEXT NOT NULL, owner_ref TEXT NOT NULL,
 manifest_digest TEXT NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
 witness_headers JSONB NOT NULL,
 manifest JSONB NOT NULL CHECK(jsonb_typeof(manifest)='object'),
 state TEXT NOT NULL CHECK(state IN ('staging','committed','revoked')),
 receipt JSONB, expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(tenant_id,submission_id,revision)
);
CREATE TABLE trace_token_attachments (
 tenant_id TEXT NOT NULL, submission_id UUID NOT NULL, revision TEXT NOT NULL,
 artifact_id TEXT NOT NULL, object_ref JSONB NOT NULL,
 deleted BOOLEAN NOT NULL DEFAULT FALSE,
 ready BOOLEAN NOT NULL DEFAULT FALSE,
 -- Temporary encrypted packet, never plaintext tokens. Retained until publish
 -- is confirmed so retries reproduce identical ciphertext and object identity.
 prepared BYTEA CHECK(octet_length(prepared)<=12582912),
 PRIMARY KEY(tenant_id,submission_id,revision,artifact_id),
 FOREIGN KEY(tenant_id,submission_id,revision) REFERENCES trace_token_bundles(tenant_id,submission_id,revision)
);
CREATE INDEX trace_token_bundles_cleanup ON trace_token_bundles(tenant_id,state,expires_at);
ALTER TABLE trace_token_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_token_bundles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS trace_corpus_tenant_isolation ON trace_token_bundles;
CREATE POLICY trace_corpus_tenant_isolation ON trace_token_bundles
 USING(tenant_id=trace_current_tenant_id()) WITH CHECK(tenant_id=trace_current_tenant_id());
ALTER TABLE trace_token_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_token_attachments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS trace_corpus_tenant_isolation ON trace_token_attachments;
CREATE POLICY trace_corpus_tenant_isolation ON trace_token_attachments
 USING(tenant_id=trace_current_tenant_id()) WITH CHECK(tenant_id=trace_current_tenant_id());
-- A parent revocation blocks reads even before asynchronous object deletion.
CREATE FUNCTION trace_revoke_token_bundles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status = 'revoked' OR NEW.withdrawn_at IS NOT NULL OR NEW.purged_at IS NOT NULL THEN
  UPDATE trace_token_bundles SET state='revoked' WHERE tenant_id=NEW.tenant_id AND submission_id=NEW.submission_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trace_revoke_token_bundles_after_update AFTER UPDATE ON trace_submissions
 FOR EACH ROW EXECUTE FUNCTION trace_revoke_token_bundles();
