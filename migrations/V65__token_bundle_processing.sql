-- Revision-scoped outbox: the commit and its processing intent are one row
-- transaction. Metadata contains no token strings or probability arrays.
ALTER TABLE trace_token_bundles ADD COLUMN processing_state TEXT NOT NULL DEFAULT 'pending'
 CHECK(processing_state IN ('pending','ready','revoked'));
ALTER TABLE trace_token_bundles ADD COLUMN processing_summary JSONB;
ALTER TABLE trace_token_bundles ADD COLUMN processing_policy TEXT;
CREATE INDEX trace_token_processing_pending ON trace_token_bundles(tenant_id,processing_state,created_at);
CREATE OR REPLACE FUNCTION trace_revoke_token_bundles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status = 'revoked' OR NEW.withdrawn_at IS NOT NULL OR NEW.purged_at IS NOT NULL THEN
  UPDATE trace_token_bundles SET state='revoked',processing_state='revoked',processing_summary=NULL
   WHERE tenant_id=NEW.tenant_id AND submission_id=NEW.submission_id;
 END IF;
 RETURN NEW;
END $$;
