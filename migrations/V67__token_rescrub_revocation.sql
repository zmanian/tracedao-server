-- A new redaction result invalidates prior token summaries as well as downloads.
CREATE OR REPLACE FUNCTION trace_revoke_token_bundles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status = 'revoked' OR NEW.withdrawn_at IS NOT NULL OR NEW.purged_at IS NOT NULL
    OR NEW.redaction_hash IS DISTINCT FROM OLD.redaction_hash THEN
  UPDATE trace_token_bundles SET state='revoked',processing_state='revoked',processing_summary=NULL
   WHERE tenant_id=NEW.tenant_id AND submission_id=NEW.submission_id;
 END IF;
 RETURN NEW;
END $$;
