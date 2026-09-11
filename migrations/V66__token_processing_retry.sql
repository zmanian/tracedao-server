ALTER TABLE trace_token_bundles ADD COLUMN processing_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX trace_token_processing_retry ON trace_token_bundles(tenant_id,processing_retry_at) WHERE state='committed' AND processing_state='pending';
