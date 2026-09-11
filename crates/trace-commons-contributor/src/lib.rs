//! Contributor-side client for trace-commons-server: discovers local coding
//! agent transcripts, redacts them through the deterministic pipeline, and
//! submits TraceContributionEnvelopes under instance-vouched per-user
//! identities.

pub mod account_auth;
pub(crate) mod antigravity;
pub mod brand;
pub mod commands;
pub mod compute;
pub mod config;
pub mod consent;
pub mod consent_copy;
pub mod daemon;
pub mod envelope;
pub mod harness_state;
pub mod identity;
pub mod issuer_client;
pub mod onboarding_copy;
pub mod picker;
pub mod pricing;
pub mod private_inference_copy;
pub mod routing;
pub mod routing_copy;
pub mod source;
pub mod source_copy;
pub mod submit;
pub mod token_bundle;
pub mod token_capture_client;
pub mod token_review_lease;
pub mod update;
pub mod watch_events;
pub mod withdraw;
pub mod witness;
pub mod witness_copy;

pub mod evidence_import;
