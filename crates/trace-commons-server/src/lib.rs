// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TraceCommons hosted server crate.

pub mod account_native_auth;
pub mod account_near;
pub mod account_onboarding;
pub mod account_passkey;
pub mod account_session;
pub mod admission_evidence;
pub mod admission_ledger;
pub mod audit_chain;
pub mod celestine_sloth_claim;
/// Plumbing shared by the two self-serve claim surfaces.
pub(crate) mod claim_common;
pub mod config;
pub mod contributor_cap;
pub mod correction_value;
pub mod credit_numbers;
pub mod credit_quality;
pub mod db;
pub mod dedup_assign;
pub mod dedup_simhash;
pub mod driver_liveness;
pub mod error;
pub mod inference_funding;
pub mod instance_enroll_guard;
pub mod near_account_identity;
pub mod near_ai_login;
pub mod near_attestation;
pub mod near_credit;
pub mod near_legion_claim;
pub mod redaction_witness;
pub mod register_stats;
pub mod secrets;
pub mod trace_artifact_gcs;
pub mod trace_artifact_kek;
pub mod trace_artifact_store;
pub mod trace_corpus_storage;
pub mod trace_gate_service;
pub mod trace_invite_admin;
pub mod trace_invite_registry;
pub mod trace_score_attestation;
pub mod trace_upload_claim_allowlist;
pub mod trace_upload_claim_issuer;
pub mod trace_upload_claim_issuer_admin;
pub mod witness_service;

pub const TRACE_COMMONS_SERVER_EXTRACTION_STAGE: &str = "server-storage-owned";

pub mod token_bundle_store;
