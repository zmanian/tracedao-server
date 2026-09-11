//! Versioned token attachments. These types do not enable capture or upload.
//!
//! Token payloads deliberately do not implement Debug. Only the witness may
//! turn raw records into sanitized records after contextual alternative checks.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_ALTERNATIVES: usize = 20;
pub const MAX_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BUNDLE_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ATTACHMENTS: usize = 4096;
pub const MAX_REDACTION_EDITS: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DistributionError {
    #[error("unsupported-token-schema")]
    Version,
    #[error("invalid-token-distribution")]
    Invalid,
    #[error("token-distribution-limit")]
    Limit,
    #[error("token-byte-alignment-mismatch")]
    Alignment,
    #[error("token-artifact-digest-mismatch")]
    Digest,
    #[error("token-bundle-receipt-mismatch")]
    Receipt,
    #[error("invalid-token-redaction-map")]
    Redaction,
}

/// Lowercase SHA-256 of exact bytes, never of a parsed/reserialized response.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentDigest(String);
impl ContentDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }
    pub fn validate(&self) -> Result<(), DistributionError> {
        if self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(())
        } else {
            Err(DistributionError::Digest)
        }
    }
    pub fn matches(&self, bytes: &[u8]) -> bool {
        *self == Self::of(bytes)
    }
}

/// All spans in this module use UTF-8 bytes, not classifier codepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteSpan {
    pub start: u64,
    pub end: u64,
}
impl ByteSpan {
    fn range(self, len: usize) -> Result<std::ops::Range<usize>, DistributionError> {
        let start = usize::try_from(self.start).map_err(|_| DistributionError::Alignment)?;
        let end = usize::try_from(self.end).map_err(|_| DistributionError::Alignment)?;
        if start >= end || end > len {
            return Err(DistributionError::Alignment);
        }
        Ok(start..end)
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LogProbability {
    Finite(#[serde(with = "finite_probability")] f64),
    NegativeInfinity,
    Unavailable,
}
// A decimal string preserves parsed FP64 values across serde_json feature
// unification: decoding uses Rust's correctly rounded float parser. JSON
// number decoding without float_roundtrip can otherwise move a value one ULP.
mod finite_probability {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
        if !value.is_finite() || *value > 0.0 {
            return Err(serde::ser::Error::custom("invalid-logprob"));
        }
        serializer.serialize_str(&format!("{value:e}"))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > 32 {
            return Err(serde::de::Error::custom("invalid-logprob"));
        }
        let number: f64 = value
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid-logprob"))?;
        if !number.is_finite() || number > 0.0 {
            return Err(serde::de::Error::custom("invalid-logprob"));
        }
        Ok(number)
    }
}

impl LogProbability {
    fn validate(&self) -> Result<(), DistributionError> {
        match self {
            Self::Finite(v) if !v.is_finite() || *v > 0.0 => Err(DistributionError::Invalid),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenValue {
    /// Provider bytes can split a UTF-8 codepoint. Never decode them lossily.
    pub bytes: Vec<u8>,
    pub token_id: Option<u64>,
    pub logprob: LogProbability,
}
impl TokenValue {
    fn validate(&self) -> Result<(), DistributionError> {
        if self.bytes.is_empty() || self.bytes.len() > 65536 {
            return Err(DistributionError::Limit);
        }
        self.logprob.validate()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    pub index: u64,
    pub span: ByteSpan,
    pub chosen: TokenValue,
    pub alternatives: Vec<TokenValue>,
    pub returned_alternatives: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbabilitySemantics {
    PreSampling,
    Processed,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    ProviderResponseVerified,
    WitnessFilteredOnly,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conditioning {
    Original,
    OutboundSubstituted,
    Unknown,
}

/// V1 distributions have no public/general-export profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenUsageProfile {
    RestrictedResearch,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDistribution {
    pub version: u32,
    pub capture_store_id: String,
    pub exchange_id: String,
    pub event_id: String,
    pub choice: u32,
    pub segment: u32,
    pub requested_model: String,
    pub served_model: Option<String>,
    pub tokenizer: Option<String>,
    pub semantics: ProbabilitySemantics,
    pub conditioning: Conditioning,
    pub requested_alternatives: u32,
    pub response_digest: ContentDigest,
    pub records: Vec<TokenRecord>,
}

fn identifier(value: &str) -> Result<(), DistributionError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:/".contains(&c))
    {
        Err(DistributionError::Invalid)
    } else {
        Ok(())
    }
}

impl TokenDistribution {
    /// Validates complete, contiguous coverage of this single original segment.
    /// Partial/unmappable segments must be omitted, not aligned by text search.
    pub fn validate(&self, response: &[u8]) -> Result<(), DistributionError> {
        if self.version != SCHEMA_VERSION {
            return Err(DistributionError::Version);
        }
        if response.len() > MAX_ATTACHMENT_BYTES {
            return Err(DistributionError::Limit);
        }
        for id in [
            &self.capture_store_id,
            &self.exchange_id,
            &self.event_id,
            &self.requested_model,
        ] {
            identifier(id)?;
        }
        for id in [&self.served_model, &self.tokenizer].into_iter().flatten() {
            identifier(id)?;
        }
        if self.requested_alternatives > MAX_ALTERNATIVES as u32 || self.records.len() > 131072 {
            return Err(DistributionError::Limit);
        }
        if !self.response_digest.matches(response) {
            return Err(DistributionError::Digest);
        }
        let mut end = 0;
        let mut payload_bytes = 0usize;
        for (index, record) in self.records.iter().enumerate() {
            let range = record.span.range(response.len())?;
            if record.index != index as u64
                || range.start != end
                || record.chosen.bytes != response[range.clone()]
            {
                return Err(DistributionError::Alignment);
            }
            record.chosen.validate()?;
            payload_bytes = payload_bytes.saturating_add(record.chosen.bytes.len());
            for alt in &record.alternatives {
                payload_bytes = payload_bytes.saturating_add(alt.bytes.len());
            }
            if payload_bytes > MAX_ATTACHMENT_BYTES {
                return Err(DistributionError::Limit);
            }
            if record.alternatives.len() > MAX_ALTERNATIVES
                || record.alternatives.len() > record.returned_alternatives as usize
            {
                return Err(DistributionError::Limit);
            }
            for alt in &record.alternatives {
                alt.validate()?;
            }
            end = range.end;
        }
        if end != response.len() {
            return Err(DistributionError::Alignment);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8], response: &[u8]) -> Result<Self, DistributionError> {
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(DistributionError::Limit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| DistributionError::Invalid)?;
        value.validate(response)?;
        Ok(value)
    }
}

/// Private witness working data. Do not persist or include in certified output.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactionEdit {
    pub original: ByteSpan,
    pub replacement: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedTokenRecord {
    /// Index in the sanitized record list; original token indices are private.
    pub index: u64,
    pub span: ByteSpan,
    pub chosen: TokenValue,
    pub alternatives: Vec<TokenValue>,
    pub returned_alternatives: u32,
}
/// Provider-reported values are distinct from verified serving identity.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMetadata {
    pub requested_alternatives: Option<u32>,
    pub reported_model: Option<String>,
    pub evidence: Option<EvidenceCoverage>,
    pub sampling: std::collections::BTreeMap<String, f64>,
    pub redacted_records: u64,
    pub redacted_alternatives: u64,
    pub unsupported_records: u64,
    #[serde(default)]
    pub unsupported_alternatives: u64,
    pub budget_alternatives: u64,
    pub provider_truncated_alternatives: u64,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedTokenAttachment {
    #[serde(default)]
    pub metadata: TokenMetadata,
    pub version: u32,
    pub capture_store_id: String,
    pub exchange_id: String,
    pub requested_model: String,
    pub served_model: Option<String>,
    pub tokenizer: Option<String>,
    pub semantics: ProbabilitySemantics,
    pub conditioning: Conditioning,
    pub event_id: String,
    pub choice: u32,
    pub segment: u32,
    pub response_digest: ContentDigest,
    pub policy_version: String,
    pub records: Vec<SanitizedTokenRecord>,
    pub omitted_records: u64,
    pub omitted_alternatives: u64,
}

/// A callback must screen alternatives in context. Failure drops the position.
/// This helper does not itself establish PII safety or provider provenance.
/// The witness must verify source evidence before calling it or signing output.
pub fn filter_with_edits<F>(
    source: &TokenDistribution,
    original: &[u8],
    sanitized: &[u8],
    edits: &[RedactionEdit],
    policy_version: &str,
    mut screen: F,
) -> Result<SanitizedTokenAttachment, DistributionError>
where
    F: FnMut(&TokenDistribution, usize, &[u8]) -> Option<Vec<bool>>,
{
    source.validate(original)?;
    if edits.len() > MAX_REDACTION_EDITS || sanitized.len() > MAX_ATTACHMENT_BYTES {
        return Err(DistributionError::Limit);
    }
    identifier(policy_version)?;
    let mut reconstructed = Vec::new();
    let mut cursor = 0;
    for edit in edits {
        let range = edit
            .original
            .range(original.len())
            .map_err(|_| DistributionError::Redaction)?;
        if range.start < cursor {
            return Err(DistributionError::Redaction);
        }
        if reconstructed
            .len()
            .saturating_add(range.start - cursor)
            .saturating_add(edit.replacement.len())
            > MAX_ATTACHMENT_BYTES
        {
            return Err(DistributionError::Limit);
        }
        reconstructed.extend_from_slice(&original[cursor..range.start]);
        reconstructed.extend_from_slice(&edit.replacement);
        cursor = range.end;
    }
    if reconstructed.len().saturating_add(original.len() - cursor) > MAX_ATTACHMENT_BYTES {
        return Err(DistributionError::Limit);
    }
    reconstructed.extend_from_slice(&original[cursor..]);
    if reconstructed != sanitized {
        return Err(DistributionError::Redaction);
    }
    let mut output = SanitizedTokenAttachment {
        metadata: TokenMetadata {
            requested_alternatives: Some(source.requested_alternatives),
            provider_truncated_alternatives: source
                .records
                .iter()
                .map(|r| {
                    u64::from(r.returned_alternatives).saturating_sub(r.alternatives.len() as u64)
                })
                .sum(),
            ..Default::default()
        },
        version: SCHEMA_VERSION,
        capture_store_id: source.capture_store_id.clone(),
        exchange_id: source.exchange_id.clone(),
        requested_model: source.requested_model.clone(),
        served_model: source.served_model.clone(),
        tokenizer: source.tokenizer.clone(),
        semantics: source.semantics.clone(),
        conditioning: source.conditioning.clone(),
        event_id: source.event_id.clone(),
        choice: source.choice,
        segment: source.segment,
        response_digest: ContentDigest::of(sanitized),
        policy_version: policy_version.into(),
        records: Vec::new(),
        omitted_records: 0,
        omitted_alternatives: 0,
    };
    let mut edit_cursor = 0;
    let mut shift = 0i128;
    for (position, record) in source.records.iter().enumerate() {
        while edit_cursor < edits.len() && edits[edit_cursor].original.end <= record.span.start {
            let edit = &edits[edit_cursor];
            shift +=
                edit.replacement.len() as i128 - (edit.original.end - edit.original.start) as i128;
            edit_cursor += 1;
        }
        if edits
            .get(edit_cursor)
            .is_some_and(|e| e.original.overlaps(record.span))
        {
            output.omitted_records += 1;
            output.metadata.redacted_records += 1;
            output.metadata.redacted_alternatives += record.alternatives.len() as u64;
            output.omitted_alternatives += record.alternatives.len() as u64;
            continue;
        }
        let Some(keep) =
            screen(source, position, original).filter(|v| v.len() == record.alternatives.len())
        else {
            output.metadata.unsupported_records += 1;
            output.omitted_records += 1;
            output.omitted_alternatives += record.alternatives.len() as u64;
            continue;
        };
        let start = record.span.start as i128 + shift;
        let end = record.span.end as i128 + shift;
        let span = ByteSpan {
            start: u64::try_from(start).map_err(|_| DistributionError::Redaction)?,
            end: u64::try_from(end).map_err(|_| DistributionError::Redaction)?,
        };
        if sanitized[span.range(sanitized.len())?] != record.chosen.bytes {
            return Err(DistributionError::Redaction);
        }
        let alternatives = record
            .alternatives
            .iter()
            .zip(keep)
            .filter_map(|(value, keep)| {
                if keep {
                    Some(value.clone())
                } else {
                    output.omitted_alternatives += 1;
                    output.metadata.redacted_alternatives += 1;
                    None
                }
            })
            .collect();
        output.records.push(SanitizedTokenRecord {
            index: output.records.len() as u64,
            span,
            chosen: record.chosen.clone(),
            alternatives,
            returned_alternatives: record.returned_alternatives,
        });
    }
    Ok(output)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentDescriptor {
    pub artifact_id: String,
    pub event_id: String,
    pub content_digest: ContentDigest,
    /// V1 is uncompressed JSON. New codecs require a new protocol version.
    pub size_bytes: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionBundleManifest {
    pub version: u32,
    pub usage_profile: TokenUsageProfile,
    pub submission_id: String,
    pub bundle_revision: String,
    pub envelope_digest: ContentDigest,
    pub consent_digest: ContentDigest,
    pub policy_version: String,
    pub attachments: Vec<AttachmentDescriptor>,
}
impl ContributionBundleManifest {
    pub fn validate(&self) -> Result<(), DistributionError> {
        if self.version != SCHEMA_VERSION {
            return Err(DistributionError::Version);
        }
        for id in [
            &self.submission_id,
            &self.bundle_revision,
            &self.policy_version,
        ] {
            identifier(id)?;
        }
        self.envelope_digest.validate()?;
        self.consent_digest.validate()?;
        if self.attachments.len() > MAX_ATTACHMENTS {
            return Err(DistributionError::Limit);
        }
        let mut ids = BTreeSet::new();
        let mut total = 0u64;
        for attachment in &self.attachments {
            identifier(&attachment.artifact_id)?;
            identifier(&attachment.event_id)?;
            attachment.content_digest.validate()?;
            if attachment.artifact_id == "envelope" || !ids.insert(&attachment.artifact_id) {
                return Err(DistributionError::Invalid);
            }
            if attachment.size_bytes == 0 || attachment.size_bytes > MAX_ATTACHMENT_BYTES as u64 {
                return Err(DistributionError::Limit);
            }
            total = total
                .checked_add(attachment.size_bytes)
                .ok_or(DistributionError::Limit)?;
        }
        if total > MAX_BUNDLE_ATTACHMENT_BYTES {
            return Err(DistributionError::Limit);
        }
        Ok(())
    }
    /// Struct field order and attachment order are part of the v1 encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DistributionError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| DistributionError::Invalid)
    }
    pub fn digest(&self) -> Result<ContentDigest, DistributionError> {
        Ok(ContentDigest::of(&self.canonical_bytes()?))
    }
    pub fn verify_attachment(&self, id: &str, bytes: &[u8]) -> Result<(), DistributionError> {
        self.validate()?;
        let descriptor = self
            .attachments
            .iter()
            .find(|a| a.artifact_id == id)
            .ok_or(DistributionError::Digest)?;
        if bytes.len() as u64 != descriptor.size_bytes || !descriptor.content_digest.matches(bytes)
        {
            return Err(DistributionError::Digest);
        }
        Ok(())
    }
}

/// An identity to match against an authenticated server response. This record
/// alone is not proof of persistence and cannot authorize filesystem deletion.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableBundleReceipt {
    pub version: u32,
    pub server_id: String,
    pub tenant_id: String,
    pub account_id: String,
    pub submission_id: String,
    pub bundle_revision: String,
    pub manifest_digest: ContentDigest,
    pub committed_at_unix: u64,
    pub retain_until_unix: u64,
    pub retention_policy_version: String,
}
impl DurableBundleReceipt {
    /// Call only after authenticating transport and validating server capability.
    /// Caller must durably journal this receipt before releasing its own lease.
    pub fn matches_bundle(
        &self,
        manifest: &ContributionBundleManifest,
        server: &str,
        tenant: &str,
        account: &str,
        now: u64,
    ) -> Result<(), DistributionError> {
        if self.version != SCHEMA_VERSION {
            return Err(DistributionError::Version);
        }
        identifier(&self.retention_policy_version)?;
        if self.server_id != server
            || self.tenant_id != tenant
            || self.account_id != account
            || self.submission_id != manifest.submission_id
            || self.bundle_revision != manifest.bundle_revision
            || self.manifest_digest != manifest.digest()?
            || self.committed_at_unix > now
            || self.retain_until_unix <= now
            || self.retain_until_unix <= self.committed_at_unix
        {
            return Err(DistributionError::Receipt);
        }
        Ok(())
    }
}

impl SanitizedTokenAttachment {
    /// Checks positions against the stored sanitized event. Use this again
    /// after any server rescrub; a changed event digest invalidates the link.
    pub fn validate(&self, sanitized: &[u8]) -> Result<(), DistributionError> {
        if self.metadata.requested_alternatives.is_some_and(|k| k > 20)
            || self.metadata.sampling.len() > 7
        {
            return Err(DistributionError::Invalid);
        }
        if let Some(model) = &self.metadata.reported_model {
            identifier(model)?;
        }
        for (key, value) in &self.metadata.sampling {
            if ![
                "temperature",
                "top_p",
                "seed",
                "presence_penalty",
                "frequency_penalty",
                "max_tokens",
                "max_completion_tokens",
            ]
            .contains(&key.as_str())
                || !value.is_finite()
            {
                return Err(DistributionError::Invalid);
            }
        }
        if self.version != SCHEMA_VERSION {
            return Err(DistributionError::Version);
        }
        if sanitized.len() > MAX_ATTACHMENT_BYTES || self.records.len() > 131072 {
            return Err(DistributionError::Limit);
        }
        for id in [
            &self.capture_store_id,
            &self.exchange_id,
            &self.event_id,
            &self.policy_version,
            &self.requested_model,
        ] {
            identifier(id)?;
        }
        for id in [&self.served_model, &self.tokenizer].into_iter().flatten() {
            identifier(id)?;
        }
        if !self.response_digest.matches(sanitized) {
            return Err(DistributionError::Digest);
        }
        let mut end = 0;
        let mut payload_bytes = 0usize;
        for (index, record) in self.records.iter().enumerate() {
            let range = record.span.range(sanitized.len())?;
            if record.index != index as u64
                || range.start < end
                || record.chosen.bytes != sanitized[range.clone()]
            {
                return Err(DistributionError::Alignment);
            }
            record.chosen.validate()?;
            payload_bytes = payload_bytes.saturating_add(record.chosen.bytes.len());
            for alt in &record.alternatives {
                payload_bytes = payload_bytes.saturating_add(alt.bytes.len());
            }
            if payload_bytes > MAX_ATTACHMENT_BYTES {
                return Err(DistributionError::Limit);
            }
            if record.alternatives.len() > MAX_ALTERNATIVES
                || record.alternatives.len() > record.returned_alternatives as usize
            {
                return Err(DistributionError::Limit);
            }
            for alternative in &record.alternatives {
                alternative.validate()?;
            }
            end = range.end;
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8], sanitized: &[u8]) -> Result<Self, DistributionError> {
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(DistributionError::Limit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| DistributionError::Invalid)?;
        value.validate(sanitized)?;
        Ok(value)
    }
}

impl ContributionBundleManifest {
    pub fn decode(bytes: &[u8]) -> Result<Self, DistributionError> {
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(DistributionError::Limit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| DistributionError::Invalid)?;
        value.validate()?;
        // The certificate signs canonical bytes. Refuse alternate spellings,
        // duplicate JSON keys, or reordered fields before hashing a manifest.
        if value.canonical_bytes()? != bytes {
            return Err(DistributionError::Invalid);
        }
        Ok(value)
    }
    pub fn verify_sanitized_attachment(
        &self,
        id: &str,
        bytes: &[u8],
        sanitized: &[u8],
    ) -> Result<SanitizedTokenAttachment, DistributionError> {
        self.verify_attachment(id, bytes)?;
        let attachment = SanitizedTokenAttachment::decode(bytes, sanitized)?;
        let descriptor = self
            .attachments
            .iter()
            .find(|a| a.artifact_id == id)
            .ok_or(DistributionError::Digest)?;
        if attachment.event_id != descriptor.event_id
            || attachment.policy_version != self.policy_version
        {
            return Err(DistributionError::Digest);
        }
        Ok(attachment)
    }
}
