//! The typed half of `trace_commons.daemon.v1_1`.
//!
//! Every field here exists on the wire in
//! `docs/contributor-daemon-ipc-v1_1.md`. Nothing is invented, and nothing
//! that the contract keeps off the wire -- a filesystem path, a token, a
//! project key -- has a home in these types, so a rendering mistake cannot
//! put one on screen.
//!
//! Deserialization is deliberately tolerant of unknown fields: the contract
//! is additive, and a shell that refused a daemon newer than itself would
//! break on the next additive revision.

use serde::Deserialize;

/// `status`.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub logged_in: bool,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub consent_scopes: Vec<String>,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub queue_depth: u64,
    #[serde(default)]
    pub next_digest_at: Option<String>,
    #[serde(default)]
    pub health: Health,
    /// The daily volume caps, and what they are holding back.
    ///
    /// Read independently of `health`: `daily-cap-reached` is last in the
    /// daemon's precedence order, so any other condition takes the single
    /// health slot and the cap disappears from view. That is exactly how a
    /// spent budget came to be indistinguishable from a broken app.
    #[serde(default)]
    pub daily_budget: DailyBudget,
    /// What the daemon is seeing from the local proxy it was told about.
    ///
    /// Absent on a daemon older than the block, and `RoutingStatus`'s
    /// default is the state that claims nothing.
    #[serde(default)]
    pub routing: RoutingStatus,
}

/// `status.routing`. Three states and one per-process timestamp; nothing
/// identifying, no port and no path.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutingStatus {
    /// The effective metadata reader is derived from this app's owned service.
    #[serde(default)]
    pub derived: bool,
    /// `not_declared`, `awaiting_rows` or `rows_seen`. Empty when the
    /// daemon did not report the block at all, which reads as the first.
    #[serde(default)]
    pub state: String,
    /// When the daemon last got an answer. **Per-process**: it starts
    /// empty again every time the daemon comes back up, so it is a "last
    /// checked" and never a date this install began.
    #[serde(default)]
    pub last_refresh_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `status.daily_budget`. Counts and one timestamp; nothing identifying.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DailyBudget {
    #[serde(default)]
    pub bytes_today: u64,
    #[serde(default)]
    pub max_bytes_per_day: u64,
    #[serde(default)]
    pub bytes_remaining: u64,
    #[serde(default)]
    pub uploads_today: u32,
    #[serde(default)]
    pub max_uploads_per_day: u32,
    #[serde(default)]
    pub uploads_remaining: u32,
    /// When the counters zero. The daemon derives this from its own day
    /// bucket, so it may be stated rather than paraphrased as "tomorrow".
    #[serde(default)]
    pub resets_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether at least one approved trace cannot go out before the reset.
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub blocked_entries: u32,
    #[serde(default)]
    pub blocked_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Health {
    #[serde(default)]
    pub last_error_label: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
}

/// One queue entry, as `list_pending` and the `snapshot` event carry it.
///
/// `project_key` and `path` are absent from the wire by design; they are
/// absent from this struct for the same reason.
///
/// `Default` is consistent with how it deserializes rather than an extra
/// promise: every field but `entry_id` already carries `#[serde(default)]`,
/// so an all-defaults value is exactly what an empty object decodes to.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QueueEntry {
    pub entry_id: String,
    #[serde(default)]
    pub session_hash: String,
    /// `claude-code`, `codex`, or `trajectory`: which ADAPTER produced this.
    #[serde(default)]
    pub source: String,
    /// What the transcript declares itself to be, when the daemon knew it.
    ///
    /// An imported Antigravity conversation is stored as a trajectory file,
    /// so `source` says `trajectory` -- the storage format, not the tool the
    /// contributor used. Absent for every native adapter, and for a
    /// trajectory the daemon was handed by name rather than discovered.
    #[serde(default)]
    pub declared_source: Option<String>,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub project_label: String,
    /// The project's folder, `~`-abbreviated, for display only.
    ///
    /// The daemon relaxed its path rule in exactly one place to send this
    /// (`ipc::display_path`), because a label can keep two projects distinct
    /// but can never make them identifiable, and the folder rows are where
    /// that difference is decided. Never logged, never in a notification,
    /// never in a history record.
    #[serde(default)]
    pub project_path: String,
    /// Where this session actually ran, when that is not the project root.
    ///
    /// `None` both when the daemon predates the field and when the session
    /// ran at the root -- the daemon sends null rather than repeating
    /// `project_path`, so a row draws this line only when it says something.
    #[serde(default)]
    pub session_path: Option<String>,
    /// The size of the session file on disk. This is **not** what would be
    /// sent; `PreviewSummary::would_send_bytes` is, and it is usually
    /// larger. Never label this one "would send".
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub discovered_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub reason_label: Option<String>,
    /// How many delegated subagent transcripts this entry's session covers,
    /// and how many were left out because the conversation exceeded the
    /// source's raw byte budget.
    ///
    /// The contract calls a non-zero `subagents_dropped` something a client
    /// **must** surface: the card stands for a whole conversation, and one
    /// that was trimmed to fit has to say so rather than presenting as
    /// complete. Rendered through [`crate::copy::subagent_line`].
    ///
    /// Both default to zero, which is what a daemon predating the fields
    /// reports and what every source with no such structure (codex,
    /// trajectory) sends.
    #[serde(default)]
    pub subagent_count: u32,
    #[serde(default)]
    pub subagents_dropped: u32,
    /// Whether this session can be contributed, as the daemon worked it out
    /// from the cheap checks it can run without reading bodies off disk.
    ///
    /// `None` IS NOT `unknown`. The field is absent from the wire entirely
    /// when the contributor was invited rather than admitted on evidence, or
    /// when the config could not be read -- they have no eligibility
    /// question, and a row that answered one they do not have would put a
    /// sentence about admissibility on every card an invited contributor
    /// owns. `unknown` is a real state that arrives as a string and gets its
    /// own sentence. The same tri-state discipline
    /// `Settings::destination_credentialed` follows, and `#[serde(default)]`
    /// on an `Option` is the mechanism that keeps the two apart.
    ///
    /// Never matched on in this shell: it is handed to
    /// [`crate::eligibility`], which asks the shared crate.
    #[serde(default)]
    pub eligibility: Option<String>,
    /// Which `Unattestable` variant decided [`Self::eligibility`], as a
    /// stable label. Absent on every `eligible` row, and on a daemon that
    /// predates the field.
    #[serde(default)]
    pub eligibility_reason: Option<String>,
    /// Whether this session carries a checkable copy of the model call
    /// that produced it.
    ///
    /// **The opposite presence rule to [`Self::eligibility`], and this is
    /// the field's whole point.** Eligibility asks whether this contributor
    /// may send this session, and is absent when nobody is asking. The mark
    /// states a fact about the trace, which every contributor is owed --
    /// including an invited one, whose sessions send perfectly well and may
    /// still arrive without a copy of their call. The daemon therefore
    /// sends it on EVERY entry, unconditionally.
    ///
    /// `Option` here is not a tri-state, then: it is the daemon that
    /// predates the field, and it degrades to `unknown` rather than to an
    /// unattested mark -- a build that cannot read a label has no evidence
    /// about anybody's session. `crate::copy::attestation_state_line`
    /// answers the `unknown` sentence for the empty string, so the absence
    /// needs no branch of its own.
    ///
    /// Never matched on in this shell: it is handed to
    /// [`crate::attestation`], which asks the shared crate.
    #[serde(default)]
    pub attestation: Option<String>,
    /// Which classification decided [`Self::attestation`], as a stable
    /// label.
    ///
    /// **Presence varies WITHIN a single mark.** `attested` never carries
    /// one; both unattested marks always do; `unknown` carries one only
    /// when a send was refused for `receipt_unavailable`, which is a
    /// retraction rather than a refusal because the receipt comes from a
    /// service that can be down. A shell that suppressed the reason on
    /// `unknown` would drop the only signal saying it may work later, so
    /// the reason line branches on THIS KEY's presence and never on the
    /// mark.
    ///
    /// The same thirteen labels [`Self::eligibility_reason`] takes, and
    /// deliberately NOT the same sentences -- see
    /// `crate::copy::attestation_reason_line`.
    #[serde(default)]
    pub attestation_reason: Option<String>,
    /// Whether a witness certificate is held for the bytes this entry was
    /// pinned to. True after either witness route.
    ///
    /// **`#[serde(default)]` here is a hazard, not a convenience**, and the
    /// reason `certificate::view` is tested against a decode. Every field on
    /// this struct defaults, so a daemon that did not send the key -- or a
    /// key renamed on one side only -- decodes to `false` on every row and
    /// renders an EMPTY LIST. An empty list is exactly what a contributor
    /// with no certificates sees, so the failure is invisible. The empty
    /// state says which one it is, and
    /// `a_decoded_entry_carrying_the_key_differs_from_one_without_it` is
    /// what keeps the key itself honest.
    ///
    /// Not the attestation mark above: that says whether the session carries
    /// a copy of the model call, this says whether a certificate is held
    /// over the reviewed bytes.
    #[serde(default)]
    pub holds_certificate: bool,
}

impl QueueEntry {
    /// The agent that produced the session, in the words a contributor uses
    /// for it.
    ///
    /// Prefers what the transcript declares over the adapter that stores it.
    /// An imported Antigravity conversation reads as "Antigravity", not as
    /// the trajectory file it happens to be kept in.
    ///
    /// The fallback arm returns `self.source` rather than the declared
    /// value: an unrecognised declaration is untrusted text out of a file,
    /// and putting it on screen unmapped is a different decision from
    /// mapping a slug this build knows.
    pub fn agent_label(&self) -> &str {
        match self
            .declared_source
            .as_deref()
            .unwrap_or(self.source.as_str())
        {
            "claude-code" => "Claude Code",
            "codex" => "Codex",
            "gemini-cli" => "Gemini CLI",
            "cline" => "Cline",
            "antigravity" => "Antigravity",
            "trajectory" => "Trajectory",
            _ => self.source.as_str(),
        }
    }
}

/// `preview`, and the in-process preview the hosting shell can run.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewSummary {
    #[serde(default)]
    pub token_distribution_summary: Option<String>,
    #[serde(default)]
    pub would_send_bytes: u64,
    #[serde(default)]
    pub raw_session_bytes: u64,
    #[serde(default)]
    pub event_count: u64,
    /// Redacted trace content, and the one place the contract permits it.
    #[serde(default)]
    pub opening_prompt: String,
    #[serde(default)]
    pub redactions: std::collections::BTreeMap<String, u32>,
    /// Distinct values removed per label, beside `redactions`' occurrence
    /// counts.
    ///
    /// The redactor mints one placeholder per DISTINCT value and reuses it
    /// wherever that value recurs, so one path referenced two hundred times
    /// is two hundred occurrences and one value. See
    /// [`crate::redaction_labels::line`].
    ///
    /// **Only two labels can ever appear here.** Distinct counts come from
    /// the placeholder map, and `apply_placeholder_regex` mints a numbered
    /// placeholder for `local_path` and `private_email` and nothing else --
    /// secrets are replaced with a bare `[REDACTED]`. So a secrets-only
    /// session reports occurrences and an EMPTY map here, and a missing or
    /// zero entry means "not measured", never "no distinct values".
    #[serde(default)]
    pub redactions_distinct: std::collections::BTreeMap<String, u32>,
    #[serde(default)]
    pub pii_labels_present: Vec<String>,
    #[serde(default)]
    pub consent_scopes: Vec<String>,
    #[serde(default)]
    pub residual_risk: String,
    #[serde(default)]
    pub envelope_digest: String,
    #[serde(default)]
    pub input_fingerprint: String,
    /// `false` means this preview was built from a placeholder identity and
    /// nothing was pinned: an illustration, not something to approve
    /// against.
    #[serde(default)]
    pub enrolled: bool,
}

impl PreviewSummary {
    /// The redaction receipt line from the shared spec, e.g.
    /// `scrubbed: 12 secrets, 4 tokens, 31 paths`.
    ///
    /// Category names come from the daemon; they are labels, never matched
    /// text. A count of zero is reported as `scrubbed: nothing` rather than
    /// hidden -- the whole point of the receipt is that `0` on a session
    /// that obviously touched a `.env` is a signal the contributor can act
    /// on.
    pub fn scrubbed_line(&self) -> String {
        // Removals only. `redactions` also carries `residual_secret_at:*`,
        // which counts a secret that was DETECTED AND LEFT IN, and this line
        // renders under a heading that says the opposite. That mislabelling
        // was worse here than in the other shells:
        // `humanize_redaction_kind` maps any label containing `secret` onto
        // the word "secrets", so a survivor was summed into the removed
        // count and became indistinguishable from a secret that had really
        // been taken out. See `crate::redaction_labels`.
        let total = crate::redaction_labels::removed_total(&self.redactions);
        if total == 0 {
            return "scrubbed: nothing".to_string();
        }
        // Several daemon-side categories map onto one word a contributor
        // uses -- `aws_secret_key` and `generic_secret` are both "secrets".
        // Their counts are summed rather than listed twice: "1 secrets, 1
        // secrets" reads as a bug, and it is one.
        let mut totals: std::collections::BTreeMap<String, u32> = Default::default();
        for (kind, n) in self
            .redactions
            .iter()
            .filter(|(kind, n)| **n > 0 && crate::redaction_labels::is_removal(kind))
        {
            *totals.entry(humanize_redaction_kind(kind)).or_default() += n;
        }
        // Ordered as the shared spec writes the line -- "12 secrets, 4
        // tokens, 31 paths" -- most alarming first, rather than
        // alphabetically. What a contributor scans for is whether a secret
        // was in there, not whether a path was.
        let mut ordered: Vec<(String, u32)> = totals.into_iter().collect();
        ordered.sort_by_key(|(word, _)| (severity_rank(word), word.clone()));
        let parts: Vec<String> = ordered
            .iter()
            .map(|(word, n)| format!("{n} {}", pluralize(word, *n)))
            .collect();
        format!("scrubbed: {}", parts.join(", "))
    }
}

fn severity_rank(word: &str) -> u8 {
    match word {
        "secrets" => 0,
        "keys" => 1,
        "tokens" => 2,
        "email addresses" => 3,
        "URLs" => 4,
        "paths" => 5,
        _ => 6,
    }
}

/// The categories above are written plural, since that is the common case;
/// a count of one gets the singular back.
fn pluralize(word: &str, n: u32) -> String {
    if n != 1 {
        return word.to_string();
    }
    match word {
        "email addresses" => "email address".to_string(),
        w => w.strip_suffix('s').unwrap_or(w).to_string(),
    }
}

/// Turn a daemon-side redaction category into ordinary words. Unknown
/// categories fall through with their underscores softened rather than
/// being dropped: an unrecognized category is still a real redaction and
/// hiding it would understate the receipt.
fn humanize_redaction_kind(kind: &str) -> String {
    let base = match kind {
        k if k.contains("secret") => "secrets",
        k if k.contains("token") => "tokens",
        k if k.contains("key") => "keys",
        k if k.contains("path") => "paths",
        k if k.contains("email") => "email addresses",
        k if k.contains("url") => "URLs",
        _ => return kind.replace('_', " "),
    };
    base.to_string()
}

/// `approve`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApproveResult {
    #[serde(default)]
    pub approved: u64,
    #[serde(default)]
    pub hold_secs: u64,
    /// The instant the daemon will first consider the entry for upload.
    ///
    /// A countdown runs against **this**, never against a duration the
    /// shell picked. `None` means no undo may be offered at all.
    #[serde(default)]
    pub hold_until: Option<chrono::DateTime<chrono::Utc>>,
    /// How many entries carried a PII label. Feeds the toast's clause 3,
    /// which appears only when this is non-zero. See
    /// `docs/superpowers/specs/2026-08-20-one-click-submit-design.md` under
    /// "The toast: normative copy".
    #[serde(default)]
    pub flagged: u64,
    /// Redaction counts, by category. The toast sums these -- it names a
    /// count, never a category; the preview sheet is where a contributor
    /// sees which detector fired.
    #[serde(default)]
    pub redactions: std::collections::BTreeMap<String, u32>,
    /// Entries this call could not send, and why. Never rendered as the
    /// wire label or the entry id -- `crate::toast::toast` maps each label
    /// through `copy::submit_skip_reason_label` before it reaches a
    /// contributor.
    #[serde(default)]
    pub skipped: Vec<SkippedEntry>,
    /// How many pending entries a GROUP selector left out for being
    /// ineligible.
    ///
    /// **Absent, not zero**, on a single-`entry_id` call and for an invited
    /// contributor -- in both cases no filter ran, and zero would read as
    /// "nothing was left out", a claim about something that did not happen.
    /// Present-and-zero is a different and meaningful answer: the filter ran
    /// and took everything.
    ///
    /// Excluded entries are NEVER in [`Self::skipped`]. They were never
    /// selected; `skipped` stays the account of what the call was asked to
    /// act on.
    ///
    /// Rendered through `copy::group_withheld_line`, which answers the empty
    /// string for zero -- so the absent case and the took-everything case
    /// both draw nothing without this shell branching on the count.
    #[serde(default)]
    pub excluded_ineligible: Option<u64>,
}

/// One entry `approve` could not send, from the `skipped` list in its
/// response.
#[derive(Debug, Clone, Deserialize)]
pub struct SkippedEntry {
    #[serde(default)]
    pub entry_id: String,
    #[serde(default)]
    pub reason_label: String,
}

/// The daemon's fixed label for a submission refused because the
/// contributor's correction contains something credential-shaped.
///
/// The wire spelling of `envelope::REASON_CORRECTION_CREDENTIAL` in the
/// contributor crate. It is matched, never rendered: what a contributor
/// reads is `copy::CORRECTION_CREDENTIAL_HEADLINE` and its body.
pub const CORRECTION_CREDENTIAL_REFUSAL: &str = "correction-credential-detected";

impl ApproveResult {
    /// Whether this response is the correction-credential refusal.
    ///
    /// Distinguished from every other skip because it is the only one the
    /// contributor caused and the only one they can fix, and because the
    /// advice that goes with it -- rotate the credential, it has already
    /// been typed -- is not advice any other refusal carries.
    pub fn was_refused_for_a_correction_credential(&self) -> bool {
        self.skipped
            .iter()
            .any(|s| s.reason_label == CORRECTION_CREDENTIAL_REFUSAL)
    }

    /// The sum of `redactions`, which is what the toast actually renders --
    /// see [`crate::toast::toast`].
    pub fn total_redactions(&self) -> u64 {
        self.redactions.values().map(|&n| u64::from(n)).sum()
    }

    /// Whether the toast this response earns should come with Undo.
    ///
    /// This is the fix for the defect
    /// `docs/superpowers/specs/2026-08-20-one-click-submit-design.md`
    /// names: `ui::preview` used to call `App::offer_undo` on any `Ok`
    /// response, which was correct while every approval succeeded and is
    /// wrong now that entries can be skipped -- a skipped entry read to the
    /// contributor as sent, with an undo timer behind it.
    ///
    /// Two conditions, both required. [`crate::toast::SubmitToast::offer_undo`]
    /// carries the spec's rule -- Undo only when `approved > 0` -- and this
    /// adds the one the spec's Undo mechanics require: there must be a
    /// `hold_until` to hold it against. `approved > 0` with no `hold_until`
    /// means the hold is configured off, which the toast's own sentence
    /// already reports as sent; there is nothing left to offer a countdown
    /// on.
    pub fn offers_undo(&self) -> bool {
        let skipped: Vec<&str> = self
            .skipped
            .iter()
            .map(|s| s.reason_label.as_str())
            .collect();
        crate::toast::toast(
            self.approved,
            self.total_redactions(),
            self.flagged,
            &skipped,
        )
        .offer_undo
            && self.hold_until.is_some()
    }
}

/// `arming_suggestion`: the one project worth offering to arm right now.
///
/// The daemon answers with an empty object when there is nothing to suggest,
/// which deserializes to `None` at the call site rather than to a
/// zero-filled offer -- a shell that receives no suggestion must draw no
/// card.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ArmingOffer {
    pub project_id: String,
    #[serde(default)]
    pub project_label: String,
    #[serde(default)]
    pub contributed_count: u32,
}

/// `list_projects`.
#[derive(Debug, Clone, Deserialize)]
pub struct Project {
    pub project_id: String,
    #[serde(default)]
    pub project_label: String,
    /// The project's folder, `~`-abbreviated, for display only.
    ///
    /// Same bound as [`QueueEntry::project_path`]: rendered, never logged,
    /// never persisted. It is what lets a history folder row name the
    /// repository it stands for rather than only its basename.
    #[serde(default)]
    pub project_path: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub configured: bool,
    /// The row holding sessions whose working directory had no usable final
    /// segment. It can be silenced but never armed -- `Policy` refuses
    /// `auto_upload` for it in two independent places -- so a shell reports
    /// that rather than enforcing it.
    ///
    /// The daemon says so explicitly because it is the only side that knows
    /// it for free. Deriving it would mean re-deriving `project_id_for`'s
    /// hash, and the IPC contract states clients MUST NOT recognise the row
    /// by `project_label`: that string is display text, and every shell
    /// rewords it precisely because the raw slug is not something a
    /// contributor should read.
    #[serde(default)]
    pub is_unresolved_bucket: bool,
    /// How many of this project's sessions are waiting. Always present.
    #[serde(default)]
    pub pending_count: u64,
    /// How many of those a group-level submit would actually send.
    ///
    /// **Absent when eligibility does not apply**, which is an invited
    /// contributor -- they have no "3 of 7" to be told about, and
    /// [`Self::pending_count`] alone is their answer. Never null, and never
    /// zero standing in for absence: zero means the daemon's filter RAN and
    /// took nothing, which is a different and offerable-nothing answer.
    ///
    /// This is the daemon's own count, not one this shell re-derives. The
    /// filter that produces it is the filter a project-wide `approve`
    /// applies, so the button and the call cannot disagree about what
    /// "all eligible" means -- and if that rule ever changes an arm, this
    /// follows it without anything here being edited.
    #[serde(default)]
    pub contributable_count: Option<u64>,
}

/// `list_history`.
///
/// `Default` is consistent with how it deserializes: every field carries
/// `#[serde(default)]`, so an all-defaults value is what an empty object
/// decodes to.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HistoryRecord {
    /// The server's id for this submission, and the only handle `withdraw`
    /// takes. Not an identity and not a path -- an opaque uuid the daemon
    /// already put on the wire. `#[serde(default)]` like every other field
    /// here, so a daemon that stopped sending it degrades to "this row has
    /// no withdraw button" rather than to a history screen that will not
    /// parse.
    #[serde(default)]
    pub submission_id: String,
    #[serde(default)]
    pub submitted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The opaque project id, for grouping history the same way the queue
    /// groups: on identity rather than on a display name.
    ///
    /// A one-way id, never a path -- the daemon's path relaxation reaches
    /// the socket's live views and never a persisted history record. Empty
    /// for a record written before project keys were normalized, which is
    /// why `history_folders` falls back to the label rather than putting
    /// every such record in one folder.
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub project_label: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub credit_points_pending: f32,
    #[serde(default)]
    pub credit_points_final: Option<f32>,
    /// The server's own prose. Rendered verbatim; a status word is a poor
    /// substitute for "held because a passage looked like a personal
    /// address".
    #[serde(default)]
    pub explanations: Vec<String>,
}

/// `history_rollup`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HistoryRollup {
    #[serde(default)]
    pub week: Counts,
    #[serde(default)]
    pub month: Counts,
    #[serde(default)]
    pub all_time: Counts,
    #[serde(default)]
    pub credit_pending: f32,
    #[serde(default)]
    pub credit_final: f32,
    #[serde(default)]
    pub quarantined: u32,
    /// `null` renders as "Not synced yet", never as a confident `0.0`.
    #[serde(default)]
    pub last_refreshed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Counts {
    #[serde(default)]
    pub submitted: u32,
    #[serde(default)]
    pub accepted: u32,
    #[serde(default)]
    pub quarantined: u32,
    #[serde(default)]
    pub other: u32,
}

impl Counts {
    /// Everything in every bucket.
    ///
    /// `submitted` is one bucket among four -- traces that have gone out
    /// and have no verdict back yet -- and never a running total. Reading
    /// it as one made "waiting to be scored" arithmetic
    /// (`submitted - accepted - quarantined`) permanently negative, so it
    /// saturated to zero and the screen said nothing was ever in flight.
    pub fn total(&self) -> u32 {
        self.submitted + self.accepted + self.quarantined + self.other
    }
}

/// `get_settings`. The three booleans are configured-or-not facts; the
/// underlying credential and paths never cross the socket and have no field
/// here to land in.
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub quiescence_secs: u64,
    #[serde(default)]
    pub digest_interval_secs: u64,
    #[serde(default)]
    pub approval_hold_secs: u64,
    #[serde(default)]
    pub max_uploads_per_day: u64,
    #[serde(default)]
    pub max_bytes_per_day: u64,
    #[serde(default)]
    pub local_notifications: bool,
    #[serde(default)]
    pub near_ai_configured: bool,
    /// `watch`, `off` or `unset`, per source.
    ///
    /// `get_settings` also sends `claude_root_configured` /
    /// `codex_root_configured`, and this shell deliberately does not read
    /// them. That boolean is `mode == "watch"`, so it is false for `off` as
    /// well as for `unset` -- and the settings screen printed one sentence
    /// on that false branch, telling a contributor who declared a tool off
    /// that its sessions were being read from the usual place. Only the mode
    /// separates "watched somewhere else", "watched where it usually lives"
    /// and "not used at all", and only the last of those reads "Not used".
    #[serde(default)]
    pub claude_source_mode: String,
    #[serde(default)]
    pub codex_source_mode: String,
    #[serde(default)]
    pub gemini_source_mode: String,
    #[serde(default)]
    pub cline_source_mode: String,
    /// The local proxy declaration as the daemon holds it. Absent means
    /// off -- there is no conventional fallback for a local service, so
    /// unlike a source root there is no third state.
    ///
    /// Carries the declared *folder*, never a token: the daemon reads the
    /// credential at call time and it never enters settings.
    #[serde(default)]
    pub ironwire: Option<RoutingDeclaration>,
    /// Separate consent to carry captured inference bodies to the witness.
    #[serde(default)]
    pub token_distributions_contribution: bool,
    #[serde(default)]
    pub token_storage: Option<TokenStorage>,
    #[serde(default)]
    pub ironwire_attested_bodies: bool,
    #[serde(default)]
    pub admission_evidence_required: Option<bool>,
    /// Whether this daemon has been asked to answer model calls itself.
    ///
    /// What was *asked for*. What actually happened is
    /// [`Settings::private_inference_state`] beside it, and the two differ
    /// whenever the listener refused to start -- which is exactly the case a
    /// screen rendering the boolean alone would draw as on.
    #[serde(default)]
    pub private_inference: bool,
    /// Whether the contributor has already been asked about the switch.
    ///
    /// Written on either answer, so a decline is remembered. Absent on a
    /// daemon that predates the key, which reads as unanswered and is what
    /// makes the offer appear once after an upgrade.
    #[serde(default)]
    pub private_inference_offer_seen: bool,
    /// What the listener is actually doing.
    #[serde(default)]
    pub private_inference_state: Option<PrivateInferenceState>,
}

/// `get_settings`'s and `status`'s `private_inference_state` block.
///
/// The label is carried as the daemon's own string and handed straight to
/// [`crate::copy::private_inference_state_line`] and its tone twin. It is
/// deliberately not parsed into an enum here: a label a later daemon grows
/// would then have to be spelled in this shell before it could be shown, and
/// the shared table already answers an unknown label safely.
#[derive(Debug, Clone, Deserialize)]
pub struct PrivateInferenceState {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub port: Option<u16>,
}

/// `near_ai_balance`'s answer: what is left in the account this computer
/// answers model calls with.
///
/// The label is carried as the daemon's own string, for
/// [`PrivateInferenceState`]'s reason, and handed to
/// [`crate::balance::view`] rather than matched on here.
///
/// # Every amount is an `Option`, and that is the whole point
///
/// These figures are SIGNED -- an overdrawn account is a negative number --
/// so absence cannot be folded onto an out-of-range integer the way the rest
/// of this surface folds it. A bare `i64` defaulting to zero would collapse
/// "we know we do not know" onto "the money is gone", and the collapsed
/// value is the alarming one. `remaining_nanos` in particular is nullable
/// even on a `known` read: that is the ordinary shape of an account nobody
/// has capped.
///
/// `scale` is an `Option` for a different reason: it is the wire's own
/// units, and a daemon that sends none leaves this shell with no way to
/// render a figure. Defaulting it to a nine of this shell's own would print
/// an amount wrong by a factor of a thousand rather than printing none.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NearAiBalance {
    #[serde(default)]
    pub state: String,
    /// The wire's own units. Never assumed; see the type note above.
    #[serde(default)]
    pub scale: Option<u8>,
    #[serde(default)]
    pub remaining_nanos: Option<i64>,
    #[serde(default)]
    pub spend_limit_nanos: Option<i64>,
    #[serde(default)]
    pub total_spent_nanos: Option<i64>,
    /// The DAEMON'S clock at the moment the service answered, RFC 3339 --
    /// not the service's own `updated_at`. What a shell may say with it is
    /// how long ago the question was put, and nothing about bookkeeping.
    #[serde(default)]
    pub observed_at: Option<String>,
}

/// `harness_list`'s answer: the coding tools on this computer.
///
/// `catalog_present` is a fact about this build, not about the machine. With
/// no signed catalog loaded the list is the tools this build ships knowing
/// about, and the daemon says so rather than letting a short list imply the
/// machine has only those.
#[derive(Debug, Clone, Deserialize)]
pub struct HarnessList {
    #[serde(default)]
    pub catalog_present: bool,
    /// The port this computer answers model calls on, or absent when
    /// nothing here answers. A connect has nothing to write without one.
    #[serde(default)]
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub harnesses: Vec<Harness>,
    /// Whether the destination this app hosts can answer anything, which is
    /// what gates a connect.
    ///
    /// THREE ANSWERS, NOT TWO, and the `Option` is carrying the third. A
    /// daemon older than the gate does not send the field at all, and that is
    /// not the same fact as a daemon reporting no key: the first connects
    /// tools without a sign-in and the second cannot. Defaulting it to `false`
    /// would tell a contributor on the older build to go and get a key nothing
    /// wants. `harness_credential_notice` is where the three are separated;
    /// nothing here reads this as a boolean.
    #[serde(default)]
    pub destination_credentialed: Option<bool>,
    /// What the calls answered here have cost today, or the absence that
    /// must never be drawn as zero.
    ///
    /// Defaulted, so a daemon older than the release that reports it leaves
    /// the amount unknown rather than taking the whole tool list down with
    /// it -- and unknown is the honest answer for a daemon that does not
    /// report it.
    #[serde(default)]
    pub spend: HarnessSpend,
}

/// What today's calls cost, as the daemon reports it.
///
/// A block with a flag rather than a bare number, because the flag is the
/// whole point: `known` false is "nobody could measure this", which is NOT a
/// day on which nothing was spent. A bare number defaulting to zero would
/// collapse the two, and the collapsed value is a confident figure nothing
/// supports.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HarnessSpend {
    #[serde(default)]
    pub known: bool,
    /// Millionths of a dollar, since the most recent midnight.
    #[serde(default)]
    pub micros: Option<u64>,
}

impl HarnessSpend {
    /// The figure, or `None` for every way of not having one.
    ///
    /// `known` true with no number is a contradiction, and the safe reading
    /// of it is that nothing was measured -- never zero.
    #[must_use]
    pub fn micros(&self) -> Option<u64> {
        if self.known { self.micros } else { None }
    }
}

/// One row of `harness_list`.
///
/// `name` is IronWire's, never this shell's: a tool's name is not wording
/// this app authors, and a list that spelled it here would go stale the day
/// the catalog grows.
///
/// `state` is carried as the daemon's own label and handed to
/// [`crate::ui::private_inference::harness_line`] and its tone twin, for the
/// reason [`PrivateInferenceState`] gives: a label a later daemon grows
/// would otherwise have to be spelled here before it could be shown.
///
/// `can_connect` and `can_disconnect` are the daemon's answers to whether
/// each action may be offered, and this shell reads them rather than
/// re-deriving them from `installed` and `connected`.
#[derive(Debug, Clone, Deserialize)]
pub struct Harness {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub connect_command: String,
    #[serde(default)]
    pub state: String,
    /// When a call of this tool's kind last arrived, as RFC 3339. Present
    /// only for the states that mean a call actually arrived.
    #[serde(default)]
    pub last_call_at: Option<String>,
    #[serde(default)]
    pub can_connect: bool,
    #[serde(default)]
    pub can_disconnect: bool,
}

/// `harness_plan`'s answer: an edit worked out, with nothing written.
///
/// `plan_id` is minted only where there is something to commit, and
/// `harness_commit` takes it and nothing else -- which is what stops this
/// shell from constructing a write of its own.
#[derive(Debug, Clone, Deserialize)]
pub struct HarnessPlan {
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub changes: Vec<String>,
    /// Slots left exactly as the contributor had them.
    ///
    /// NOT an outcome, and carried whatever the outcome says. A plan can
    /// have changes and occupied slots at once, and flattening the two would
    /// lose whichever half came second.
    #[serde(default)]
    pub occupied: Vec<HarnessOccupied>,
}

/// One slot that already had a value in it, and the value that is in it.
///
/// The value is shown deliberately: reporting rather than overwriting is the
/// whole point, and a report that hid what it found would not be one.
#[derive(Debug, Clone, Deserialize)]
pub struct HarnessOccupied {
    pub slot: String,
    #[serde(default)]
    pub current: String,
}

/// `get_settings`'s `ironwire` block.
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingDeclaration {
    /// `watch` or `off`.
    pub mode: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub token_dir: Option<String>,
}

/// `consent_options`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConsentScope {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub always_on: bool,
    #[serde(default)]
    pub grants_data_use: bool,
}

/// Format a byte count for a contributor deciding whether to send it.
pub fn human_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{bytes} bytes")
    }
}

/// "3 hours ago", for a queue row. Never an absolute timestamp: a
/// contributor placing a session in their own day thinks in elapsed time.
pub fn human_when(then: Option<chrono::DateTime<chrono::Utc>>) -> String {
    let Some(then) = then else {
        return "just now".to_string();
    };
    let mins = (chrono::Utc::now() - then).num_minutes().max(0);
    match mins {
        0..=1 => "just now".to_string(),
        2..=59 => format!("{mins} minutes ago"),
        60..=119 => "an hour ago".to_string(),
        120..=1439 => format!("{} hours ago", mins / 60),
        1440..=2879 => "yesterday".to_string(),
        _ => format!("{} days ago", mins / 1440),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this fixes: `ui::preview` used to call `App::offer_undo`
    /// on any `Ok` response from `approve`, ignoring `approved`. Correct
    /// while every approval succeeded; wrong once entries can be skipped,
    /// because a skipped entry read to the contributor as sent, with an
    /// undo timer behind it.
    ///
    /// This decodes a literal `approve` response in the daemon's real wire
    /// shape (`docs/superpowers/plans/2026-08-20-one-click-submit-shells.md`,
    /// "Existing interfaces") with `approved: 0`, and asserts through
    /// `ApproveResult::offers_undo` -- the same method `App::render_submit_response`
    /// calls in production -- that no undo is offered.
    #[test]
    fn a_response_with_zero_approved_offers_no_undo() {
        let value = serde_json::json!({
            "approved": 0,
            "flagged": 0,
            "redactions": {},
            "skipped": [{"entry_id": "e1", "reason_label": "not-pending"}],
            "hold_secs": 120,
            "hold_until": null,
        });
        let approve: ApproveResult = serde_json::from_value(value).expect("decodes");
        assert_eq!(approve.approved, 0);
        assert!(
            !approve.offers_undo(),
            "an approve response with approved: 0 must not offer undo"
        );
    }

    /// The ordinary case, for contrast: something was approved and the
    /// daemon returned a hold to undo it against.
    #[test]
    fn a_response_with_a_hold_and_something_approved_offers_undo() {
        let value = serde_json::json!({
            "approved": 1,
            "flagged": 0,
            "redactions": {"secrets": 2},
            "skipped": [],
            "hold_secs": 120,
            "hold_until": "2026-08-20T00:02:00Z",
        });
        let approve: ApproveResult = serde_json::from_value(value).expect("decodes");
        assert!(approve.offers_undo());
        assert_eq!(approve.total_redactions(), 2);
    }

    /// `approved > 0` alone is not enough: the spec's Undo mechanics need a
    /// `hold_until` to hold against, and a daemon with the hold configured
    /// off returns `approved > 0` with `hold_until: null`.
    #[test]
    fn something_approved_with_no_hold_still_offers_no_undo() {
        let value = serde_json::json!({
            "approved": 1,
            "flagged": 0,
            "redactions": {},
            "skipped": [],
            "hold_secs": 0,
            "hold_until": null,
        });
        let approve: ApproveResult = serde_json::from_value(value).expect("decodes");
        assert!(!approve.offers_undo());
    }

    #[test]
    fn a_receipt_with_no_redactions_says_so_rather_than_going_quiet() {
        let s = PreviewSummary {
            token_distribution_summary: None,
            would_send_bytes: 0,
            raw_session_bytes: 0,
            event_count: 0,
            opening_prompt: String::new(),
            redactions: Default::default(),
            redactions_distinct: Default::default(),
            pii_labels_present: vec![],
            consent_scopes: vec![],
            residual_risk: String::new(),
            envelope_digest: String::new(),
            input_fingerprint: String::new(),
            enrolled: true,
        };
        assert_eq!(s.scrubbed_line(), "scrubbed: nothing");
    }

    #[test]
    fn the_receipt_reads_as_the_shared_spec_writes_it() {
        let mut redactions = std::collections::BTreeMap::new();
        redactions.insert("aws_secret_key".to_string(), 12);
        redactions.insert("bearer_token".to_string(), 4);
        redactions.insert("home_path".to_string(), 31);
        let s = PreviewSummary {
            token_distribution_summary: None,
            would_send_bytes: 86016,
            raw_session_bytes: 1,
            event_count: 1,
            opening_prompt: String::new(),
            redactions,
            redactions_distinct: Default::default(),
            pii_labels_present: vec![],
            consent_scopes: vec![],
            residual_risk: "pattern-based".to_string(),
            envelope_digest: String::new(),
            input_fingerprint: String::new(),
            enrolled: true,
        };
        assert_eq!(
            s.scrubbed_line(),
            "scrubbed: 12 secrets, 4 tokens, 31 paths"
        );
        assert_eq!(human_bytes(s.would_send_bytes), "84 KB");
    }

    #[test]
    fn an_unknown_redaction_category_still_appears_in_the_receipt() {
        let mut redactions = std::collections::BTreeMap::new();
        redactions.insert("some_new_shape".to_string(), 2);
        let s = PreviewSummary {
            token_distribution_summary: None,
            would_send_bytes: 0,
            raw_session_bytes: 0,
            event_count: 0,
            opening_prompt: String::new(),
            redactions,
            redactions_distinct: Default::default(),
            pii_labels_present: vec![],
            consent_scopes: vec![],
            residual_risk: String::new(),
            envelope_digest: String::new(),
            input_fingerprint: String::new(),
            enrolled: true,
        };
        assert_eq!(s.scrubbed_line(), "scrubbed: 2 some new shape");
    }

    #[test]
    fn categories_that_mean_the_same_word_are_summed_not_listed_twice() {
        let mut redactions = std::collections::BTreeMap::new();
        redactions.insert("aws_secret_key".to_string(), 1);
        redactions.insert("generic_secret".to_string(), 1);
        redactions.insert("email".to_string(), 1);
        let s = PreviewSummary {
            token_distribution_summary: None,
            would_send_bytes: 0,
            raw_session_bytes: 0,
            event_count: 0,
            opening_prompt: String::new(),
            redactions,
            redactions_distinct: Default::default(),
            pii_labels_present: vec![],
            consent_scopes: vec![],
            residual_risk: String::new(),
            envelope_digest: String::new(),
            input_fingerprint: String::new(),
            enrolled: true,
        };
        assert_eq!(s.scrubbed_line(), "scrubbed: 2 secrets, 1 email address");
    }

    /// The queue names what a trace came FROM, not how it is stored.
    ///
    /// An imported Antigravity conversation is staged as a trajectory file
    /// and read by the trajectory adapter, so the adapter name alone would
    /// label it "Trajectory" -- the storage format, and not the word the
    /// contributor typed to collect it.
    #[test]
    fn an_imported_conversation_is_labelled_by_what_it_declares() {
        let entry: QueueEntry = serde_json::from_value(serde_json::json!({
            "entry_id": "e1",
            "source": "trajectory",
            "declared_source": "antigravity",
        }))
        .unwrap();
        assert_eq!(entry.agent_label(), "Antigravity");
    }

    /// A native session declares nothing and still reads correctly, which
    /// is what stops this from being a one-source special case.
    #[test]
    fn a_session_that_declares_nothing_falls_back_to_its_adapter() {
        let entry: QueueEntry = serde_json::from_value(serde_json::json!({
            "entry_id": "e2",
            "source": "claude-code",
        }))
        .unwrap();
        assert_eq!(entry.declared_source, None);
        assert_eq!(entry.agent_label(), "Claude Code");
    }

    /// An unrecognised declaration is untrusted text from a file. It must
    /// not reach the screen unmapped -- the adapter is shown instead.
    #[test]
    fn an_unknown_declaration_does_not_reach_the_screen() {
        let entry: QueueEntry = serde_json::from_value(serde_json::json!({
            "entry_id": "e3",
            "source": "trajectory",
            "declared_source": "something-this-build-has-never-heard-of",
        }))
        .unwrap();
        assert_eq!(entry.agent_label(), "trajectory");
    }

    #[test]
    fn a_queue_entry_decodes_the_project_and_session_paths() {
        let e: QueueEntry = serde_json::from_value(serde_json::json!({
            "entry_id": "e1",
            "project_id": "proj_a",
            "project_label": "repo",
            "project_path": "~/code/repo",
            "session_path": "~/code/repo/crates/inner",
            "state": "pending"
        }))
        .unwrap();
        assert_eq!(e.project_path, "~/code/repo");
        assert_eq!(e.session_path.as_deref(), Some("~/code/repo/crates/inner"));
    }

    #[test]
    fn a_queue_entry_from_an_older_daemon_has_no_paths() {
        let e: QueueEntry = serde_json::from_value(serde_json::json!({
            "entry_id": "e1", "project_id": "proj_a",
            "project_label": "repo", "state": "pending"
        }))
        .unwrap();
        assert_eq!(e.project_path, "");
        assert_eq!(e.session_path, None);
    }

    #[test]
    fn a_preview_summary_decodes_distinct_redaction_counts() {
        let p: PreviewSummary = serde_json::from_value(serde_json::json!({
            "redactions": { "local_path": 185 },
            "redactions_distinct": { "local_path": 12 }
        }))
        .unwrap();
        assert_eq!(p.redactions.get("local_path"), Some(&185));
        assert_eq!(p.redactions_distinct.get("local_path"), Some(&12));
    }

    #[test]
    fn a_preview_summary_from_an_older_daemon_has_no_distinct_counts() {
        let p: PreviewSummary = serde_json::from_value(serde_json::json!({
            "redactions": { "local_path": 185 }
        }))
        .unwrap();
        assert!(p.redactions_distinct.is_empty());
    }

    #[test]
    fn a_history_record_decodes_its_project_id() {
        let r: HistoryRecord = serde_json::from_value(serde_json::json!({
            "submission_id": "s1",
            "project_id": "proj_a",
            "project_label": "repo",
            "status": "accepted"
        }))
        .unwrap();
        assert_eq!(r.project_id, "proj_a");
    }

    #[test]
    fn a_history_record_from_before_the_upgrade_has_no_project_id() {
        let r: HistoryRecord = serde_json::from_value(serde_json::json!({
            "submission_id": "s1", "project_label": "repo", "status": "accepted"
        }))
        .unwrap();
        assert_eq!(r.project_id, "");
    }

    #[test]
    fn a_project_decodes_its_path() {
        let p: Project = serde_json::from_value(serde_json::json!({
            "project_id": "proj_a",
            "project_label": "repo",
            "project_path": "~/code/repo"
        }))
        .unwrap();
        assert_eq!(p.project_path, "~/code/repo");
    }

    #[test]
    fn a_project_from_an_older_daemon_has_no_path() {
        let p: Project = serde_json::from_value(serde_json::json!({
            "project_id": "proj_a", "project_label": "repo"
        }))
        .unwrap();
        assert_eq!(p.project_path, "");
    }
}

#[cfg(test)]
#[test]
fn routing_origin_is_only_the_reported_derived_flag() {
    let derived: RoutingStatus =
        serde_json::from_str(r#"{"state":"awaiting_rows","derived":true}"#).unwrap();
    assert!(derived.derived);
    let legacy: RoutingStatus = serde_json::from_str(r#"{"state":"awaiting_rows"}"#).unwrap();
    assert!(!legacy.derived);
    let unknown: RoutingStatus =
        serde_json::from_str(r#"{"state":"unknown","derived":false}"#).unwrap();
    assert_eq!(unknown.state, "unknown");
    assert!(!unknown.derived);
    assert!(serde_json::from_str::<RoutingStatus>(r#"{"derived":"true"}"#).is_err());
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenStorage {
    #[serde(default)]
    pub capture_enabled: bool,
    #[serde(default)]
    pub capture_label: String,
    #[serde(default)]
    pub capture_confirmation: String,
    #[serde(default)]
    pub capture_notice: String,
    pub state_line: String,
    pub scope_note: String,
    pub cleanup_label: String,
    pub discard_label: String,
    pub discard_confirmation: String,
    pub cancel_label: String,
    pub confirm_label: String,
    pub failure_line: String,
}
