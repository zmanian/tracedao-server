//! Daemon configuration: the knobs governing how patient, how chatty, and how
//! autonomous the background uploader is.
//!
//! These are persisted rather than read from the process environment because a
//! daemon started by a service manager inherits none of the user's shell
//! environment. Settings read from env would leave every upload refusing with
//! `pii-filter-unavailable` under systemd while working perfectly by hand.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{ConfigStore, DAEMON_SETTINGS_FILE};
use crate::envelope::NearAiSettings;

pub const DAEMON_SETTINGS_SCHEMA: &str = "trace_commons.daemon_settings.v1";

/// How long a session must go unwritten before it counts as finished.
const DEFAULT_QUIESCENCE_SECS: u64 = 1800;
/// How often the watcher stats the session roots. Much finer than the
/// quiescence window, so the poll rate costs nothing in responsiveness.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;
/// Minimum gap between digest notifications, so a busy day is one interruption
/// rather than a dozen.
const DEFAULT_DIGEST_INTERVAL_SECS: u64 = 14_400;
const DEFAULT_QUEUE_TTL_DAYS: i64 = 14;
/// A resumed session must grow by this factor to be worth re-uploading.
const DEFAULT_GROWTH_FACTOR: f64 = 2.0;
/// ...or by this many absolute bytes, which is what actually catches growth on
/// an already-large session.
const DEFAULT_GROWTH_MIN_NEW_BYTES: u64 = 65_536;
/// A session re-uploads at most this many times. Each re-upload re-sends the
/// whole file, so an unbounded count would pay the privacy-filter bill
/// repeatedly over the same text and dilute the contributor's own credit
/// through server-side duplicate clustering.
const DEFAULT_MAX_REUPLOADS: u32 = 3;
const DEFAULT_MAX_UPLOADS_PER_DAY: u32 = 50;
const DEFAULT_MAX_BYTES_PER_DAY: u64 = 209_715_200;
/// The upper bound `set_settings` (and the C ABI's pre-start override) will
/// accept for `max_uploads_per_day`. The cap exists to bound a runaway
/// client -- an app that decides to upload everything should not be able
/// to -- so it must stay a validated ceiling, not an open field. 20x the
/// default comfortably covers a contributor running several agents across
/// a very active day (a real machine needed 200/day, four times the
/// default) while still being a real bound: a client that hit this would
/// still be stopped well short of "everything, all day".
const MAX_UPLOADS_PER_DAY_CEILING: u32 = 1_000;
/// The upper bound for `max_bytes_per_day`, in bytes. Sized from real
/// corpus data, not a guess: a machine with 81 Claude sessions (0.9 GB
/// total, largest 93.6 MB) and 3,069 Codex sessions (10.8 GB total) still
/// only produces a few GB of *accepted* envelopes on its most active day,
/// since a single accepted envelope commonly runs several MB. 5 GiB is
/// comfortably above that (and above the 2 GiB a contributor had already
/// raised their own machine to by hand) while remaining a real ceiling on
/// a client that decided to send everything at once.
const MAX_BYTES_PER_DAY_CEILING: u64 = 5 * 1024 * 1024 * 1024;
const DEFAULT_MAX_QUEUE_ENTRIES: usize = 500;
const DEFAULT_HISTORY_POLL_SECS: u64 = 1800;
/// How often the public community roster is fetched. The server serves a
/// pre-rendered snapshot and refuses to serve one older than fifteen minutes,
/// so polling faster than that only re-fetches a body the server has not
/// recomputed. Fifteen minutes is the roster's own cadence, and this follows
/// it rather than inventing a second one.
const DEFAULT_COMMUNITY_POLL_SECS: u64 = 900;
/// A privacy-filter self-test from days ago proves nothing about the filter
/// now, so a long-lived process re-checks on this interval.
const DEFAULT_CANARY_INTERVAL_SECS: u64 = 3600;
/// How long an approval is held before the uploader will touch it, which is
/// how long a contributor's "Undo" really lasts.
///
/// The designed affordance is a five-second undo after approving. Five
/// seconds is therefore the floor, not the target: the client's countdown
/// starts when it renders the response, which is already after the approval
/// was stamped, and the cancel that ends it has to travel back over the
/// socket. Ten leaves room for both, plus the second or two of clock skew
/// between an application counting in its own process and a daemon deciding
/// in another, and costs nothing that matters -- uploads are unattended
/// background work on a 60-second poll, so an armed project's traces still
/// go out on the very next tick.
///
/// Zero disables the hold, restoring the old behaviour for anyone who wants
/// it; a client is expected to stop offering an undo when
/// `approve` reports no `hold_until`.
const DEFAULT_APPROVAL_HOLD_SECS: u64 = 10;

/// A minted NEAR AI inference credential, as persisted.
///
/// The service returns the plaintext key exactly once, at creation, so there
/// is no re-reading it: this record is the only copy the contributor has, and
/// losing it means minting another. Everything beside the key is context the
/// service itself renders in its own key list -- the prefix, the ids -- and is
/// safe to show; the key never is.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearAiInferenceCredential {
    /// The `sk-` key. Never rendered, never logged, never crosses the socket.
    pub key: String,
    /// The service's own id for the key, which is what revoking it needs.
    pub key_id: String,
    /// The leading characters the service shows in its key list, so a
    /// contributor can tell which of their keys this is without seeing it.
    pub key_prefix: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub minted_at: DateTime<Utc>,
}

impl std::fmt::Debug for NearAiInferenceCredential {
    /// Hand-written because `DaemonSettings` derives `Debug`: a derived impl
    /// here would put the key in every `{:?}` of the whole settings document.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NearAiInferenceCredential")
            .field("key", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("key_prefix", &self.key_prefix)
            .field("organization_id", &self.organization_id)
            .field("workspace_id", &self.workspace_id)
            .field("minted_at", &self.minted_at)
            .finish()
    }
}

/// The NEAR AI **session** this daemon retained after the credential
/// ceremony, kept for one reason: reading the account balance.
///
/// **This is a wider credential than the inference key beside it, and the
/// difference is not cosmetic.** The `sk-` key in
/// [`NearAiInferenceCredential`] buys inference and nothing else -- every
/// management route on cloud-api refuses it. A refresh token buys a session,
/// and a session can mint further API keys, read organization and workspace
/// state, and enumerate and delete the account's own tokens. A contributor
/// who obtained inference has, by keeping this, given the daemon on their
/// machine authority over their NEAR AI account that the inference key alone
/// would never have carried.
///
/// It is retained anyway, deliberately, because the balance is
/// session-authenticated and there is no narrower credential that can read
/// it: `GET /v1/organizations/{org}/usage/balance` is `session_token`-only,
/// as is every other management route, and an `sk-` key answers 401 on all of
/// them. Showing a contributor what their account has left is worth the
/// wider credential; pretending the credential is not wider would not be.
///
/// Only the refresh token is stored. The access token it buys is short-lived
/// and lives in memory for as long as one daemon process runs -- there is
/// nothing to gain from putting a second credential on disk, and the exchange
/// route (`POST /v1/users/me/access-tokens`) is authenticated by the refresh
/// token itself rather than by an access token, so a stale access token is
/// never a reason to go back to the browser.
///
/// The refresh token **rotates**: every exchange returns a new one and the
/// old one stops working. So this record is rewritten on each refresh, and a
/// rotation that is minted but not persisted locks the contributor out until
/// they re-run the ceremony. That is why the write happens before the new
/// access token is used for anything.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearAiSession {
    /// The `rt_` refresh token. Never rendered, never logged, never crosses
    /// the socket.
    pub refresh_token: String,
    /// When the service last said this refresh token stops working, if it has
    /// said. `None` is "not known" -- the OAuth finish hands the token back in
    /// a URL fragment with no expiry beside it, so the first exchange is what
    /// populates this. It is never treated as "does not expire": the refresh
    /// route is the only thing that can tell us, and a refusal is what a
    /// contributor is actually shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    /// When this record was last written, which after a rotation is when the
    /// current token was issued rather than when the ceremony ran.
    pub stored_at: DateTime<Utc>,
}

impl std::fmt::Debug for NearAiSession {
    /// Hand-written for the same reason as [`NearAiInferenceCredential`]'s:
    /// `DaemonSettings` derives `Debug`, and a derived impl here would put a
    /// live refresh token -- the wider of the two credentials in this
    /// document -- into every `{:?}` of the whole settings blob.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NearAiSession")
            .field("refresh_token", &"<redacted>")
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .field("stored_at", &self.stored_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonSettings {
    /// Opaque OS entry and Cloud metadata. Legacy documents omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_credentials: Option<crate::daemon::stored_cloud_credentials::StoredCloudCredentials>,
    /// Runtime-only failure, never a credential or a platform error string.
    #[serde(skip)]
    pub cloud_storage_unavailable: bool,
    pub schema_version: String,
    pub poll_interval_secs: u64,
    pub quiescence_secs: u64,
    pub digest_interval_secs: u64,
    pub queue_ttl_days: i64,
    pub growth_factor: f64,
    pub growth_min_new_bytes: u64,
    pub max_reuploads: u32,
    pub max_uploads_per_day: u32,
    pub max_bytes_per_day: u64,
    pub max_queue_entries: usize,
    pub history_poll_secs: u64,
    /// How often the public community roster is fetched. `#[serde(default)]`
    /// so a settings file written before this field existed loads with the
    /// poll on its published cadence rather than failing to parse.
    #[serde(default = "default_community_poll_secs")]
    pub community_poll_secs: u64,
    pub canary_interval_secs: u64,
    /// How long after an approval the uploader must leave the entry alone,
    /// so the undo a client offers is real rather than a race against the
    /// next upload pass. See `DEFAULT_APPROVAL_HOLD_SECS` and
    /// `queue::QueueEntry::approved_at`.
    ///
    /// `#[serde(default = ...)]` so a settings file written before this
    /// field existed loads with the hold on rather than off: a missing key
    /// must not silently mean "no undo window".
    #[serde(default = "default_approval_hold_secs")]
    pub approval_hold_secs: u64,
    /// Whether the daemon itself renders OS notifications. Off by default:
    /// the native applications render their own, and the daemon's shell-out
    /// path needs a desktop session it may not have.
    pub local_notifications: bool,
    /// Privacy-filter credentials, persisted so a service-managed daemon can
    /// reach the filter without a shell environment.
    pub near_ai: Option<NearAiSettings>,
    /// The NEAR AI **inference** credential this daemon obtained for the
    /// contributor, distinct from `near_ai` above, which is the
    /// **privacy-filter** credential and answers a different service. Two
    /// near-homonyms in one file invite "I set my NEAR AI key, why do calls
    /// still fail", so the distinction is stated here, on the IPC boolean, and
    /// in the doc inventory rather than left to be inferred from the name.
    ///
    /// This slot is the daemon's, and that is the point. The rule this module
    /// keeps elsewhere -- never act on a slot the contributor owns -- is about
    /// IronWire's own `config.json`, which a contributor may edit and which
    /// `StartupProbes::Configured` exists to respect. Writing a minted key
    /// into that file would be exactly the violation the rule forbids. So the
    /// credential is resolved here in memory from the OS store. Settings
    /// persist only `cloud_credentials` metadata after verified migration;
    /// this field remains readable for upgrades from the old plaintext format.
    ///
    /// `#[serde(default)]` so a settings file written before this field
    /// existed loads without one rather than failing to parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_ai_inference: Option<NearAiInferenceCredential>,
    /// The session retained alongside the credential above, so the account
    /// balance can be read. See [`NearAiSession`] for what this is authority
    /// over, which is considerably more than the key beside it.
    ///
    /// A third NEAR-AI-shaped key in one document, and the three answer three
    /// different questions: `near_ai` is the privacy-filter credential,
    /// `near_ai_inference` is the key inference calls carry, and this is the
    /// session that management reads need. Forgetting the credential clears
    /// this too -- see `nearai_credential::ceremony::forget` -- because a
    /// contributor who believes they revoked the daemon's access and left a
    /// session behind has been told something false.
    ///
    /// `#[serde(default)]` so a settings file written before this field
    /// existed loads without one rather than failing to parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_ai_session: Option<NearAiSession>,
    /// What the contributor said about each agent's sessions.
    ///
    /// `None` is "never asked", and it is the ONLY state that still falls
    /// back to the conventional per-user location -- which is why the
    /// application shells refuse to start on it. `Some(Off)` is a real
    /// answer and is never a fallback; see [`SourceDeclaration`].
    #[serde(default)]
    pub claude_source: Option<SourceDeclaration>,
    #[serde(default)]
    pub codex_source: Option<SourceDeclaration>,
    /// Added after every desktop client had shipped, which is why an absent
    /// value here means "no gemini adapter" rather than "the conventional
    /// `~/.gemini`" -- see [`crate::source::SourceRoots`] and
    /// [`roots_declared`].
    #[serde(default)]
    pub gemini_source: Option<SourceDeclaration>,
    /// Added after every desktop client had shipped; absent means "no cline
    /// adapter", never the conventional `~/.cline` -- see [`gemini_source`]
    /// for the reasoning, which is identical.
    ///
    /// [`gemini_source`]: DaemonSettings::gemini_source
    #[serde(default)]
    pub cline_source: Option<SourceDeclaration>,
    /// Explicit OpenCode export directory. Absent/null and Off construct no
    /// adapter; there is no conventional native database or export location.
    #[serde(default)]
    pub opencode_source: Option<SourceDeclaration>,

    /// An explicit local proxy declaration. Off refuses metadata; Watch
    /// keeps its endpoint. Absent permits the daemon to derive metadata only
    /// from explicitly enabled hosting it owns; see [`IronWireDeclaration`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ironwire: Option<IronWireDeclaration>,

    /// Whether the final inference call's verbatim request and response
    /// bodies are carried to a witness.
    ///
    /// **A second answer, never a consequence of the field above.** The
    /// declaration says "read this proxy's ledger": numbers about calls --
    /// how many, how much they cost, which backend served them. This says
    /// "and send that call's content", which is the contributor's own
    /// prompt, in the clear, to a remote process. A contributor who wanted
    /// cost attribution has not thereby agreed to publish a prompt, so
    /// declaring the proxy must never switch this on and this is a separate
    /// key on the wire. The directory is *derived* from the declaration --
    /// see [`attested_bodies_dir_for`] -- because two configured paths that
    /// have to agree is a bug waiting to happen; the switch is what stays
    /// separate.
    ///
    /// `#[serde(default)]` so a settings file written before this field
    /// existed loads with it off. An upgrade must not start sending prompt
    /// bodies on its own.
    ///
    /// Off is fully inert: nothing is read, nothing is carried, and a
    /// contributor with no witness configured is unaffected either way --
    /// the bodies only ever reach a witness (`witness::transport`), never a
    /// queued or submitted envelope.
    #[serde(default)]
    pub ironwire_attested_bodies: bool,
    /// Separate consent to include filtered token probabilities in explicit reviews.
    #[serde(default)]
    pub token_distributions_contribution: bool,
    #[serde(default)]
    pub token_capture_enabled: Option<bool>,

    /// Run IronWire inside this daemon, so tools can send inference through
    /// it. Off by default and never turned on by discovery: finding
    /// IronWire's pointer on disk means someone else is running it, which is
    /// a different fact from the contributor asking us to.
    ///
    /// Turning this on does not repoint any agent. Which tools route through
    /// IronWire stays a per-tool declaration. With no explicit `ironwire`
    /// declaration, the owned proxy supplies metadata routing only; body
    /// collection remains a separate opt-in requiring an explicit Watch.
    ///
    /// `#[serde(default)]` so a settings file written before this field
    /// existed loads with it off. An upgrade must never start a proxy on a
    /// contributor's machine because the key was absent.
    #[serde(default)]
    pub private_inference: bool,

    /// Whether the contributor has been asked about the switch above.
    ///
    /// Written by *either* answer, so "Not now" is remembered exactly as
    /// "Turn it on" is, and a shell that asked once does not ask again on
    /// every launch. It records that a question was put, never what the
    /// answer was: the answer is the boolean above, and reading this one as
    /// consent to anything would be reading a receipt as a signature.
    ///
    /// It lives beside the switch, in the daemon, rather than in each
    /// shell's own state file, because the fact belongs to the machine and
    /// not to a window: on Linux the GTK shell attaches to a daemon that
    /// outlives it, and a contributor who answered in one shell has answered.
    ///
    /// `#[serde(default)]` is load-bearing rather than incidental. A settings
    /// file written before this key existed loads unanswered, which is what
    /// makes the offer appear on the first start after an upgrade as well as
    /// on a fresh install -- the two cases the design asks for, from one
    /// default.
    #[serde(default)]
    pub private_inference_offer_seen: bool,

    /// Legacy spellings, read on load and never written.
    ///
    /// Settings files written before source declarations existed carry
    /// `claude_root` / `codex_root` strings meaning "watch this path".
    /// [`DaemonSettings::load`] folds them into the fields above so an
    /// install that already declared its roots is not asked again. They are
    /// `skip_serializing` so a file rewritten by this version stops carrying
    /// two spellings of the same fact.
    /// Public only because `DaemonSettings { .. }` literals live in other
    /// crates; treat it as private. Read by `load` and never written.
    #[serde(default, rename = "claude_root", skip_serializing)]
    pub legacy_claude_root: Option<PathBuf>,
    /// See `legacy_claude_root`.
    #[serde(default, rename = "codex_root", skip_serializing)]
    pub legacy_codex_root: Option<PathBuf>,
}

/// What the contributor said about one agent's session store.
///
/// The tri-state this replaces was `Option<PathBuf>`, where `None` had to
/// carry both "never asked" and "I don't use this agent" -- and the daemon
/// resolved that ambiguity by watching the real `~/.claude` or `~/.codex`
/// (`crate::source::all_sources`). So the one answer a privacy-conscious
/// contributor is most likely to give was the one answer that silently
/// scanned their work.
///
/// Serialized tagged rather than as a bare string, so `off` can never be
/// mistaken for a path and a future third state has somewhere to go:
///
/// ```json
/// "claude_source": { "mode": "watch", "path": "/Users/x/.claude/projects" }
/// "codex_source":  { "mode": "off" }
/// ```
///
/// Deliberately NOT a sentinel path (an empty directory, a temp dir, "/dev/null").
/// A sentinel that is a real filesystem location is a lie every later reader
/// has to decode, and it stops being true the moment somebody creates that
/// directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SourceDeclaration {
    /// Watch this directory. The contributor chose it.
    Watch { path: PathBuf },
    /// The contributor said they do not use this agent. Nothing is watched
    /// for it, and there is no fallback.
    Off,
}

impl SourceDeclaration {
    /// The directory to watch, or `None` when the source is off.
    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            SourceDeclaration::Watch { path } => Some(path.as_path()),
            SourceDeclaration::Off => None,
        }
    }
}

/// What the contributor said about a local inference proxy.
///
/// Deliberately NOT the same tri-state semantics as [`SourceDeclaration`].
/// There, `None` means "never asked" and falls back to the conventional
/// per-user location. Here `None` supplies no endpoint and never triggers
/// discovery. The daemon may separately derive metadata from its own proxy
/// after accepted `private_inference` opt-in; explicit Off always refuses it.
///
/// A session root has a conventional location to fall back to. A local service
/// does not: connecting to `127.0.0.1:8463` because nobody said otherwise is a
/// probe of a service the contributor never mentioned, which is exactly the
/// error the source tri-state was introduced to stop making about their files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum IronWireDeclaration {
    /// Read the proxy's ledger on this loopback port.
    Watch {
        port: u16,
        /// Where the proxy writes `control.token`, when the contributor
        /// said. Absent means fall back to the discovery pointer, then
        /// `IRONWIRE_HOME`, then `~/.ironwire`; see [`ironwire_ledger_for`].
        ///
        /// The *directory*, never the token. The token is a credential for
        /// an API that can rewrite the contributor's agent configuration; it
        /// is read at call time and never enters our settings file.
        ///
        /// `#[serde(default)]` because every settings file already on disk
        /// was written before this field existed, and `skip_serializing_if`
        /// so a file rewritten by this version does not grow a null key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_dir: Option<PathBuf>,
    },
    /// The contributor said they do not use it. Nothing is read.
    Off,
}

/// The file the proxy writes its control-API token to, inside whichever
/// directory [`ironwire_token_path`] resolves.
pub const IRONWIRE_TOKEN_FILE: &str = "control.token";

/// The subdirectory of the proxy's home holding the verbatim bodies it
/// captured, one pair per exchange as `<body_ref>.req` / `<body_ref>.res`.
///
/// IronWire's own name for it, and the only place this crate spells it.
pub const IRONWIRE_BODIES_SUBDIR: &str = "bodies";

impl IronWireDeclaration {
    /// The port to read, or `None` when the proxy is off.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        match self {
            IronWireDeclaration::Watch { port, .. } => Some(*port),
            IronWireDeclaration::Off => None,
        }
    }

    /// The declared directory holding `control.token`, when there is one.
    #[must_use]
    pub fn token_dir(&self) -> Option<&std::path::Path> {
        match self {
            IronWireDeclaration::Watch { token_dir, .. } => token_dir.as_deref(),
            IronWireDeclaration::Off => None,
        }
    }
}

/// The file `control.token` would be read from, given a declared directory.
///
/// Factored out of [`ironwire_ledger_for`] rather than duplicated because a
/// probe that reports a different path from the one the reader actually uses
/// is worse than no probe: it would send a contributor to fix a file nothing
/// reads. Both callers resolve through this one function, so they cannot
/// drift. The resolution order it encodes is documented on
/// [`ironwire_ledger_for`].
///
/// Reads the discovery pointer at call time, so a proxy started after the
/// daemon is found without a restart, and one stopped cleanly stops being
/// consulted. See [`super::ironwire_pointer`] for why a missing or unusable
/// pointer is not an error.
///
/// `None` only when nothing at all resolves -- no declared directory, no
/// pointer, no `IRONWIRE_HOME`, and no discoverable home directory.
#[must_use]
pub fn ironwire_token_path(declared: Option<&std::path::Path>) -> Option<PathBuf> {
    ironwire_token_path_with(declared, super::ironwire_pointer::read_pointer().as_ref())
}

/// [`ironwire_token_path`] against a pointer supplied by the caller.
///
/// The whole resolution order in one pure function, so a test can state it
/// without a home directory to write into.
#[must_use]
pub(crate) fn ironwire_token_path_with(
    declared: Option<&std::path::Path>,
    pointer: Option<&super::ironwire_pointer::IronWirePointer>,
) -> Option<PathBuf> {
    if let Some(declared) = declared {
        return Some(declared.join(IRONWIRE_TOKEN_FILE));
    }
    // The pointer names a *file*, not a directory, and is used as written.
    // A running daemon's own statement of where it put its token is better
    // evidence than a convention, and strictly better evidence than
    // `IRONWIRE_HOME`, which a GUI application launched from Finder, the
    // Dock or a desktop entry never sees.
    //
    // Taken only when the file is actually there, and this is the one place
    // in this function that falls through on a miss. It is deliberately the
    // opposite of the declared-directory rule directly above, and for the
    // same underlying reason. A *declared* directory that holds no token
    // must not fall through, because falling through would enrich the
    // contributor from a proxy they did not name. A *pointer* is not a
    // thing the contributor named; it is a file a crashed daemon can leave
    // behind. Honouring a stale one to the point of refusing the token
    // `IRONWIRE_HOME` still names would make discovery turn a working
    // configuration into a broken one -- a stale pointer strictly worse
    // than no pointer, which is the thing it must never be. Falling
    // through leaves that machine exactly where it was before this file
    // was ever read.
    //
    // A file that exists and cannot be read does not fall through: it
    // yields that path, the read fails, and there is no reader -- the same
    // state as no proxy, and the state the probe reports as
    // `token_unreadable` naming this path, which is the fixable fact.
    //
    // The existence check races a daemon shutting down. Losing that race
    // costs a token read that fails, which is a state every caller here
    // already treats as "no proxy".
    //
    // `trustworthy_file` rather than `is_file`: this is the one branch whose
    // path came out of a file anything on the machine can write, so the
    // token it names must also be a regular file this user owns and nobody
    // else can write. `read_pointer` has already confined the path to the
    // token directory; this is the check on the file at the end of it.
    if let Some(from_pointer) = pointer.and_then(|p| p.token_path.as_ref())
        && super::ironwire_pointer::trustworthy_file(from_pointer).is_some()
    {
        return Some(from_pointer.clone());
    }
    Some(ironwire_default_token_dir()?.join(IRONWIRE_TOKEN_FILE))
}

/// The folder the token is read from when nothing has been declared.
///
/// `$IRONWIRE_HOME`, else `~/.ironwire`: the last step of
/// [`ironwire_token_path_with`]'s order, and the only step that is a fixed
/// convention rather than something a contributor or a running daemon said.
///
/// Exported because it is also what the settings screen's folder field means
/// by "the usual place". That sentence used to name nothing, and a
/// contributor sent to the field by a failure line had no way to learn which
/// folder it was about. Resolved here rather than in the copy so the
/// sentence cannot name one folder while this function reads another.
#[must_use]
pub fn ironwire_default_token_dir() -> Option<PathBuf> {
    std::env::var_os("IRONWIRE_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(super::ironwire_pointer::POINTER_DIR)))
}

/// Build a routing ledger for a declaration, or nothing.
///
/// The `control.token` to read resolves in this order:
///
/// 1. `control.token` in the directory declared in settings,
/// 2. the `token_path` in IronWire's discovery pointer, when that file is
///    actually there,
/// 3. `$IRONWIRE_HOME/control.token`,
/// 4. `~/.ironwire/control.token`.
///
/// Settings come first because a declaration is an explicit human
/// instruction, and because they are the only one of the four a GUI
/// contributor can actually set: an app launched from Finder, the Dock or a
/// desktop entry inherits the session manager's environment, not a shell
/// profile's, so `IRONWIRE_HOME` is not a configuration mechanism for the
/// desktop applications at all. It stays supported, third, so a CLI started
/// from a shell keeps working.
///
/// The pointer sits second, above the environment, because it is the
/// running daemon's own statement of fact about where it put its token,
/// written by the process that wrote the token. `IRONWIRE_HOME` is a guess
/// about that same daemon made by whoever launched this app -- and on the
/// desktop, nobody.
///
/// # The port is not discovered here
///
/// The pointer also states a port, and this function ignores it. A declared
/// port is left alone, always, and an *undeclared* proxy is still not read.
///
/// A declared port is a human instruction; the pointer is a file left on
/// disk that survives the daemon that wrote it. IronWire removes it on a
/// clean stop, so a crash leaves it behind -- and the failure mode of
/// letting it win is not "one refused connection". It is a contributor who
/// declared 8463, whose stale pointer says 9000, and whose traces quietly
/// carry either nothing or the routing data of whatever else is on 9000,
/// with the settings file still reading 8463 and the probe -- which is
/// handed the port by the caller -- still agreeing with it. That is a
/// confidently wrong answer, which is the one thing a stale pointer must
/// not be able to produce.
///
/// And leaving an undeclared proxy unread is the tri-state on
/// [`IronWireDeclaration`]: connecting to a local service nobody named is
/// exactly the error the declaration exists to stop.
///
/// So discovery of the *port* is offered to the declaring flow instead, by
/// the `discover_routing` IPC method: the app pre-fills what the machine
/// already knows and the contributor confirms it, which removes the
/// question without removing the consent. The token path needs no such
/// confirmation because it is only ever consulted for a proxy the
/// contributor already declared.
///
/// The token itself is read here at build time and never copied into our
/// settings file. An unreadable token yields no reader: absence and failure
/// are the same state at this layer, and a declared directory that turns out
/// to hold no token does *not* fall through to the environment -- falling
/// through would enrich the contributor from a proxy they did not name.
#[must_use]
pub fn ironwire_ledger_for(
    declaration: Option<&IronWireDeclaration>,
) -> Option<std::sync::Arc<crate::routing::ironwire::IronWireLedger>> {
    let declaration = declaration?;
    let port = declaration.port()?;
    let path = ironwire_token_path(declaration.token_dir())?;
    // The token is a credential for an API that can rewrite the
    // contributor's agent configuration, and this process is about to put it
    // on the wire. A file another principal could have written is not one to
    // send anywhere, whichever of the four resolution steps produced it.
    super::ironwire_pointer::trustworthy_file(&path)?;
    let token = std::fs::read_to_string(&path).ok()?;
    Some(std::sync::Arc::new(
        crate::routing::ironwire::IronWireLedger::new(port, token.trim().to_string()),
    ))
}

/// Where the proxy's verbatim body store is, for a deployment that carries
/// attested bodies -- and `None` for every deployment that does not.
///
/// Two independent conditions, both required, and the separation between
/// them is the point:
///
/// 1. `enabled` -- the contributor's answer to "carry the call's content",
///    which is [`DaemonSettings::ironwire_attested_bodies`] and nothing
///    else. A routing declaration alone never satisfies it.
/// 2. a declared, watched proxy -- because the bodies are located through
///    the ledger rows joined to a session, so a body store with no ledger
///    names nothing.
///
/// The path is **derived**, not configured. It resolves through
/// [`ironwire_token_path`] and takes the home that produced the token, so
/// the store this reads and the token the ledger reads always come from the
/// same proxy. A second configured path would be a second thing to keep in
/// agreement, and the failure of that agreement is silent: a body store
/// belonging to some other proxy would be read as this one's.
///
/// Fail-closed everywhere. No declaration, a declaration of `Off`, a switch
/// left off, or nothing at all resolving -- every one of them is `None`, no
/// error and nothing carried, which is exactly the state a machine with no
/// proxy is in. A directory that does not exist or cannot be read is not
/// checked here either: `routing::attested` refuses on the read, by name,
/// and refusing there keeps every "could not carry" answer in one place.
#[must_use]
pub fn attested_bodies_dir_for(
    declaration: Option<&IronWireDeclaration>,
    enabled: bool,
) -> Option<PathBuf> {
    if !enabled {
        return None;
    }
    let declaration = declaration?;
    // `Off` answers `None` here, which is the refusal.
    declaration.port()?;
    let token = ironwire_token_path(declaration.token_dir())?;
    Some(token.parent()?.join(IRONWIRE_BODIES_SUBDIR))
}

fn default_approval_hold_secs() -> u64 {
    DEFAULT_APPROVAL_HOLD_SECS
}

fn default_community_poll_secs() -> u64 {
    DEFAULT_COMMUNITY_POLL_SECS
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            schema_version: DAEMON_SETTINGS_SCHEMA.to_string(),
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            quiescence_secs: DEFAULT_QUIESCENCE_SECS,
            digest_interval_secs: DEFAULT_DIGEST_INTERVAL_SECS,
            queue_ttl_days: DEFAULT_QUEUE_TTL_DAYS,
            growth_factor: DEFAULT_GROWTH_FACTOR,
            growth_min_new_bytes: DEFAULT_GROWTH_MIN_NEW_BYTES,
            max_reuploads: DEFAULT_MAX_REUPLOADS,
            max_uploads_per_day: DEFAULT_MAX_UPLOADS_PER_DAY,
            max_bytes_per_day: DEFAULT_MAX_BYTES_PER_DAY,
            max_queue_entries: DEFAULT_MAX_QUEUE_ENTRIES,
            history_poll_secs: DEFAULT_HISTORY_POLL_SECS,
            community_poll_secs: DEFAULT_COMMUNITY_POLL_SECS,
            canary_interval_secs: DEFAULT_CANARY_INTERVAL_SECS,
            approval_hold_secs: DEFAULT_APPROVAL_HOLD_SECS,
            local_notifications: false,
            near_ai: None,
            near_ai_inference: None,
            near_ai_session: None,
            cloud_credentials: None,
            cloud_storage_unavailable: false,
            claude_source: None,
            codex_source: None,
            gemini_source: None,
            cline_source: None,
            opencode_source: None,
            ironwire: None,
            ironwire_attested_bodies: false,
            token_distributions_contribution: false,
            token_capture_enabled: None,
            private_inference: false,
            private_inference_offer_seen: false,
            legacy_claude_root: None,
            legacy_codex_root: None,
        }
    }
}

impl DaemonSettings {
    /// May prompt for OS storage. Call on a blocking worker before starting
    /// Cloud consumers.
    pub fn load_with_cloud_credentials(store: &ConfigStore) -> Result<Self> {
        crate::daemon::cloud_credential_lifecycle::load_for_runtime(store)
    }

    /// Preserve existing metadata during preference edits without requiring an
    /// available OS entry. Legacy plaintext must migrate before the next save.
    /// Call on a blocking worker: migration may prompt for OS storage.
    pub fn load_for_preferences(store: &ConfigStore) -> Result<Self> {
        let settings = Self::load(store)?;
        if settings.near_ai_inference.is_some() || settings.near_ai_session.is_some() {
            Self::load_with_cloud_credentials(store)
        } else {
            Ok(settings)
        }
    }
    /// Load persisted settings, falling back to defaults when the daemon has
    /// never been configured on this machine.
    pub fn load(store: &ConfigStore) -> Result<Self> {
        let Some(body) = store.read_daemon_file(DAEMON_SETTINGS_FILE)? else {
            return Ok(Self::default());
        };
        // The serde context stays for local stderr and journals, where the
        // parser's own "missing field `schema_version` at line 1 column 65"
        // is the whole diagnosis. `StartFailure` rides alongside it so a
        // caller across the C ABI -- which must not receive that text, since
        // the file it names is in the contributor's home directory -- can
        // still tell this apart from every other start failure.
        let mut settings: Self = serde_json::from_slice(&body)
            .context("parsing daemon settings")
            .context(crate::daemon::StartFailure::SettingsUnreadable)?;
        settings.absorb_legacy_roots();
        Ok(settings)
    }

    /// Fold `claude_root` / `codex_root` from an older file into the source
    /// declarations. A legacy path means "watch this"; it never means off,
    /// because off could not be expressed before this existed.
    ///
    /// An explicit declaration always wins, so a file carrying both (written
    /// by a version in between, or edited by hand) is not downgraded.
    fn absorb_legacy_roots(&mut self) {
        if self.claude_source.is_none()
            && let Some(path) = self.legacy_claude_root.take()
        {
            self.claude_source = Some(SourceDeclaration::Watch { path });
        }
        if self.codex_source.is_none()
            && let Some(path) = self.legacy_codex_root.take()
        {
            self.codex_source = Some(SourceDeclaration::Watch { path });
        }
        self.legacy_claude_root = None;
        self.legacy_codex_root = None;
    }

    /// What the contributor declared, in the shape `crate::source::all_sources`
    /// takes.
    ///
    /// The named fields stay the serialised shape -- a `daemon-settings.json`
    /// written by any previous version parses unchanged -- and the map is
    /// built from them here, in one place, so adding an adapter does not
    /// touch the daemon, the watcher, the preview scheduler or the CLI.
    ///
    /// No WORKING-DIRECTORY trajectory scope: a daemon's working directory
    /// is whatever a service manager handed it, so auto-discovery would
    /// mean nothing there.
    ///
    /// The STAGING directory is a different thing and is included. It is a
    /// fixed path under the contributor's own state directory, resolved
    /// through `ConfigStore`, created 0700 and cleared by `logout`, holding
    /// only what `import-antigravity` put there on an explicit command.
    ///
    /// That distinction was previously collapsed: this method took neither,
    /// under one reason that covers only the first. The cost was that every
    /// imported conversation was invisible to all three desktop apps -- no
    /// entry, no error, no empty state naming it -- while the CLI, which
    /// builds its own roots, could see them the whole time.
    ///
    /// No routing overlay either, and deliberately not yet: settings
    /// describe the IronWire *declaration*, not the ledger *instance*.
    /// [`ironwire_ledger_for`] builds a fresh, cold `IronWireLedger` on every
    /// call, so wiring it in here would hand every caller its own
    /// never-refreshed snapshot -- the overlay would compile but never
    /// produce a row. The instance needs a single long-lived owner that
    /// refreshes it on a schedule, which is a separate, reviewed piece of
    /// work; see [`crate::source::SourceRoots::with_routing`].
    pub fn source_roots(&self, store: &ConfigStore) -> crate::source::SourceRoots {
        crate::source::SourceRoots::new()
            .declare(
                crate::source::SOURCE_CLAUDE_CODE,
                self.claude_source.clone(),
            )
            .declare(crate::source::SOURCE_CODEX, self.codex_source.clone())
            .declare(crate::source::SOURCE_GEMINI_CLI, self.gemini_source.clone())
            .declare(crate::source::SOURCE_CLINE, self.cline_source.clone())
            .declare(crate::source::SOURCE_OPENCODE, self.opencode_source.clone())
            .with_trajectory(crate::source::TrajectorySelection::Auto {
                working_dir: None,
                staging_dir: Some(store.dir().join(crate::source::TRAJECTORY_STAGING_SUBDIR)),
            })
    }

    pub fn save(&self, store: &ConfigStore) -> Result<()> {
        let locks = crate::daemon::nearai_credential::session::coordination(store.dir())?;
        let _commit = locks.commit.lock()?;
        // A preference writer may not restore a connection replaced since
        // its snapshot was read. Credential mutations use the lifecycle.
        crate::daemon::cloud_credential_lifecycle::ensure_current(&Self::load(store)?, self)?;
        self.save_locked(store)
    }

    pub(crate) fn save_locked(&self, store: &ConfigStore) -> Result<()> {
        let has_secrets = self.near_ai_inference.is_some() || self.near_ai_session.is_some();
        if has_secrets
            && !self.cloud_credentials.as_ref().is_some_and(|metadata| {
                metadata.matches(
                    self.near_ai_inference.as_ref(),
                    self.near_ai_session.as_ref(),
                )
            })
        {
            return Err(anyhow::anyhow!(
                "near_ai_credential_storage_migration_required"
            ));
        }
        let mut persisted = self.clone();
        persisted.near_ai_inference = None;
        persisted.near_ai_session = None;
        let body = serde_json::to_vec_pretty(&persisted).context("serializing daemon settings")?;
        store.write_daemon_file(DAEMON_SETTINGS_FILE, &body)
    }
}

/// A partial-settings object held nothing this function recognizes.
pub const ERR_SETTINGS_NOT_OBJECT: &str = "settings-not-object";
/// A partial-settings object had a top-level key this function does not
/// recognize.
pub const ERR_SETTINGS_UNKNOWN_FIELD: &str = "settings-unknown-field";
/// A recognized key held a value of the wrong JSON type (or, for
/// `claude_root`/`codex_root`, a JSON type other than string/null), or --
/// for `max_uploads_per_day`/`max_bytes_per_day` -- a value of the right
/// type but out of the accepted range (zero, or above the validated
/// ceiling; see `MAX_UPLOADS_PER_DAY_CEILING` and
/// `MAX_BYTES_PER_DAY_CEILING`). One fixed label covers both failure
/// shapes deliberately: the point of the label is that it never carries
/// the caller's value, and "wrong type" vs. "right type, wrong range" is
/// not a distinction a fail-closed caller needs to branch on.
pub const ERR_SETTINGS_INVALID_VALUE: &str = "settings-invalid-value";

/// The `daemon-settings.json` key carrying one adapter's declaration.
///
/// The mapping exists because the adapter names are wire names
/// (`gemini-cli`) and the settings keys are field names (`gemini_source`);
/// a shell that renders one candidate per discovered source needs to turn
/// the first into the second without transcribing a table of its own. An
/// unrecognised source answers `None` rather than inventing a key, so a
/// caller that has fallen behind this crate refuses rather than writing a
/// field `apply_settings_object` will reject.
pub fn source_settings_key(source: &str) -> Option<&'static str> {
    match source {
        crate::source::SOURCE_CLAUDE_CODE => Some("claude_source"),
        crate::source::SOURCE_CODEX => Some("codex_source"),
        crate::source::SOURCE_GEMINI_CLI => Some("gemini_source"),
        crate::source::SOURCE_CLINE => Some("cline_source"),
        crate::source::SOURCE_OPENCODE => Some("opencode_source"),
        _ => None,
    }
}

/// Whether the contributor has said which session folders to watch.
///
/// BOTH, not either. `claude_root: None` does not mean "no Claude source" --
/// `DaemonSettings` documents it as meaning the conventional per-user
/// location, so an undeclared root is the real `~/.claude` or `~/.codex`.
/// Half a declaration therefore buys none of the protection while reading as
/// though it had, which is why an `||` here would be a fail-open.
///
/// This is the ONLY place the rule is written. The application shells consult
/// it -- macOS and Windows through the C ABI's start functions, the GTK shell
/// by calling it directly -- rather than each transcribing the predicate into
/// its own language, because three copies of a rule that decides whether a
/// developer's source tree gets scanned is three chances for one of them to
/// drift. Compare `tc_daemon_start_with_settings`, which shares
/// `set_settings`' validator for exactly this reason.
///
/// The daemon core does not consult it: `trace-commons-contributor daemon` is
/// someone typing a command on purpose, and the CLI keeps its defaults.
pub fn roots_declared(settings: &DaemonSettings) -> bool {
    settings.claude_source.is_some() && settings.codex_source.is_some()
}

/// Whether the contributor has been asked about their Gemini CLI sessions.
///
/// Deliberately NOT a third conjunct in `roots_declared`. That predicate
/// decides whether the daemon may start, and every desktop client already
/// installed declares claude and codex and has no gemini field: a third
/// conjunct would stop the daemon starting on every one of them. An absent
/// gemini declaration is not disqualifying because it is not dangerous --
/// it constructs no adapter and scans nothing (`crate::source::Undeclared`)
/// -- which is exactly the property the fail-closed-roots rule turns on.
///
/// So this is a question about what a shell should OFFER to ask, not a gate
/// on starting.
pub fn gemini_declared(settings: &DaemonSettings) -> bool {
    settings.gemini_source.is_some()
}

/// Apply a partial settings object -- the shape `tc_call(handle,
/// "set_settings", ...)` takes over the socket, and the shape
/// `tc_daemon_start_with_settings` takes over the C ABI before the daemon's
/// first supervisor tick -- onto `settings` in place. One function, so
/// both callers share one definition of "a valid settings object" rather
/// than two that can drift.
///
/// Every top-level key must be one this function recognizes; an
/// unrecognized key is rejected outright (`Err(ERR_SETTINGS_UNKNOWN_FIELD)`)
/// rather than silently ignored. Silently ignoring a misspelled
/// `claude_root` is exactly the bug this exists to prevent: a caller that
/// meant to redirect the watcher and typo'd the key would otherwise get no
/// signal at all, and the daemon would quietly go on scanning wherever it
/// was already pointed.
///
/// Every error is a fixed, content-free `&'static str` label. In
/// particular, a bad `claude_root`/`codex_root` value never appears in the
/// label -- only the recognized field name distinguishes one failure from
/// another, and the field *names* are a small, fixed, known set, never
/// caller-supplied text. The values themselves (which is where a
/// filesystem path lives) never cross into an error string.
///
/// Returns whether anything was applied. An empty object (or one holding
/// only keys whose values happen to match the current setting) still
/// reports `true` for any key present and accepted -- this always applies
/// every key it accepts, so `Ok(false)` only ever means "the object had no
/// keys at all". Callers that require at least one recognized field (as
/// `set_settings` does, to catch an empty or accidental call) check that
/// themselves; `tc_daemon_start_with_settings` does not, since "nothing to
/// override" is its documented no-op case.
///
/// `max_uploads_per_day` and `max_bytes_per_day` are validated against a
/// fixed ceiling (`MAX_UPLOADS_PER_DAY_CEILING`, `MAX_BYTES_PER_DAY_CEILING`)
/// rather than accepted as an open field: the cap exists to bound a runaway
/// client, and an unbounded setter would give that protection up entirely.
/// A value below the current default is accepted with no floor beyond
/// non-zero -- throttling one's own uploads is not a safety concern -- but
/// zero and anything above the ceiling are refused with the same
/// `ERR_SETTINGS_INVALID_VALUE` label the other typed fields use.
pub fn apply_settings_object(
    settings: &mut DaemonSettings,
    params: &serde_json::Value,
) -> std::result::Result<bool, &'static str> {
    let obj = params.as_object().ok_or(ERR_SETTINGS_NOT_OBJECT)?;
    let mut changed = false;
    for (key, value) in obj {
        // SET-SETTINGS-KEYS-BEGIN
        //
        // `docs/contributor-daemon-ipc-v1_1.md` lists these keys twice, and
        // drifted to eight while this match accepted twelve -- a Task author
        // reading the doc would have concluded `ironwire` was not settable.
        // `the_ipc_doc_lists_every_key_this_match_accepts` walks the region
        // between these markers via `include_str!`. **Adding a key outside
        // them makes that test cover nothing**, which is the exact failure it
        // replaces.
        match key.as_str() {
            "quiescence_secs" => {
                settings.quiescence_secs = value.as_u64().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            "digest_interval_secs" => {
                settings.digest_interval_secs = value.as_u64().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            "approval_hold_secs" => {
                settings.approval_hold_secs = value.as_u64().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            "local_notifications" => {
                settings.local_notifications = value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            // Both caps take a validated ceiling, not an open field: the
            // cap exists to bound a runaway client, and a freely settable
            // value would give up exactly the protection it was added for.
            // A value below the default IS allowed -- a contributor
            // throttling their own uploads is a legitimate thing to want
            // and is not a safety concern -- but zero is refused rather
            // than accepted as "no uploads": that state already exists and
            // is spelled `pause`, which (unlike a cap of zero) is visibly
            // temporary and does not fight the health-label machinery that
            // treats a reached cap as a `CapReached`/health-label
            // condition on every single upload attempt.
            "max_uploads_per_day" => {
                settings.max_uploads_per_day = parse_max_uploads_per_day(value)?;
            }
            "max_bytes_per_day" => {
                settings.max_bytes_per_day = parse_max_bytes_per_day(value)?;
            }
            // The path spellings. A string declares "watch this"; null
            // clears the declaration back to never-asked, which is what the
            // application shells refuse to start on. Kept because the C ABI
            // documents these exact keys and both native shells send them.
            "claude_root" => {
                settings.claude_source = parse_optional_root(value)?;
            }
            "codex_root" => {
                settings.codex_source = parse_optional_root(value)?;
            }
            // The full declaration, including the one thing a path cannot
            // say: off.
            "claude_source" => {
                settings.claude_source = parse_source_declaration(value)?;
            }
            "codex_source" => {
                settings.codex_source = parse_source_declaration(value)?;
            }
            "gemini_source" => {
                settings.gemini_source = parse_source_declaration(value)?;
            }
            "cline_source" => {
                settings.cline_source = parse_source_declaration(value)?;
            }
            "opencode_source" => {
                settings.opencode_source = parse_source_declaration(value)?;
            }
            // Unlike the source roots above, `null` here means **off**, not
            // "never asked" -- see `IronWireDeclaration`'s doc comment for
            // why the tri-state does not apply to a local service with no
            // conventional fallback location.
            "ironwire" => {
                settings.ironwire = parse_ironwire_declaration(value)?;
            }
            // A SECOND question, deliberately not folded into the key
            // above. Declaring the proxy is consent to read metadata about
            // calls; this is consent to send one call's content to a
            // witness. A shell that sets `ironwire` and not this one gets
            // routing telemetry and no bodies, which is the answer most
            // contributors mean.
            "token_distributions_contribution" => {
                settings.token_distributions_contribution =
                    value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            "ironwire_attested_bodies" => {
                settings.ironwire_attested_bodies =
                    value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            // A THIRD question, and the only one that starts a process.
            // `ironwire` says "read the proxy running over there"; this
            // says "be the proxy". Setting it never repoints a tool, and
            // clearing it stops only the instance this daemon started --
            // an IronWire someone else is running is never touched by
            // either value.
            "token_capture_enabled" => {
                settings.token_capture_enabled =
                    Some(value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?);
            }
            "private_inference" => {
                settings.private_inference = value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            // NOT a fourth answer -- a record that the question was asked.
            // A shell writes it on either button, and nothing in the daemon
            // reads it except a shell deciding whether to ask again. It
            // starts nothing and stops nothing.
            "private_inference_offer_seen" => {
                settings.private_inference_offer_seen =
                    value.as_bool().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
            }
            _ => return Err(ERR_SETTINGS_UNKNOWN_FIELD),
        }
        // SET-SETTINGS-KEYS-END
        changed = true;
    }
    Ok(changed)
}

/// `max_uploads_per_day`: a non-zero `u32` at most `MAX_UPLOADS_PER_DAY_CEILING`.
/// Zero is refused -- see the call site's doc for why a cap of zero is not
/// this method's way to stop uploads.
fn parse_max_uploads_per_day(value: &serde_json::Value) -> std::result::Result<u32, &'static str> {
    let n = value.as_u64().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
    if n == 0 || n > MAX_UPLOADS_PER_DAY_CEILING as u64 {
        return Err(ERR_SETTINGS_INVALID_VALUE);
    }
    Ok(n as u32)
}

/// `max_bytes_per_day`: a non-zero `u64` at most `MAX_BYTES_PER_DAY_CEILING`.
fn parse_max_bytes_per_day(value: &serde_json::Value) -> std::result::Result<u64, &'static str> {
    let n = value.as_u64().ok_or(ERR_SETTINGS_INVALID_VALUE)?;
    if n == 0 || n > MAX_BYTES_PER_DAY_CEILING {
        return Err(ERR_SETTINGS_INVALID_VALUE);
    }
    Ok(n)
}

/// `null` clears the override (falls back to the conventional per-user
/// location); a string sets it; anything else is a type error. Never
/// formats `value` into the error -- see `apply_settings_object`'s doc.
fn parse_optional_root(
    value: &serde_json::Value,
) -> std::result::Result<Option<SourceDeclaration>, &'static str> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(SourceDeclaration::Watch {
            path: PathBuf::from(s),
        })),
        _ => Err(ERR_SETTINGS_INVALID_VALUE),
    }
}

/// `{"mode":"watch","port":8463}` or null to turn it off. `{"mode":"off"}`
/// is also accepted since it round-trips `IronWireDeclaration::Off`, but null
/// is the documented way to reach the same state over IPC. Never formats
/// `value` into the error -- see `apply_settings_object`'s doc.
fn parse_ironwire_declaration(
    value: &serde_json::Value,
) -> std::result::Result<Option<IronWireDeclaration>, &'static str> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(_) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| ERR_SETTINGS_INVALID_VALUE),
        _ => Err(ERR_SETTINGS_INVALID_VALUE),
    }
}

/// `{"mode":"watch","path":"..."}`, `{"mode":"off"}`, or null to clear the
/// declaration back to never-asked. Never formats `value` into the error --
/// see `apply_settings_object`'s doc; a declaration carries a path.
fn parse_source_declaration(
    value: &serde_json::Value,
) -> std::result::Result<Option<SourceDeclaration>, &'static str> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(_) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| ERR_SETTINGS_INVALID_VALUE),
        _ => Err(ERR_SETTINGS_INVALID_VALUE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests_support::temp_store;

    fn credential() -> NearAiInferenceCredential {
        NearAiInferenceCredential {
            key: "sk-super-secret-key".into(),
            key_id: "key-1".into(),
            key_prefix: "sk-sup".into(),
            organization_id: "org-1".into(),
            workspace_id: "ws-1".into(),
            minted_at: Utc::now(),
        }
    }

    /// `DaemonSettings` derives `Debug`, so a derived `Debug` on the
    /// credential would put a live inference key into every `{:?}` of the
    /// whole settings document -- one `tracing::debug!` from a log file.
    #[test]
    fn the_inference_key_is_not_printable_through_the_settings_it_lives_in() {
        let mut settings = DaemonSettings::default();
        assert!(settings.near_ai_inference.is_none(), "off by default");
        settings.near_ai_inference = Some(credential());
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("sk-super-secret-key"), "{rendered}");
        // The prefix is what the service itself shows in its key list, and is
        // how a contributor tells which of their keys this is.
        assert!(rendered.contains("sk-sup"), "{rendered}");
    }

    /// The credential survives the 0600 settings file, and a file written
    /// before the field existed still loads.
    #[test]
    fn the_credential_round_trips_and_an_older_settings_file_still_loads() {
        let (_dir, store) = temp_store();
        let mut settings = DaemonSettings {
            near_ai_inference: Some(credential()),
            ..Default::default()
        };
        settings.save_for_test(&store).unwrap();
        assert_eq!(
            DaemonSettings::load_with_cloud_credentials(&store)
                .unwrap()
                .near_ai_inference,
            settings.near_ai_inference
        );

        let mut older: serde_json::Value =
            serde_json::from_slice(&std::fs::read(store.dir().join(DAEMON_SETTINGS_FILE)).unwrap())
                .unwrap();
        older.as_object_mut().unwrap().remove("near_ai_inference");
        older.as_object_mut().unwrap().remove("cloud_credentials");
        std::fs::write(
            store.dir().join(DAEMON_SETTINGS_FILE),
            serde_json::to_vec(&older).unwrap(),
        )
        .unwrap();
        assert!(
            DaemonSettings::load(&store)
                .unwrap()
                .near_ai_inference
                .is_none()
        );
    }

    /// The daemon reads the staging directory `import-antigravity` writes to.
    ///
    /// It did not, and the reason given covered only half of what it
    /// excluded: a service manager's working directory means nothing to a
    /// daemon, which says nothing about a fixed path under the
    /// contributor's own 0700 state directory. A contributor who imported
    /// and then opened a desktop app saw nothing at all -- no entry, no
    /// error, no empty state naming Antigravity.
    #[test]
    fn the_daemon_reads_the_trajectory_staging_directory() {
        let (_d, store) = temp_store();
        let s = DaemonSettings::default();

        let names: Vec<&str> = crate::source::all_sources(&s.source_roots(&store))
            .iter()
            .map(|s| s.name())
            .collect();
        assert!(
            names.contains(&crate::source::SOURCE_TRAJECTORY),
            "the daemon must construct a trajectory source; got {names:?}"
        );
    }

    /// What the DAEMON CORE does when the contributor has declared nothing.
    ///
    /// Not a fail-closed path, and deliberately so: `roots_declared` gates
    /// the three application shells, never `daemon run`. So this is the
    /// exposure that remains, and it is worth pinning as a fact rather than
    /// leaving as a property somebody has to re-derive from `Undeclared`:
    /// a daemon started from the CLI (which on Linux is the systemd user
    /// unit `daemon install` writes) with a fresh `daemon-settings.json`
    /// constructs claude and codex adapters over the contributor's real
    /// `~/.claude/projects` and `~/.codex/sessions`.
    ///
    /// Gemini is absent from the same settings and constructs nothing,
    /// which is the contrast that makes the first two a choice rather than
    /// an accident. See `crate::source::Undeclared`.
    ///
    /// Documenting, not aspirational. If the CLI's undeclared fallback is
    /// ever closed, this test is what should be changed, alongside the
    /// `Undeclared::Conventional` rows it mirrors.
    #[test]
    fn an_undeclared_daemon_still_builds_the_conventional_claude_and_codex_adapters() {
        let (_d, store) = temp_store();
        let s = DaemonSettings::default();
        assert!(
            !roots_declared(&s),
            "a fresh settings file must not read as declared"
        );

        let names: Vec<&str> = crate::source::all_sources(&s.source_roots(&store))
            .iter()
            .map(|s| s.name())
            .collect();
        let home = dirs::home_dir().unwrap_or_default();
        assert!(
            names.contains(&crate::source::SOURCE_CLAUDE_CODE),
            "an undeclared claude source still reaches {}; got {names:?}",
            home.join(".claude/projects").display()
        );
        assert!(
            names.contains(&crate::source::SOURCE_CODEX),
            "an undeclared codex source still reaches {}; got {names:?}",
            home.join(".codex/sessions").display()
        );
        assert!(
            !names.contains(&crate::source::SOURCE_GEMINI_CLI),
            "but an undeclared gemini source constructs nothing; got {names:?}"
        );
    }

    /// And ONLY the staging directory. The working-directory half of
    /// `TrajectorySelection::Auto` stays off, which is what the original
    /// exclusion was actually about: a daemon's working directory is
    /// whatever a service manager handed it.
    #[test]
    fn the_daemon_does_not_read_its_own_working_directory() {
        let (_d, store) = temp_store();
        let s = DaemonSettings::default();
        let roots = s.source_roots(&store);

        match roots.trajectory_selection() {
            crate::source::TrajectorySelection::Auto {
                working_dir,
                staging_dir,
            } => {
                assert!(
                    working_dir.is_none(),
                    "the daemon must not scan its own working directory"
                );
                assert_eq!(
                    staging_dir.as_deref(),
                    Some(
                        store
                            .dir()
                            .join(crate::source::TRAJECTORY_STAGING_SUBDIR)
                            .as_path()
                    )
                );
            }
            other => panic!("expected an Auto staging selection, got {other:?}"),
        }
    }

    #[test]
    fn settings_round_trip_through_the_store() {
        let (_d, store) = temp_store();
        let s = DaemonSettings {
            quiescence_secs: 60,
            ..Default::default()
        };
        s.save(&store).unwrap();
        assert_eq!(DaemonSettings::load(&store).unwrap().quiescence_secs, 60);
    }

    // `DaemonSettings::schema_version` has no `#[serde(default)]`, so a bare
    // `{}` does not exercise the field under test -- it fails to parse at
    // all, for an unrelated reason. Every case below starts from a full
    // `DaemonSettings::default()` value and edits just the `ironwire` key,
    // matching the pattern `a_settings_file_written_before_gemini_existed_
    // loads_with_it_absent` already uses for the same reason.

    #[test]
    fn a_contributor_who_never_mentioned_the_proxy_is_not_probed() {
        // The divergence from SourceDeclaration, and the reason for it. For a
        // session root, `None` falls back to the conventional location. There is
        // no conventional location for a local service: connecting to 127.0.0.1
        // unasked is a probe of something the contributor never mentioned, which
        // is the same mistake the source tri-state exists to have fixed.
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut().unwrap().remove("ironwire");
        let settings: DaemonSettings = serde_json::from_value(v).expect("settings load");
        assert!(settings.ironwire.is_none());
        assert!(
            ironwire_ledger_for(settings.ironwire.as_ref()).is_none(),
            "no declaration means no reader is built at all"
        );
    }

    #[test]
    fn a_proxy_declared_off_builds_no_reader() {
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v["ironwire"] = serde_json::json!({"mode": "off"});
        let settings: DaemonSettings = serde_json::from_value(v).expect("loads");
        assert!(ironwire_ledger_for(settings.ironwire.as_ref()).is_none());
    }

    /// Also the back-compatibility case: every settings file already on disk
    /// was written before `token_dir` existed, and this JSON has no such
    /// key. It must load with no declared directory rather than fail.
    #[test]
    fn a_watched_proxy_round_trips_its_port() {
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v["ironwire"] = serde_json::json!({"mode": "watch", "port": 8463});
        let settings: DaemonSettings = serde_json::from_value(v).expect("loads");
        assert_eq!(
            settings.ironwire,
            Some(IronWireDeclaration::Watch {
                port: 8463,
                token_dir: None
            })
        );
    }

    use super::super::ironwire_pointer::test_support::IronWireAt;

    /// A directory holding a `control.token` with exactly this text.
    fn token_dir_holding(token: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        std::fs::write(d.path().join("control.token"), format!("{token}\n")).expect("write token");
        d
    }

    /// The whole point of the task: a GUI-launched app has no shell
    /// environment, so the declared path is the only one of the three a
    /// contributor could have set. It must therefore win.
    ///
    /// Asserts *which* token the ledger was built with. "A ledger was built"
    /// would pass under either precedence and prove nothing.
    #[test]
    fn a_declared_token_directory_wins_over_the_environment() {
        let declared = token_dir_holding("token-from-settings");
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());

        let declaration = IronWireDeclaration::Watch {
            port: 8463,
            token_dir: Some(declared.path().to_path_buf()),
        };
        let ledger = ironwire_ledger_for(Some(&declaration))
            .expect("a declared directory holding a token builds a reader");

        assert_eq!(
            ledger.token_for_test(),
            "token-from-settings",
            "the declared directory must win over IRONWIRE_HOME"
        );
    }

    /// The CLI case. `IRONWIRE_HOME` stays supported so an install that
    /// already relies on it keeps working.
    #[test]
    fn the_environment_is_still_honoured_when_no_path_is_declared() {
        let environment = token_dir_holding("token-from-environment");
        // Pins both halves: `IRONWIRE_HOME` here, and "no pointer". A
        // discovery test on another thread must not be able to set either
        // underneath this one -- with the environment loose it would resolve
        // against another test's directory, and with the override loose it
        // would resolve that test's pointer's token instead.
        let _at = IronWireAt::home(environment.path());

        let declaration = IronWireDeclaration::Watch {
            port: 8463,
            token_dir: None,
        };
        let ledger = ironwire_ledger_for(Some(&declaration))
            .expect("IRONWIRE_HOME must still build a reader when nothing is declared");

        assert_eq!(ledger.token_for_test(), "token-from-environment");
    }

    /// Absence and failure stay the same state at this layer -- and a
    /// declared directory that turned out to be wrong must NOT silently fall
    /// through to the environment, or the contributor is enriched from a
    /// proxy they did not name. The difference between "off" and "declared
    /// but unreadable" is reported by the probe in Task 2, not here.
    #[test]
    fn a_declared_directory_with_no_token_yields_no_reader() {
        let declared = tempfile::tempdir().expect("tempdir");
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());

        let declaration = IronWireDeclaration::Watch {
            port: 8463,
            token_dir: Some(declared.path().to_path_buf()),
        };

        assert!(
            ironwire_ledger_for(Some(&declaration)).is_none(),
            "a declared directory with no token yields no reader, and never \
             falls back to the environment"
        );
    }

    // --- the attested-bodies switch ------------------------------------

    /// The separation, stated as a test: declaring the proxy for routing
    /// telemetry carries no bodies. Cost attribution is not consent to send
    /// a prompt, so the switch is a second, independent answer and the
    /// declaration alone never implies it.
    #[test]
    fn a_declared_proxy_alone_carries_no_attested_bodies() {
        let home = token_dir_holding("token");
        let declaration = watch(Some(home.path()));
        assert!(
            attested_bodies_dir_for(Some(&declaration), false).is_none(),
            "a routing declaration must never switch on body capture"
        );
    }

    /// And where the directory comes from: the SAME home the token resolved
    /// in, never a second configured path that could disagree with it.
    #[test]
    fn the_bodies_directory_is_derived_from_the_declared_proxy_home() {
        let home = token_dir_holding("token");
        let declaration = watch(Some(home.path()));
        assert_eq!(
            attested_bodies_dir_for(Some(&declaration), true),
            Some(home.path().join(IRONWIRE_BODIES_SUBDIR)),
            "the body store sits beside the control token, in the one home \
             the contributor named"
        );
    }

    /// Fail-closed on every absent or refused declaration, switch or no
    /// switch.
    #[test]
    fn no_declaration_carries_no_attested_bodies() {
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());
        assert!(
            attested_bodies_dir_for(None, true).is_none(),
            "an undeclared proxy is not read, and its bodies least of all"
        );
        assert!(
            attested_bodies_dir_for(Some(&IronWireDeclaration::Off), true).is_none(),
            "a proxy the contributor declared off carries nothing"
        );
    }

    /// A settings file written before the switch existed loads with it off.
    /// An upgrade must never start sending prompt bodies on its own.
    #[test]
    fn a_settings_file_written_before_the_switch_existed_loads_with_it_off() {
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut()
            .unwrap()
            .remove("ironwire_attested_bodies");
        let settings: DaemonSettings = serde_json::from_value(v).expect("settings load");
        assert!(
            !settings.ironwire_attested_bodies,
            "an absent switch is off, never on"
        );
    }

    /// The offer marker is written by *either* answer, and a settings file
    /// written before it existed loads unanswered.
    ///
    /// That default is the whole mechanism behind "the offer appears on the
    /// first start after an upgrade as well as on a fresh install": an
    /// installed 0.9.0 has a settings file with no such key, so the first
    /// build that knows the key reads it as false and asks.
    #[test]
    fn the_offer_marker_defaults_to_unanswered_and_takes_either_answer() {
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut()
            .unwrap()
            .remove("private_inference_offer_seen");
        let settings: DaemonSettings = serde_json::from_value(v).expect("settings load");
        assert!(
            !settings.private_inference_offer_seen,
            "an absent marker means nobody has been asked yet"
        );

        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"private_inference_offer_seen": true})
            ),
            Ok(true)
        );
        assert!(s.private_inference_offer_seen);
        assert!(
            !s.private_inference,
            "recording that the offer was answered must never start anything"
        );
    }

    /// The marker is a boolean and nothing else, refused by the same label
    /// every other mistyped value gets.
    #[test]
    fn the_offer_marker_refuses_a_non_boolean() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"private_inference_offer_seen": "yes"})
            ),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert!(!s.private_inference_offer_seen);
    }

    // --- the discovery pointer -----------------------------------------

    use super::super::ironwire_pointer::IronWirePointer;

    /// A pointer naming a `control.token` holding exactly this text.
    /// Returns the directory, which must outlive the assertions.
    fn pointer_holding(token: &str) -> (tempfile::TempDir, IronWirePointer) {
        let d = tempfile::tempdir().expect("tempdir");
        let path = d.path().join("control.token");
        std::fs::write(&path, format!("{token}\n")).expect("write token");
        let pointer = IronWirePointer {
            port: 8463,
            token_path: Some(path),
        };
        (d, pointer)
    }

    fn watch(token_dir: Option<&std::path::Path>) -> IronWireDeclaration {
        IronWireDeclaration::Watch {
            port: 8463,
            token_dir: token_dir.map(std::path::Path::to_path_buf),
        }
    }

    /// A declaration is an explicit human instruction and outranks a file
    /// the machine wrote about itself.
    ///
    /// Asserts *which* token is resolved. "A path came back" would pass
    /// under either precedence and prove nothing.
    #[test]
    fn a_declared_directory_wins_over_the_pointer() {
        let declared = token_dir_holding("token-from-settings");
        let (_d, pointer) = pointer_holding("token-from-pointer");

        let path = ironwire_token_path_with(Some(declared.path()), Some(&pointer))
            .expect("a declared directory always resolves");

        assert_eq!(path, declared.path().join(IRONWIRE_TOKEN_FILE));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            "token-from-settings",
        );
    }

    /// The running daemon's own statement of fact beats an environment
    /// variable no GUI application ever sees.
    #[test]
    fn the_pointer_wins_over_the_environment() {
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());
        let (_d, pointer) = pointer_holding("token-from-pointer");

        let path =
            ironwire_token_path_with(None, Some(&pointer)).expect("the pointer resolves a path");

        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            "token-from-pointer",
            "the pointer must outrank IRONWIRE_HOME",
        );
    }

    /// The pointer names a file. Joining `control.token` onto it would read
    /// `.../control.token/control.token` and find nothing, on every machine
    /// where IronWire put its token anywhere but the conventional name.
    #[test]
    fn the_pointer_path_is_used_as_a_file_not_joined_as_a_directory() {
        let d = tempfile::tempdir().expect("tempdir");
        let path = d.path().join("ironwire.tok");
        std::fs::write(&path, "tok\n").expect("write token");
        let pointer = IronWirePointer {
            port: 8463,
            token_path: Some(path.clone()),
        };

        assert_eq!(ironwire_token_path_with(None, Some(&pointer)), Some(path));
    }

    /// The rule that keeps discovery from ever making a machine worse: a
    /// pointer left behind by a crashed daemon, naming a token that is no
    /// longer there, must leave that machine exactly where it was.
    #[test]
    fn a_stale_pointer_falls_through_and_is_no_worse_than_no_pointer() {
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());

        let gone = tempfile::tempdir().expect("tempdir");
        let missing = gone.path().join("control.token");
        let stale = IronWirePointer {
            port: 8463,
            token_path: Some(missing),
        };

        let with_stale = ironwire_token_path_with(None, Some(&stale));
        let without = ironwire_token_path_with(None, None);

        assert_eq!(
            with_stale, without,
            "a stale pointer must resolve exactly what no pointer resolves",
        );
        assert_eq!(
            std::fs::read_to_string(with_stale.unwrap()).unwrap().trim(),
            "token-from-environment",
        );
    }

    /// A pointer that named no token path at all is not a reason to stop
    /// resolving one.
    #[test]
    fn a_pointer_with_no_token_path_still_falls_through() {
        let environment = token_dir_holding("token-from-environment");
        let _at = IronWireAt::home(environment.path());
        let pointer = IronWirePointer {
            port: 8463,
            token_path: None,
        };

        assert_eq!(
            ironwire_token_path_with(None, Some(&pointer)),
            ironwire_token_path_with(None, None),
        );
    }

    /// End to end through the real entry point, which reads the pointer off
    /// disk. Asserts the token the ledger was actually built with.
    #[test]
    fn a_discovered_token_builds_a_reader_for_a_declaration_that_named_no_directory() {
        let d = tempfile::tempdir().expect("tempdir");
        let token = d.path().join("control.token");
        std::fs::write(&token, "token-from-pointer\n").expect("write token");
        let endpoint = d.path().join("endpoint.json");
        std::fs::write(
            &endpoint,
            serde_json::to_string(&serde_json::json!({
                "control_url": "http://127.0.0.1:8463",
                "token_path": token,
            }))
            .expect("pointer serialises"),
        )
        .expect("write pointer");
        let _at = IronWireAt::pointer(&endpoint);

        let ledger = ironwire_ledger_for(Some(&watch(None)))
            .expect("a discovered token must build a reader");
        assert_eq!(ledger.token_for_test(), "token-from-pointer");
    }

    /// The judgement recorded on `ironwire_ledger_for`: the pointer's port
    /// is advisory and never overrides a declared one. A pointer left by a
    /// crashed daemon naming a live-but-unrelated port would otherwise send
    /// every read somewhere the contributor never named, with settings and
    /// the probe both still agreeing on the declared port.
    #[test]
    fn a_pointer_port_never_overrides_a_declared_port() {
        let d = tempfile::tempdir().expect("tempdir");
        let token = d.path().join("control.token");
        std::fs::write(&token, "tok\n").expect("write token");
        let endpoint = d.path().join("endpoint.json");
        std::fs::write(
            &endpoint,
            serde_json::to_string(&serde_json::json!({
                "control_url": "http://127.0.0.1:9999",
                "token_path": token,
            }))
            .expect("pointer serialises"),
        )
        .expect("write pointer");
        let _at = IronWireAt::pointer(&endpoint);

        let declaration = IronWireDeclaration::Watch {
            port: 8463,
            token_dir: None,
        };
        let ledger =
            ironwire_ledger_for(Some(&declaration)).expect("a reader is built from the token");
        assert_eq!(
            ledger.port_for_test(),
            8463,
            "the declared port must survive a pointer naming another one",
        );
    }

    /// An undeclared proxy stays unread. Discovery reaches the *declaring*
    /// flow through `discover_routing`; it does not quietly start reading a
    /// local service nobody named, which is the error the declaration
    /// tri-state exists to prevent.
    #[test]
    fn a_discovered_proxy_is_not_read_without_a_declaration() {
        let d = tempfile::tempdir().expect("tempdir");
        let token = d.path().join("control.token");
        std::fs::write(&token, "tok\n").expect("write token");
        let endpoint = d.path().join("endpoint.json");
        std::fs::write(
            &endpoint,
            serde_json::to_string(&serde_json::json!({
                "control_url": "http://127.0.0.1:8463",
                "token_path": token,
            }))
            .expect("pointer serialises"),
        )
        .expect("write pointer");
        let _at = IronWireAt::pointer(&endpoint);

        assert!(
            ironwire_ledger_for(None).is_none(),
            "no declaration means nothing is read, however discoverable",
        );
        assert!(
            ironwire_ledger_for(Some(&IronWireDeclaration::Off)).is_none(),
            "off means off, however discoverable",
        );
    }

    #[test]
    fn a_declared_token_directory_round_trips_through_the_settings_file() {
        let (_d, store) = temp_store();
        let s = DaemonSettings {
            ironwire: Some(IronWireDeclaration::Watch {
                port: 8463,
                token_dir: Some(PathBuf::from("/declared/ironwire")),
            }),
            ..Default::default()
        };
        s.save(&store).unwrap();
        assert_eq!(
            DaemonSettings::load(&store).unwrap().ironwire,
            Some(IronWireDeclaration::Watch {
                port: 8463,
                token_dir: Some(PathBuf::from("/declared/ironwire"))
            })
        );
    }

    /// `ironwire_ledger_for` and `SourceRoots::with_routing` are correct and
    /// are what a future task wires up. Neither is called from
    /// `source_roots` yet: `ironwire_ledger_for` builds a fresh, cold
    /// `IronWireLedger` on every call, so attaching one here would hand
    /// every caller its own never-refreshed snapshot -- it would compile and
    /// silently enrich nothing. Pinned so that regression does not sneak
    /// back in before the ledger has a single long-lived owner.
    #[test]
    fn source_roots_does_not_yet_attach_a_routing_overlay() {
        let (_d, store) = temp_store();
        let s = DaemonSettings {
            ironwire: Some(IronWireDeclaration::Watch {
                port: 8463,
                token_dir: None,
            }),
            ..Default::default()
        };
        assert!(!s.source_roots(&store).is_routed());
    }

    /// The A2 rule, at the gate it must not join.
    ///
    /// Every desktop client already installed declares claude and codex and
    /// has no gemini field. A third conjunct here would stop the daemon
    /// starting on every one of them.
    #[test]
    fn roots_declared_does_not_require_a_gemini_declaration() {
        let declared = |path: &str| {
            Some(SourceDeclaration::Watch {
                path: PathBuf::from(path),
            })
        };
        let s = DaemonSettings {
            claude_source: declared("/declared/claude"),
            codex_source: declared("/declared/codex"),
            ..Default::default()
        };
        assert!(
            roots_declared(&s),
            "an absent gemini declaration is not disqualifying"
        );
        assert!(
            !gemini_declared(&s),
            "but a shell can still ask whether to offer the question"
        );

        let asked = DaemonSettings {
            gemini_source: Some(SourceDeclaration::Off),
            ..s
        };
        assert!(roots_declared(&asked));
        assert!(
            gemini_declared(&asked),
            "off is an answer; it is not the absence of one"
        );
    }

    /// A settings file written before this source existed must load, and
    /// must construct no gemini adapter.
    #[test]
    fn a_settings_file_written_before_gemini_existed_loads_with_it_absent() {
        let (_d, store) = temp_store();
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut().unwrap().remove("gemini_source");
        store
            .write_daemon_file(DAEMON_SETTINGS_FILE, v.to_string().as_bytes())
            .unwrap();
        let loaded = DaemonSettings::load(&store).unwrap();
        assert_eq!(loaded.gemini_source, None);
        assert!(
            !crate::source::all_sources(&loaded.source_roots(&store))
                .iter()
                .any(|s| s.name() == crate::source::SOURCE_GEMINI_CLI)
        );
    }

    /// The declarations reach `all_sources` as a map, so an adapter added
    /// later needs no call-site change anywhere in the daemon.
    #[test]
    fn source_roots_carries_every_declaration() {
        let s = DaemonSettings {
            claude_source: Some(SourceDeclaration::Off),
            codex_source: Some(SourceDeclaration::Off),
            gemini_source: Some(SourceDeclaration::Watch {
                path: PathBuf::from("/declared/gemini"),
            }),
            ..Default::default()
        };
        let (_d, store) = temp_store();
        let names: Vec<&str> = crate::source::all_sources(&s.source_roots(&store))
            .iter()
            .map(|s| s.name())
            .collect();
        // The trajectory source is always constructed now: the daemon reads
        // the staging directory `import-antigravity` writes to. It comes
        // last because `all_sources` appends it after the native adapters.
        assert_eq!(
            names,
            vec![
                crate::source::SOURCE_GEMINI_CLI,
                crate::source::SOURCE_TRAJECTORY
            ]
        );
    }

    #[test]
    fn the_gemini_declaration_is_settable_and_type_checked() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"gemini_source": {"mode": "off"}})
            ),
            Ok(true)
        );
        assert_eq!(s.gemini_source, Some(SourceDeclaration::Off));
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"gemini_source": "/a/path"})),
            Err(ERR_SETTINGS_INVALID_VALUE),
            "a bare string is the legacy *_root spelling, which this key \
             never had"
        );
    }

    #[test]
    fn opencode_export_declaration_is_explicit_and_old_settings_stay_off() {
        let (_dir, store) = temp_store();
        let mut value = serde_json::to_value(DaemonSettings::default()).unwrap();
        value.as_object_mut().unwrap().remove("opencode_source");
        store
            .write_daemon_file(DAEMON_SETTINGS_FILE, value.to_string().as_bytes())
            .unwrap();
        let mut settings = DaemonSettings::load(&store).unwrap();
        let enabled = |s: &DaemonSettings| {
            crate::source::all_sources(&s.source_roots(&store))
                .iter()
                .any(|source| source.name() == crate::source::SOURCE_OPENCODE)
        };
        assert!(!enabled(&settings));
        assert_eq!(
            source_settings_key(crate::source::SOURCE_OPENCODE),
            Some("opencode_source")
        );
        assert_eq!(
            apply_settings_object(
                &mut settings,
                &serde_json::json!({"opencode_source":{"mode":"watch","path":"/synthetic/exports"}})
            ),
            Ok(true)
        );
        assert!(enabled(&settings));
        settings.save(&store).unwrap();
        assert_eq!(
            DaemonSettings::load(&store).unwrap().opencode_source,
            settings.opencode_source
        );
        assert_eq!(
            apply_settings_object(
                &mut settings,
                &serde_json::json!({"opencode_source":"/bare/path"})
            ),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(
            apply_settings_object(
                &mut settings,
                &serde_json::json!({"opencode_source":{"mode":"off"}})
            ),
            Ok(true)
        );
        assert!(!enabled(&settings));
        assert_eq!(
            apply_settings_object(&mut settings, &serde_json::json!({"opencode_source":null})),
            Ok(true)
        );
        assert!(!enabled(&settings));
    }

    #[test]
    fn the_cline_declaration_is_settable_and_type_checked() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            s.cline_source, None,
            "never asked, and undeclared constructs nothing"
        );
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"cline_source": {"mode": "off"}})
            ),
            Ok(true)
        );
        assert_eq!(s.cline_source, Some(SourceDeclaration::Off));
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"cline_source": {"mode": "watch", "path": "/declared/cline"}}),
            ),
            Ok(true)
        );
        assert_eq!(
            s.cline_source,
            Some(SourceDeclaration::Watch {
                path: PathBuf::from("/declared/cline")
            })
        );
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"cline_source": "/a/path"})),
            Err(ERR_SETTINGS_INVALID_VALUE),
            "a bare path is not a declaration"
        );
        assert_eq!(
            source_settings_key(crate::source::SOURCE_CLINE),
            Some("cline_source")
        );
    }

    /// A settings file written before this source existed must load, and
    /// must construct no cline adapter.
    #[test]
    fn a_settings_file_written_before_cline_existed_loads_with_it_absent() {
        let (_d, store) = temp_store();
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut().unwrap().remove("cline_source");
        store
            .write_daemon_file(DAEMON_SETTINGS_FILE, v.to_string().as_bytes())
            .unwrap();
        let loaded = DaemonSettings::load(&store).unwrap();
        assert_eq!(loaded.cline_source, None);
        assert!(
            !crate::source::all_sources(&loaded.source_roots(&store))
                .iter()
                .any(|s| s.name() == crate::source::SOURCE_CLINE)
        );
    }

    /// Every source a shell can discover must have a settings key, and
    /// every one of those keys must be one `apply_settings_object` accepts.
    /// A source added to the table without both is a roots screen that
    /// silently discards the contributor's answer.
    #[test]
    fn every_discoverable_source_has_a_settings_key_that_round_trips() {
        let (_d, store) = temp_store();
        let home = std::env::temp_dir();
        for candidate in crate::source::discovery::probe(&home, |_| None) {
            let key = source_settings_key(&candidate.source)
                .unwrap_or_else(|| panic!("no settings key for {}", candidate.source));
            let mut s = DaemonSettings::default();
            assert_eq!(
                apply_settings_object(&mut s, &serde_json::json!({ key: {"mode": "off"} })),
                Ok(true),
                "{key} is not a key apply_settings_object accepts"
            );
            assert!(
                s.source_roots(&store)
                    .is_declared(candidate.source.as_str()),
                "{key} did not reach the declaration map"
            );
        }
    }

    #[test]
    fn settings_default_when_the_file_is_absent() {
        let (_d, store) = temp_store();
        let s = DaemonSettings::load(&store).unwrap();
        assert_eq!(s.quiescence_secs, DEFAULT_QUIESCENCE_SECS);
        assert_eq!(s.max_reuploads, DEFAULT_MAX_REUPLOADS);
        assert!(!s.local_notifications, "notifications must be opt-in");
        assert!(s.near_ai.is_none());
    }

    #[test]
    fn the_approval_hold_defaults_to_more_than_the_five_second_undo() {
        // The client-side undo is five seconds. A hold shorter than that
        // would leave the same race the hold exists to remove, so the
        // default is a floor with margin rather than an exact match.
        let s = DaemonSettings::default();
        assert_eq!(s.approval_hold_secs, DEFAULT_APPROVAL_HOLD_SECS);
        assert!(s.approval_hold_secs >= 5);
    }

    #[test]
    fn a_settings_file_written_before_the_hold_existed_loads_with_it_on() {
        // A missing key must not silently mean "no undo window".
        let (_d, store) = temp_store();
        let mut v = serde_json::to_value(DaemonSettings::default()).unwrap();
        v.as_object_mut().unwrap().remove("approval_hold_secs");
        store
            .write_daemon_file(DAEMON_SETTINGS_FILE, v.to_string().as_bytes())
            .unwrap();
        assert_eq!(
            DaemonSettings::load(&store).unwrap().approval_hold_secs,
            DEFAULT_APPROVAL_HOLD_SECS
        );
    }

    #[test]
    fn the_approval_hold_is_settable_and_type_checked() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"approval_hold_secs": 30})),
            Ok(true)
        );
        assert_eq!(s.approval_hold_secs, 30);
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"approval_hold_secs": "30"})),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(s.approval_hold_secs, 30, "a rejected value changes nothing");
    }

    #[test]
    fn a_source_can_be_declared_off_and_that_survives_a_round_trip() {
        // "I don't use Codex" has to be a durable, readable declaration --
        // distinguishable from "watching a path" AND from "never asked".
        // Before this existed the only way to express it was to leave the
        // field unset, which the daemon reads as the real ~/.codex: the
        // exact fail-open the refusal exists to prevent.
        let (_d, store) = temp_store();
        let s = DaemonSettings {
            claude_source: Some(SourceDeclaration::Watch {
                path: PathBuf::from("/somewhere/claude"),
            }),
            codex_source: Some(SourceDeclaration::Off),
            ..Default::default()
        };
        s.save(&store).unwrap();

        let loaded = DaemonSettings::load(&store).unwrap();
        assert_eq!(loaded.codex_source, Some(SourceDeclaration::Off));
        assert_eq!(
            loaded.claude_source,
            Some(SourceDeclaration::Watch {
                path: PathBuf::from("/somewhere/claude")
            })
        );
    }

    #[test]
    fn off_is_not_the_same_as_never_asked() {
        let never = DaemonSettings::default();
        assert_eq!(
            never.codex_source, None,
            "a fresh install has been asked nothing"
        );

        let off = DaemonSettings {
            codex_source: Some(SourceDeclaration::Off),
            ..Default::default()
        };
        assert_ne!(
            off.codex_source, never.codex_source,
            "an answered 'I don't use this' must not collapse into 'not answered'"
        );
    }

    #[test]
    fn a_legacy_settings_file_using_claude_root_still_loads() {
        // Built from a real serialized default so this fixture cannot drift
        // out of sync with the struct, then downgraded to the old spelling:
        // source declarations removed, claude_root / codex_root added back.
        let (_d, store) = temp_store();
        let mut legacy = serde_json::to_value(DaemonSettings::default()).unwrap();
        let obj = legacy.as_object_mut().unwrap();
        obj.remove("claude_source");
        obj.remove("codex_source");
        obj.insert(
            "claude_root".to_string(),
            serde_json::Value::String("/legacy/claude".to_string()),
        );
        obj.insert(
            "codex_root".to_string(),
            serde_json::Value::String("/legacy/codex".to_string()),
        );
        store
            .write_daemon_file(DAEMON_SETTINGS_FILE, &serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let loaded = DaemonSettings::load(&store).unwrap();
        assert_eq!(
            loaded.claude_source,
            Some(SourceDeclaration::Watch {
                path: PathBuf::from("/legacy/claude")
            })
        );
        assert!(
            roots_declared(&loaded),
            "an install that already declared both roots must not be re-asked"
        );

        // And the rewrite drops the old spelling rather than carrying two.
        loaded.save(&store).unwrap();
        let raw = String::from_utf8(
            store
                .read_daemon_file(DAEMON_SETTINGS_FILE)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            !raw.contains("claude_root"),
            "legacy key must not be rewritten: {raw}"
        );
        assert!(raw.contains("claude_source"));
    }

    #[test]
    fn roots_are_declared_only_when_both_are_set() {
        let mut s = DaemonSettings::default();
        assert!(
            !roots_declared(&s),
            "a fresh settings object declares neither source"
        );

        s.claude_source = Some(SourceDeclaration::Watch {
            path: PathBuf::from("/somewhere/claude"),
        });
        assert!(
            !roots_declared(&s),
            "half a declaration is the fail-open case: an undeclared codex \
             source means the daemon watches the real ~/.codex"
        );

        s.codex_source = Some(SourceDeclaration::Off);
        assert!(
            roots_declared(&s),
            "'I don't use Codex' is an answer. Declared-off is declared -- \
             that is the entire reason it has to be representable"
        );

        s.claude_source = None;
        assert!(!roots_declared(&s), "the rule is symmetric");
    }

    #[test]
    fn settings_are_written_readable_only_by_the_owner() {
        // near_ai carries an API key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (_d, store) = temp_store();
            DaemonSettings::default().save(&store).unwrap();
            let meta = std::fs::metadata(store.daemon_path(DAEMON_SETTINGS_FILE)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    // --- Runtime-settable daily caps (issue #371) --------------------------

    #[test]
    fn a_valid_cap_change_is_accepted_persisted_and_observed_by_the_next_cap_check() {
        use crate::daemon::state::DaemonState;
        use crate::daemon::uploader::cap_check;

        let (_d, store) = temp_store();
        let mut s = DaemonSettings::default();
        assert_eq!(s.max_uploads_per_day, DEFAULT_MAX_UPLOADS_PER_DAY);
        assert_eq!(s.max_bytes_per_day, DEFAULT_MAX_BYTES_PER_DAY);

        // A state that has already exhausted the *default* budget: the
        // real-world trigger for this feature was exactly this shape --
        // approved traces waiting with nothing left in the old budget.
        let mut st = DaemonState::new();
        st.uploads_today = DEFAULT_MAX_UPLOADS_PER_DAY;
        st.bytes_today = DEFAULT_MAX_BYTES_PER_DAY;
        assert!(
            !cap_check(&st, 1, &s),
            "sanity: the default budget really is exhausted"
        );

        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({
                    "max_uploads_per_day": 200,
                    "max_bytes_per_day": 2_147_483_648u64,
                }),
            ),
            Ok(true)
        );
        assert_eq!(s.max_uploads_per_day, 200);
        assert_eq!(s.max_bytes_per_day, 2_147_483_648);

        // Persisted: a restart must not revert what was just raised.
        s.save(&store).unwrap();
        let reloaded = DaemonSettings::load(&store).unwrap();
        assert_eq!(reloaded.max_uploads_per_day, 200);
        assert_eq!(reloaded.max_bytes_per_day, 2_147_483_648);

        // Observed: the same state, held against the *reloaded* settings
        // (standing in for the live `Mutex<DaemonSettings>` a running
        // uploader reads each tick), now has room again.
        assert!(
            cap_check(&st, 1, &reloaded),
            "raising the cap must be visible to the very next cap check, \
             with no restart required"
        );
    }

    #[test]
    fn max_uploads_per_day_above_the_ceiling_is_rejected() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_uploads_per_day": MAX_UPLOADS_PER_DAY_CEILING + 1}),
            ),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(
            s.max_uploads_per_day, DEFAULT_MAX_UPLOADS_PER_DAY,
            "a rejected value changes nothing"
        );
        // The ceiling itself is accepted -- it is a ceiling, not an
        // exclusive bound.
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_uploads_per_day": MAX_UPLOADS_PER_DAY_CEILING}),
            ),
            Ok(true)
        );
        assert_eq!(s.max_uploads_per_day, MAX_UPLOADS_PER_DAY_CEILING);
    }

    #[test]
    fn max_bytes_per_day_above_the_ceiling_is_rejected() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_bytes_per_day": MAX_BYTES_PER_DAY_CEILING + 1}),
            ),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(s.max_bytes_per_day, DEFAULT_MAX_BYTES_PER_DAY);
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_bytes_per_day": MAX_BYTES_PER_DAY_CEILING}),
            ),
            Ok(true)
        );
        assert_eq!(s.max_bytes_per_day, MAX_BYTES_PER_DAY_CEILING);
    }

    #[test]
    fn a_daily_cap_of_zero_is_rejected_not_treated_as_pause() {
        // Zero would silently overlap with `pause`, which is a different,
        // visibly-temporary state. It is refused like any other
        // out-of-range value.
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"max_uploads_per_day": 0})),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"max_bytes_per_day": 0})),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
    }

    #[test]
    fn a_cap_below_the_default_is_allowed_as_self_throttling() {
        // A contributor throttling their own uploads is legitimate and is
        // not the safety concern the ceiling exists for.
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_uploads_per_day": 1, "max_bytes_per_day": 1}),
            ),
            Ok(true)
        );
        assert_eq!(s.max_uploads_per_day, 1);
        assert_eq!(s.max_bytes_per_day, 1);
    }

    #[test]
    fn an_unknown_key_alongside_a_valid_cap_is_still_rejected_outright() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(
                &mut s,
                &serde_json::json!({"max_uploads_per_day": 100, "nonsense": 1}),
            ),
            Err(ERR_SETTINGS_UNKNOWN_FIELD)
        );
    }

    #[test]
    fn wrong_type_for_a_cap_is_rejected_and_changes_nothing() {
        let mut s = DaemonSettings::default();
        assert_eq!(
            apply_settings_object(&mut s, &serde_json::json!({"max_bytes_per_day": "lots"})),
            Err(ERR_SETTINGS_INVALID_VALUE)
        );
        assert_eq!(s.max_bytes_per_day, DEFAULT_MAX_BYTES_PER_DAY);
    }

    /// Every key `apply_settings_object` accepts is documented, in both
    /// places the IPC doc lists them.
    ///
    /// This drift was real: the doc named eight keys while the match accepted
    /// twelve, so `claude_source`, `codex_source`, `gemini_source` and
    /// `ironwire` were settable and undocumented. A shell author reading the
    /// `set_settings` section rather than the changelog would have concluded
    /// `ironwire` could not be set at all.
    ///
    /// The key list is read from the source between the
    /// `SET-SETTINGS-KEYS-BEGIN` / `-END` markers rather than restated here,
    /// because a list restated in a test is a third place to drift.
    #[test]
    fn the_ipc_doc_lists_every_key_this_match_accepts() {
        let source = include_str!("settings.rs");
        let region = source
            .split_once("SET-SETTINGS-KEYS-BEGIN")
            .expect("begin marker present")
            .1
            .split_once("SET-SETTINGS-KEYS-END")
            .expect("end marker present")
            .0;

        let keys: Vec<&str> = region
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix('"')?;
                let (key, tail) = rest.split_once('"')?;
                tail.trim_start().starts_with("=>").then_some(key)
            })
            .collect();

        assert!(
            keys.len() >= 12,
            "the marked region yielded {} keys, so the sweep is covering \
             almost nothing -- did the match move out from between the \
             markers? {keys:?}",
            keys.len()
        );

        let doc = include_str!("../../../../docs/contributor-daemon-ipc-v1_1.md");
        let (table, body) = doc
            .split_once("### `set_settings`")
            .expect("the doc has a set_settings section");

        for key in &keys {
            let quoted = format!("`{key}`");
            assert!(
                table.contains(&quoted),
                "`{key}` is accepted by set_settings but missing from the \
                 method table in docs/contributor-daemon-ipc-v1_1.md"
            );
            assert!(
                body.contains(&quoted),
                "`{key}` is accepted by set_settings but missing from the \
                 `set_settings` section of docs/contributor-daemon-ipc-v1_1.md"
            );
        }
    }
}
