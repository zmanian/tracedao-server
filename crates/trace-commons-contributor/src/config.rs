//! Local contributor state: config file, device keystore path, receipts log.
//!
//! All files live under a single per-user directory (`ConfigStore::dir`).
//! Writes are atomic (temp file + rename) and permission-restricted on unix
//! (dir 0700, files 0600). Receipts are hash-only: never paths or content.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use trace_commons_attestation::measurements::{ExpectedMeasurements, ExpectedMeasurementsError};
use trace_commons_operator_client::host_allowlist::HostAllowlist;
use uuid::Uuid;

use crate::witness::WitnessTrust;

pub const CONTRIBUTOR_CONFIG_SCHEMA_VERSION: &str = "trace_commons.contributor_config.v1";

const CONFIG_FILE: &str = "contributor.json";
const DEVICE_KEY_FILE: &str = "device.pk8";
const RECEIPTS_FILE: &str = "receipts.jsonl";
const NEAR_AI_NOTICE_MARKER_FILE: &str = "near-ai-notice-shown";

/// Background-daemon state files. All live in the same 0700 directory as the
/// device key and are removed by `wipe()`, so a logout cannot leave one
/// contributor's auto-upload opt-ins in place for whoever enrolls next.
pub const DAEMON_SETTINGS_FILE: &str = "daemon-settings.json";
pub const DAEMON_STATE_FILE: &str = "daemon-state.json";
pub const DAEMON_PROJECTS_FILE: &str = "daemon-projects.json";
pub const DAEMON_QUEUE_FILE: &str = "daemon-queue.jsonl";
pub const DAEMON_HISTORY_FILE: &str = "daemon-history.jsonl";
/// Local, label-only record of consequential autonomy changes (arming
/// auto-upload, bulk-approving). This is user-facing visibility, not a
/// security control -- see `daemon::audit`.
pub const DAEMON_AUDIT_FILE: &str = "daemon-audit.jsonl";
/// The account session token from the loopback browser sign-in
/// (`crate::account_auth`). A SECRET, written at 0600 inside the 0700 state
/// directory exactly like the device key, and swept by `wipe()` -- a logout
/// that left an account token behind would hand the next person to enroll on
/// this machine the ability to read and withdraw the previous contributor's
/// traces.
pub const ACCOUNT_SESSION_FILE: &str = "account-session.json";
/// Name prefix of the per-entry redacted envelope files
/// (`daemon::approved_envelope`). One file per previewed-and-approved queue
/// entry, so they cannot be listed by name; `wipe()` sweeps them by prefix.
pub const DAEMON_APPROVED_ENVELOPE_PREFIX: &str = "daemon-approved-envelope-";
/// Runtime files, not persistent state: removed on shutdown, not by `wipe()`.
pub const DAEMON_SOCK_FILE: &str = "daemon.sock";
pub const DAEMON_LOCK_FILE: &str = "daemon.lock";

/// Per-user contributor CLI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorConfig {
    pub schema_version: String,
    pub issuer_url: String,
    pub ingest_url: String,
    pub audience: String,
    pub tenant_id: String,
    pub instance_id: String,
    pub user_subject: String,
    pub device_key_id: String,
    pub consent_scopes: Vec<String>,
    pub pii_filter: Option<String>,
    pub allowed_hosts: Option<String>,
    /// The public handle this device last claimed on the community roster,
    /// with the bio and roster date the server reported alongside it.
    ///
    /// This is a local cache of server-owned state, not the authority: the
    /// server derives the principal from the authenticated request, and
    /// there is no `GET /v1/community/profile` for a contributor to read
    /// their own row back. Without the cache a shell could not render the
    /// profile panel it just wrote, so the three fields are written on a
    /// successful `set_profile` and cleared on a successful `clear_profile`.
    ///
    /// Not a secret -- the whole point of a roster handle is that it is
    /// public -- but identity, so it lives with the enrollment it belongs to
    /// and is swept by `wipe()` on logout rather than left for whoever
    /// enrolls on this machine next.
    ///
    /// `#[serde(default)]` on all three is belt-and-braces, and the reason is
    /// worth stating so nobody "fixes" the two `Option` fields above to match.
    /// serde already treats a missing `Option` field as `None` without the
    /// attribute -- verified, not assumed -- so `pii_filter` and
    /// `allowed_hosts` are correct as they stand and a `contributor.json`
    /// written before any of these fields existed loads either way. The
    /// attribute is kept here because it states the intent at the field, and
    /// because the guarantee it makes explicit is the one that matters: this
    /// struct is read from a file the previous release wrote.
    ///
    /// It would NOT be optional on a non-`Option` field. `daemon-queue.jsonl`
    /// is the cautionary case -- unversioned, parsed line by line, and lines
    /// that fail are dropped with a warning rather than surfaced, so a
    /// non-defaulted addition there would silently empty a contributor's
    /// pending queue.
    #[serde(default)]
    pub display_handle: Option<String>,
    #[serde(default)]
    pub public_bio: Option<String>,
    #[serde(default)]
    pub public_since: Option<DateTime<Utc>>,
    /// The redaction witness, when one is configured.
    ///
    /// **Absent means the witness path does not execute at all** -- not "runs
    /// and falls back". `redact_to_envelope` runs locally, byte for byte, as
    /// it does today. There is no discovery, no server-pushed enablement, and
    /// no default that could move under a contributor.
    ///
    /// `#[serde(default)]` is required here rather than decorative: this
    /// struct is read from a file the previous release wrote, and that file
    /// has no `witness` key.
    #[serde(default)]
    pub witness: Option<WitnessSettings>,
    /// Base URL of the inference provider's receipt endpoint, e.g.
    /// `https://qwen3-6-27b.completions.near.ai/v1`.
    ///
    /// Absent -- the default, and every deployment today -- means no receipt
    /// is ever fetched and every submission is honestly unattested. It is a
    /// separate switch from the witness and from the body store, because
    /// fetching a receipt tells the provider that this exchange is being
    /// contributed (see `crate::routing::receipt`), and that is a disclosure
    /// a contributor opts into rather than inherits.
    ///
    /// A base URL rather than something derived from a routing row: the proxy
    /// records no upstream URL, so a derived base would be invented.
    ///
    /// `#[serde(default)]` is required rather than decorative: this struct is
    /// read from files written by releases that had no such key.
    #[serde(default)]
    pub inference_receipt_endpoint: Option<String>,
    /// Also fetch a nonced attestation report and refuse a receipt whose
    /// signer is not the gateway key bound in it. Off by default: it costs a
    /// second network call per submission, and it reads the report's
    /// self-description without verifying the quote -- so what it adds is
    /// consistency with NEAR AI's claim, not proof of it. Named so an
    /// operator turning it on reads that limit first.
    ///
    /// A receipt that fails this check is omitted, and the submission
    /// proceeds unattested with a fixed-label debug line; it is not refused.
    /// The witness's own `required` mode is where a refusal belongs.
    #[serde(default)]
    pub inference_receipt_check_attestation: bool,
}

/// Where the redaction witness is, and what this client will accept from it.
///
/// A configured witness with no pinned measurement **refuses submissions**. It
/// does not fall back to local redaction: the contributor's bytes would stay
/// home, but the envelope would carry a self-reported risk while the
/// contributor believed it carried a certificate, and the operator would see
/// an uncertified submission from someone enrolled as certified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessSettings {
    /// Enable account-bound admission for final calls carrying its request marker.
    /// Existing unbound history still uses signed ordinary review and the server's
    /// bounded window. Legacy invited devices stay false.
    #[serde(default)]
    pub admission_evidence: bool,
    /// Base URL of the witness, e.g. `https://witness.example`.
    pub url: String,
    /// The address whose signature this client accepts on a certificate, and
    /// which the quote's report data must name.
    pub signing_address: String,
    /// Every admitted measurement set, each a comma-separated `key=value`
    /// list in `ExpectedMeasurements`' own spelling.
    ///
    /// A **list**, because dstack derives the signing key from a stable app
    /// id: an image upgrade moves the measurement and leaves the address, so
    /// a pin holding one value would break every client on every upgrade. The
    /// new measurement is added here before the fleet rolls.
    ///
    /// Empty means nothing is pinned, which is a refusal and never a pass.
    #[serde(default)]
    pub expected_measurements: Vec<String>,
}

impl WitnessSettings {
    /// Parse the pinned measurement sets into a [`WitnessTrust`].
    ///
    /// A malformed entry is an error rather than a skipped line: a silently
    /// dropped pin would leave a contributor believing they had pinned
    /// something when nothing was checked.
    pub fn trust(&self) -> Result<WitnessTrust, ExpectedMeasurementsError> {
        let mut measurements = Vec::new();
        for entry in &self.expected_measurements {
            if let Some(parsed) = ExpectedMeasurements::from_env_value(Some(entry))? {
                measurements.push(parsed);
            }
        }
        Ok(WitnessTrust {
            signing_address: self.signing_address.clone(),
            measurements,
        })
    }
}

/// `TRACE_COMMONS_WITNESS_URL`.
pub const TRACE_COMMONS_WITNESS_URL: &str = "TRACE_COMMONS_WITNESS_URL";
/// `TRACE_COMMONS_WITNESS_SIGNING_ADDRESS`.
pub const TRACE_COMMONS_WITNESS_SIGNING_ADDRESS: &str = "TRACE_COMMONS_WITNESS_SIGNING_ADDRESS";
/// `TRACE_COMMONS_WITNESS_EXPECTED_MEASUREMENTS`. Sets are separated by `;`,
/// keys within a set by `,` -- because `ExpectedMeasurements` already uses the
/// comma.
pub const TRACE_COMMONS_WITNESS_EXPECTED_MEASUREMENTS: &str =
    "TRACE_COMMONS_WITNESS_EXPECTED_MEASUREMENTS";

/// Read witness settings from the environment, for a client that has not
/// written them into its config file.
///
/// All three must be present together. A URL with no address or no
/// measurements is a **refusal to configure**, not a partially configured
/// witness: the failure mode of the latter is a client that believes it is
/// pinned and is not.
pub fn witness_settings_from_env() -> Option<WitnessSettings> {
    let url = std::env::var(TRACE_COMMONS_WITNESS_URL).ok()?;
    let signing_address = std::env::var(TRACE_COMMONS_WITNESS_SIGNING_ADDRESS).ok()?;
    let expected = std::env::var(TRACE_COMMONS_WITNESS_EXPECTED_MEASUREMENTS).ok()?;
    Some(WitnessSettings {
        admission_evidence: false,
        url,
        signing_address,
        expected_measurements: expected
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

/// `TRACE_COMMONS_INFERENCE_RECEIPT_ENDPOINT`.
pub const TRACE_COMMONS_INFERENCE_RECEIPT_ENDPOINT: &str =
    "TRACE_COMMONS_INFERENCE_RECEIPT_ENDPOINT";

/// Read the receipt endpoint from the environment.
///
/// Absent, or set to nothing but whitespace, is "no endpoint" -- not an
/// endpoint that fails later. An empty string reaching `receipt_url` would be
/// refused there too, but as a malformed URL rather than as the "not
/// configured" it actually is.
pub fn inference_receipt_endpoint_from_env() -> Option<String> {
    std::env::var(TRACE_COMMONS_INFERENCE_RECEIPT_ENDPOINT)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The receipt endpoint this config should start using, or `None` to leave it
/// alone.
///
/// A contributor has no basis to type this URL. It names the provider that
/// served their inference and answers `/signature/{chat_id}` for it, which is
/// an operator's fact about a deployment rather than a preference of theirs --
/// so it arrives the way the witness settings already arrive, published by the
/// commons and adopted here.
///
/// The order is deliberate:
///
/// - **A saved endpoint wins over everything.** Adoption fills a hole; it
///   never overwrites an answer somebody already gave.
/// - **The environment outranks the published value.** An operator who set the
///   variable on this host is making a decision about this machine, and a
///   server must not be able to take it back.
///
/// An invalid environment value yields `None` rather than falling through to
/// the published one: a typo in an operator's own variable must not quietly
/// hand the choice back to the server.
///
/// # Each source is gated by its own list
///
/// The two allowlists are separate parameters because **the source of a value
/// decides what may vet it**, and collapsing them is how a check becomes
/// decorative.
///
/// `operator_allowlist` is the environment allowlist. It is the right gate for
/// `from_env` and only for it: that value came from an operator, so checking
/// it at the operator's trust level is checking it against its own author.
///
/// `published_allowlist` gates `published`, and must be a list derived from
/// the origin the person chose -- the same basis on which that origin's issuer
/// and witness are admitted. Passing the environment allowlist here would be a
/// hole rather than a shortcut: it is permissive whenever nobody set
/// `TRACE_COMMONS_ALLOWED_HOSTS`, which is every shipped app, and a permissive
/// list would admit whatever host a capabilities response named.
///
/// Neither branch degrades to permissive. `validate_inference_receipt_endpoint`
/// refuses a non-enforcing list outright, so an unvetted value is dropped and
/// the caller refuses, rather than being adopted unchecked.
pub(crate) fn receipt_endpoint_to_adopt(
    configured: Option<&str>,
    from_env: Option<&str>,
    operator_allowlist: &HostAllowlist,
    published: Option<&str>,
    published_allowlist: &HostAllowlist,
) -> Option<String> {
    if configured.is_some() {
        return None;
    }
    let (candidate, allowlist) = match from_env {
        Some(value) => (value, operator_allowlist),
        None => (published?, published_allowlist),
    };
    let candidate = candidate.trim();
    validate_inference_receipt_endpoint(candidate, allowlist).ok()?;
    Some(candidate.to_string())
}

/// Validate an explicitly configured receipt service before trust-bootstrap
/// persistence or admission preparation. No backend-derived URL is accepted.
pub(crate) fn validate_inference_receipt_endpoint(
    endpoint: &str,
    allowlist: &HostAllowlist,
) -> Result<()> {
    let denied = || anyhow::anyhow!("inference_receipt_endpoint_invalid");
    let url = reqwest::Url::parse(endpoint).map_err(|_| denied())?;
    if !allowlist.is_enforcing()
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(denied());
    }
    allowlist.check(&url).map_err(|_| denied())
}

/// `TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION`.
pub const TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION: &str =
    "TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION";

/// Read the attestation-check switch from the environment, for a client
/// that has not written it into its config file. Only the literal `true`
/// (after trimming, case-insensitive) turns it on; anything else, including
/// absence, is off. A switch that sends a second request naming the model
/// and a nonce must not turn itself on by a typo.
pub fn inference_receipt_check_attestation_from_env() -> bool {
    std::env::var(TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION)
        .ok()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Build the allowlist to enforce for issuer/ingest requests: the `allowed_hosts`
/// CSV when set (config's `allowed_hosts` field, or a pre-enrollment CLI
/// flag), otherwise the `TRACE_COMMONS_ALLOWED_HOSTS` env fallback. Shared by
/// every call site that builds an operator-client (`login`, issuer minting,
/// and ingest uploads/status) so none of them can drift into skipping env
/// enforcement.
pub fn allowlist_for(allowed_hosts: Option<&str>) -> HostAllowlist {
    match allowed_hosts {
        Some(csv) => HostAllowlist::from_csv(csv),
        None => HostAllowlist::from_env(),
    }
}

/// Shape check for a wallet tenant id: the `near-` namespace plus 64 lowercase
/// hex characters.
///
/// This used to be `tenant_id == format!("near-{}", &anchor_hash[7..])`, and it
/// stopped being true when the server salted the anchor. The tenant id is now
/// drawn from the OS RNG and is a function of nothing -- that is the point of
/// the change, since the old binding let anyone who knew a NEAR account name
/// compute its tenant id offline. The client cannot re-derive it, so shape is
/// all there is to check here; the value is authenticated by the session token
/// issued alongside it, not by its own contents.
///
/// Lives here, rather than beside either caller, because a second copy of a
/// namespace rule is how the two callers come to disagree about what a wallet
/// tenant is.
#[must_use]
pub fn is_near_tenant_id(tenant_id: &str) -> bool {
    tenant_id.strip_prefix("near-").is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// The allowlist to enforce for calls to hosts an enrolled config already
/// names: ingest, issuer, witness, and the inference receipt endpoint.
///
/// [`allowlist_for`] returns a PERMISSIVE list when neither `allowed_hosts`
/// nor `TRACE_COMMONS_ALLOWED_HOSTS` is set, and the paths that matter refuse
/// on a non-enforcing list -- `admission_setup`'s endpoint gate and
/// [`validate_inference_receipt_endpoint`] both do. No shipped application
/// sets either, and wallet signup deliberately persists `allowed_hosts: None`,
/// so a wallet-enrolled contributor could not prepare a bound session at all.
///
/// The fix is not a stored list. A stored list has to be maintained, and it
/// drifts from the config the moment a host enters the config by another
/// route -- a witness configured in Settings, a receipt endpoint set after
/// enrollment. Instead the list is a FUNCTION of the config:
///
/// 1. `cfg.allowed_hosts` when it names anything -- operator or CLI, wins.
/// 2. Otherwise `TRACE_COMMONS_ALLOWED_HOSTS` when set -- operator, wins.
/// 3. Otherwise exactly the hosts this config already points at.
///
/// # Optional fields
///
/// `witness` and `inference_receipt_endpoint` are `Option`, and a field that
/// is unset is **skipped**: it contributes no host and is not an error. A
/// contributor with no witness configured has no witness to dial, so a shorter
/// list is the correct list. The two things deliberately NOT done here are
/// returning a non-enforcing list (which would make an unset optional field
/// silently authorize every host) and refusing outright (which would break
/// paths that work today because an optional field is unset). An unparseable
/// or host-less value is skipped for the same reason -- it names no host to
/// authorize -- and the endpoint gates that follow still refuse it on shape.
///
/// So it cannot drift: a host is on the list precisely because the config
/// names it, and a host the config does not name was never going to be
/// dialled. It widens only when the config widens, never because a server
/// said so. And it never degrades to permissive -- [`HostAllowlist::from_hosts`]
/// treats an empty set as "nothing", not "everything", so a config with no
/// parseable host refuses everything rather than allowing everything.
///
/// Deliberately NOT a change to [`allowlist_for`], which keeps its current
/// meaning for `--attest-post`. That flag refuses outright when no allowlist
/// is configured, because its target comes from the command line rather than
/// from enrollment; a config-derived fallback there would make `is_enforcing`
/// true and silently permit a collector that happened to equal the ingest
/// host.
#[must_use]
pub fn config_allowlist(cfg: &ContributorConfig) -> HostAllowlist {
    derive_config_allowlist(&allowlist_for(cfg.allowed_hosts.as_deref()), cfg)
}

pub(crate) fn derive_config_allowlist(
    configured: &HostAllowlist,
    cfg: &ContributorConfig,
) -> HostAllowlist {
    if configured.is_enforcing() {
        return configured.clone();
    }
    let named = [
        Some(cfg.issuer_url.as_str()),
        Some(cfg.ingest_url.as_str()),
        cfg.witness.as_ref().map(|witness| witness.url.as_str()),
        cfg.inference_receipt_endpoint.as_deref(),
    ];
    HostAllowlist::from_hosts(named.into_iter().flatten().filter_map(|url| {
        reqwest::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_string))
    }))
}

/// A hash-only record of a submitted trace. Never contains paths or content./// A hash-only record of a submitted trace. Never contains paths or content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub submission_id: Uuid,
    pub session_hash: String,
    pub source: String,
    pub submitted_at: DateTime<Utc>,
    pub status: String,
}

/// The state directory's name under whichever per-user base the platform uses.
const STATE_DIR_NAME: &str = "trace-commons";

/// The default state directory for this platform.
///
/// Everywhere except Windows this is `dirs::config_dir()/trace-commons`:
/// `~/.config/trace-commons` on Linux, `~/Library/Application
/// Support/trace-commons` on macOS, matching what the native shells use.
///
/// Windows deliberately does *not* use `dirs::config_dir()`, which there is
/// roaming AppData. Two reasons, and either alone is enough:
///
/// - Roaming profiles copy that directory between machines. It holds a
///   device-bound Ed25519 key, a queue of local work, and a lock file. The
///   server treats one device key as one device, so roaming it puts a single
///   enrolled identity on several machines at once.
/// - The native Windows application has always hosted its daemon out of
///   LocalAppData (`DaemonHost.DefaultConfigDir`). While the CLI used roaming,
///   the two disagreed about where "this machine's enrollment" lives: enrolling
///   in one left the other reporting no enrollment at all, on the same account,
///   on the same machine.
///
/// So on Windows the preferred directory is LocalAppData, and an enrollment
/// left behind in the roaming location is migrated on the next run. See
/// [`adopt_state_dir`].
fn platform_default_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let preferred = dirs::config_local_dir()
            .context("could not determine a local config directory for this platform")?
            .join(STATE_DIR_NAME);
        let legacy = dirs::config_dir()
            .context("could not determine a config directory for this platform")?
            .join(STATE_DIR_NAME);
        Ok(adopt_state_dir(&preferred, &legacy))
    }
    #[cfg(not(windows))]
    {
        Ok(dirs::config_dir()
            .context("could not determine a config directory for this platform")?
            .join(STATE_DIR_NAME))
    }
}

/// Pick between the preferred state directory and a legacy one, migrating an
/// enrollment out of the legacy location when it is safe to do so.
///
/// "Enrolled" means the directory holds a `contributor.json`; a bare directory
/// counts for nothing, since both the CLI and the app create theirs on first
/// run whether or not anyone has logged in.
///
/// The migration is a single directory rename, so it either happens entirely
/// or not at all. It is skipped when the preferred directory already holds
/// state of its own, because merging two state directories is not atomic and a
/// half-merged one -- a config from here, a device key from there -- is worse
/// than one that simply has not moved yet. In that case the enrolled legacy
/// directory keeps being used and the caller is none the wiser.
#[cfg(any(windows, test))]
fn adopt_state_dir(preferred: &Path, legacy: &Path) -> PathBuf {
    if preferred.join(CONFIG_FILE).exists() || !legacy.join(CONFIG_FILE).exists() {
        return preferred.to_path_buf();
    }
    // An empty preferred directory is the ordinary case (the app makes one on
    // first run), and it is the only thing allowed to be in the way. Removing
    // it fails harmlessly if it holds anything at all.
    let _ = std::fs::remove_dir(preferred);
    if let Some(parent) = preferred.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::rename(legacy, preferred) {
        Ok(()) => preferred.to_path_buf(),
        Err(_) => legacy.to_path_buf(),
    }
}

/// Filesystem-backed store for contributor config, device key, and receipts.
#[derive(Clone)]
pub struct ConfigStore {
    dir: PathBuf,
}

impl ConfigStore {
    /// Resolve the contributor state directory using precedence:
    /// 1. `explicit` flag
    /// 2. `TRACE_COMMONS_CONTRIBUTOR_DIR` env var
    /// 3. the platform default, see [`platform_default_dir`]
    ///
    /// Creates the directory (mode 0700 on unix) if it does not exist.
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self> {
        let dir = if let Some(dir) = explicit {
            dir
        } else if let Ok(dir) = std::env::var("TRACE_COMMONS_CONTRIBUTOR_DIR") {
            PathBuf::from(dir)
        } else {
            platform_default_dir()?
        };
        Self::open(dir)
    }

    /// Open (creating if necessary) the given directory as a contributor
    /// state store. Does not consult the environment.
    pub fn open(dir: PathBuf) -> Result<Self> {
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating contributor state dir {}", dir.display()))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting permissions on {}", dir.display()))?;
        }
        Ok(Self { dir })
    }

    /// The directory backing this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    pub fn load_config(&self) -> Result<Option<ContributorConfig>> {
        let path = self.config_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(cfg))
    }

    pub fn save_config(&self, cfg: &ContributorConfig) -> Result<()> {
        let body = serde_json::to_vec_pretty(cfg).context("serializing contributor config")?;
        crate::daemon::commons_credentials::save_config(self, cfg, &body)
    }

    /// Path to the device key file. Does not imply the file exists.
    pub fn device_key_path(&self) -> PathBuf {
        self.dir.join(DEVICE_KEY_FILE)
    }

    pub fn save_device_key(&self, pkcs8_der: &[u8]) -> Result<()> {
        use crate::daemon::commons_credentials::{self, Kind};
        let expected = commons_credentials::snapshot(self, Kind::Device)?;
        if self.device_key_path().exists() {
            anyhow::bail!("commons_device_identity_exists");
        }
        commons_credentials::replace(self, &expected, pkcs8_der, None)
    }

    pub fn load_device_key(&self) -> Result<Option<Vec<u8>>> {
        crate::daemon::commons_credentials::load(
            self,
            crate::daemon::commons_credentials::Kind::Device,
        )
    }

    fn receipts_path(&self) -> PathBuf {
        self.dir.join(RECEIPTS_FILE)
    }

    pub fn append_receipt(&self, r: &Receipt) -> Result<()> {
        let path = self.receipts_path();
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        if !existed {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("setting permissions on {}", path.display()))?;
            }
        }
        let mut line = serde_json::to_string(r).context("serializing receipt")?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn load_receipts(&self) -> Result<Vec<Receipt>> {
        let path = self.receipts_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut receipts = Vec::new();
        let mut skipped = 0usize;
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Receipt>(line) {
                Ok(r) => receipts.push(r),
                Err(_) => skipped += 1,
            }
        }
        if skipped > 0 {
            tracing::warn!(skipped, "skipped unparseable receipt lines");
        }
        Ok(receipts)
    }

    /// Path to a daemon state file inside this store. Daemon state lives in
    /// the same 0700 directory as the device key, so the directory
    /// permissions are the single enforcing control for all of it.
    pub fn daemon_path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Atomically write a daemon state file at 0600.
    pub fn write_daemon_file(&self, name: &str, body: &[u8]) -> Result<()> {
        if name == ACCOUNT_SESSION_FILE {
            use crate::daemon::commons_credentials::{self, Kind};
            let expected = commons_credentials::snapshot(self, Kind::Account)?;
            return commons_credentials::replace(self, &expected, body, None);
        }
        let path = self.daemon_path(name);
        write_atomic_0600(&self.dir, &path, body)
    }

    /// Read a daemon state file, or `None` when it does not exist yet.
    pub fn read_daemon_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if name == ACCOUNT_SESSION_FILE {
            return crate::daemon::commons_credentials::load(
                self,
                crate::daemon::commons_credentials::Kind::Account,
            );
        }
        let path = self.daemon_path(name);
        match std::fs::read(&path) {
            Ok(body) => Ok(Some(body)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Remove a daemon runtime file (socket, lock). Missing is not an error.
    pub fn remove_daemon_file(&self, name: &str) -> Result<()> {
        if name == ACCOUNT_SESSION_FILE {
            return crate::daemon::commons_credentials::clear(
                self,
                &[crate::daemon::commons_credentials::Kind::Account],
            );
        }
        let path = self.daemon_path(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    fn near_ai_notice_marker_path(&self) -> PathBuf {
        self.dir.join(NEAR_AI_NOTICE_MARKER_FILE)
    }

    /// Whether the first-use NEAR AI privacy-filter notice has already been
    /// recorded. This read-only check lets the renderer show the disclosure
    /// before message text leaves the machine without consuming it until the
    /// filter has actually succeeded.
    pub fn near_ai_notice_shown(&self) -> bool {
        self.near_ai_notice_marker_path().exists()
    }

    /// Record that the one-time first-use NEAR AI privacy-filter notice was
    /// shown and the filter then succeeded. Returns `true` when this call
    /// creates the marker and `false` when it was already present.
    pub fn ensure_near_ai_notice_shown(&self) -> Result<bool> {
        let path = self.near_ai_notice_marker_path();
        if path.exists() {
            return Ok(false);
        }
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(true)
    }

    /// Remove all local contributor state (logout).
    ///
    /// Also sweeps orphaned atomic-write temp files (`.{name}.tmp-{uuid}`)
    /// that can be left behind if the process crashes between creating the
    /// temp file and renaming it into place in `write_atomic_0600`.
    pub fn wipe(&self) -> Result<()> {
        use crate::daemon::commons_credentials::{self, Kind};
        commons_credentials::clear_with(self, &[Kind::Device, Kind::Account], || {
            self.wipe_files()
        })?;
        // The local state is gone even if the native service is locked. Keep
        // its cleanup journal for retry rather than restoring either secret.
        let _ = commons_credentials::cleanup(self);
        Ok(())
    }

    fn wipe_files(&self) -> Result<()> {
        // Token review payloads belong to this enrollment. Never traverse a
        // substituted link into an agent's session directory. Remaining raw
        // capture leases expire independently in Ironwire's bounded spool.
        let bundles = self.dir.join("token-bundles");
        match std::fs::symlink_metadata(&bundles) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                std::fs::remove_dir_all(&bundles).context("removing token review journal")?
            }
            Ok(_) => std::fs::remove_file(&bundles).context("removing token review link")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("reading token review journal"),
        }
        for name in [
            CONFIG_FILE,
            DEVICE_KEY_FILE,
            RECEIPTS_FILE,
            NEAR_AI_NOTICE_MARKER_FILE,
            DAEMON_SETTINGS_FILE,
            DAEMON_STATE_FILE,
            DAEMON_PROJECTS_FILE,
            DAEMON_QUEUE_FILE,
            DAEMON_HISTORY_FILE,
            DAEMON_AUDIT_FILE,
            ACCOUNT_SESSION_FILE,
        ] {
            let path = self.dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
            }
        }

        let tmp_prefixes: Vec<String> = [
            CONFIG_FILE,
            DEVICE_KEY_FILE,
            RECEIPTS_FILE,
            DAEMON_SETTINGS_FILE,
            DAEMON_STATE_FILE,
            DAEMON_PROJECTS_FILE,
            DAEMON_QUEUE_FILE,
            DAEMON_HISTORY_FILE,
            DAEMON_AUDIT_FILE,
            ACCOUNT_SESSION_FILE,
        ]
        .into_iter()
        .map(|name| format!(".{name}.tmp-"))
        .collect();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| format!("reading dir {}", self.dir.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading dir {}", self.dir.display()))?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            // Stored approved envelopes are one file per queue entry, so they
            // cannot be named in the fixed list above. They are redacted trace
            // content at rest and must not outlive the enrollment that
            // produced them -- see `daemon::approved_envelope`. Their temp
            // files share the same prefix and are swept by the same test.
            let is_approved_envelope = file_name.starts_with(DAEMON_APPROVED_ENVELOPE_PREFIX)
                || file_name.starts_with(&format!(".{DAEMON_APPROVED_ENVELOPE_PREFIX}"));
            if is_approved_envelope
                || tmp_prefixes
                    .iter()
                    .any(|prefix| file_name.starts_with(prefix))
            {
                let path = entry.path();
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing orphaned temp file {}", path.display()))?;
            }
        }
        Ok(())
    }
}

/// Test-only helpers shared with the daemon modules, which all need a
/// throwaway store rooted in a tempdir.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::ConfigStore;
    use sha2::Digest as _;

    pub(crate) fn temp_store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::open(dir.path().to_path_buf()).unwrap();
        crate::daemon::cloud_credential_test_support::install(&store);
        (dir, store)
    }

    /// A wallet account in the shape V61 leaves behind: a tenant id and an
    /// account anchor with no arithmetic relationship to each other.
    ///
    /// Returns `(tenant_id, anchor)`, where `anchor` is the 64 hex characters
    /// an admission binding carries -- the stored `anchor_hash` without its
    /// `sha256:` prefix.
    ///
    /// # Why this exists, and why writing the literal instead is a bug
    ///
    /// Four fixtures in this workspace built `format!("near-{}", anchor)`:
    /// `daemon::approved_envelope`, `witness::transport`,
    /// `daemon::admission_setup`, and `daemon::account_onboarding`. That is the
    /// shape V58's `CHECK (tenant_id = 'near-' || substring(anchor_hash from
    /// 8))` produced; V61 made the anchor a keyed blind index and the tenant id
    /// 32 random bytes, and V62 dropped the constraint. Since then the two are
    /// equal for no real account.
    ///
    /// A fixture in the old shape is not merely unrealistic -- it is the only
    /// world in which the retired coupling holds, so a test written against it
    /// **cannot fail** when production code still assumes that coupling. That
    /// is not hypothetical: `verify_admission_context` read a tenant id as an
    /// account anchor on the live upload path and refused every
    /// admission-bearing submission, while
    /// `signed_admission_must_match_our_account_challenge_and_exact_receipt` --
    /// a test named for exactly that property, with a ten-field mutation matrix
    /// over the evidence -- passed throughout, because its fixture supplied the
    /// coupled pair. Correcting the fixture was the whole of what made it fail.
    ///
    /// # What the assertion below can and cannot catch
    ///
    /// Two independently drawn 32-byte values are never equal in practice, so
    /// the check never fires on the values themselves. That is not what it is
    /// for. It fires when a maintainer later edits **this function** to derive
    /// one side from the other -- `format!("near-{anchor}")` being the obvious
    /// and historically attested way to do it -- which is the mutation that
    /// would silently re-couple every caller at once.
    ///
    /// It is containment rather than equality, matching
    /// `near_account_identity::tenant_id_is_independent_of_every_public_input`
    /// on the server side, so a tenant id that merely *embeds* the anchor is
    /// caught too.
    ///
    /// It still cannot catch a derivation that transforms the anchor -- a
    /// reversed or re-encoded digest would pass. Nothing cheap can, short of
    /// the newtype in #794 that makes the coupling unrepresentable. So the
    /// doc comment above, which names the sites and the failure, is doing more
    /// of the work here than the assertion is; treat it as the primary control
    /// and the assertion as the backstop, not the other way round.
    pub(crate) fn v61_account() -> (String, String) {
        let anchor = hex::encode(<[u8; 32]>::from(sha2::Sha256::digest(
            uuid::Uuid::new_v4().as_bytes(),
        )));
        let tenant = format!(
            "near-{}",
            hex::encode(<[u8; 32]>::from(sha2::Sha256::digest(
                uuid::Uuid::new_v4().as_bytes()
            )))
        );
        assert!(
            !tenant.contains(&anchor) && !anchor.contains(tenant.trim_start_matches("near-")),
            "v61_account derived one side from the other; the whole point of \
             this constructor is that a tenant id and an account anchor share \
             no value. See #794."
        );
        (tenant, anchor)
    }

    #[cfg(test)]
    mod tests {
        /// The constructor is a control, so it gets a test that can go red in
        /// CI rather than only an assertion that fires if someone edits it.
        ///
        /// Modelled on the server's
        /// `tenant_id_is_independent_of_every_public_input`: draw repeatedly,
        /// and require that no draw repeats and that neither side ever
        /// contains the other. A `v61_account` rewritten to couple the two
        /// fails here, with a name that says what broke.
        #[test]
        fn v61_account_draws_the_two_halves_independently() {
            let mut tenants = std::collections::BTreeSet::new();
            let mut anchors = std::collections::BTreeSet::new();
            for _ in 0..64 {
                let (tenant, anchor) = super::v61_account();
                let suffix = tenant
                    .strip_prefix("near-")
                    .expect("a wallet tenant id keeps the namespace consumers match on");
                assert_eq!(suffix.len(), 64, "{tenant}");
                assert_eq!(anchor.len(), 64, "{anchor}");
                assert_ne!(suffix, anchor, "the two halves are the same value");
                assert!(
                    !tenant.contains(&anchor) && !anchor.contains(suffix),
                    "one half embeds the other"
                );
                assert!(tenants.insert(tenant), "a tenant id repeated across draws");
                assert!(anchors.insert(anchor), "an anchor repeated across draws");
            }
        }
    }
}

/// Write `body` to `path` atomically (temp file in the same dir, then
/// rename), setting 0600 permissions on unix.
pub(crate) fn write_atomic_0600(dir: &Path, path: &Path, body: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .context("destination path has no file name")?
        .to_string_lossy();
    let tmp_path = dir.join(format!(".{file_name}.tmp-{}", Uuid::new_v4()));
    {
        #[cfg(unix)]
        let mut tmp = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .with_context(|| format!("creating temp file {}", tmp_path.display()))?
        };
        #[cfg(not(unix))]
        let mut tmp = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating temp file {}", tmp_path.display()))?;
        tmp.write_all(body)
            .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
        tmp.sync_all()
            .with_context(|| format!("syncing temp file {}", tmp_path.display()))?;
    }
    if let Err(e) = durable_rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e)
            .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn durable_rename(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn durable_rename(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both paths are owned, NUL-terminated UTF-16 buffers, alive
    // throughout this synchronous call. Write-through completes publication
    // before an old OS credential may be retired.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::open(dir.path().to_path_buf()).unwrap();
        (dir, store)
    }

    /// A directory that looks enrolled: what `adopt_state_dir` keys off.
    fn enrolled_dir(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join(CONFIG_FILE), b"{}").unwrap();
    }

    #[test]
    fn state_dir_is_the_preferred_one_when_it_holds_the_enrollment() {
        let root = tempfile::tempdir().unwrap();
        let preferred = root.path().join("local");
        let legacy = root.path().join("roaming");
        enrolled_dir(&preferred);
        enrolled_dir(&legacy);

        // Both enrolled is the ambiguous case, and moving the legacy one over
        // the top would destroy an enrollment. The preferred directory wins
        // and the legacy one is left exactly where it was.
        assert_eq!(adopt_state_dir(&preferred, &legacy), preferred);
        assert!(legacy.join(CONFIG_FILE).exists());
    }

    #[test]
    fn state_dir_migrates_an_enrollment_left_in_the_legacy_location() {
        let root = tempfile::tempdir().unwrap();
        let preferred = root.path().join("local");
        let legacy = root.path().join("roaming");
        enrolled_dir(&legacy);
        std::fs::write(legacy.join(DEVICE_KEY_FILE), b"key").unwrap();

        assert_eq!(adopt_state_dir(&preferred, &legacy), preferred);
        assert!(preferred.join(CONFIG_FILE).exists());
        // The whole directory moved, not just the config: a device key left
        // behind is an enrollment that cannot upload.
        assert_eq!(
            std::fs::read(preferred.join(DEVICE_KEY_FILE)).unwrap(),
            b"key"
        );
        assert!(!legacy.exists());
    }

    #[test]
    fn state_dir_migrates_past_an_empty_preferred_directory() {
        // The app creates its state directory on first run whether or not
        // anyone has enrolled, so an empty directory in the way is the normal
        // case, not an exotic one.
        let root = tempfile::tempdir().unwrap();
        let preferred = root.path().join("local");
        let legacy = root.path().join("roaming");
        std::fs::create_dir_all(&preferred).unwrap();
        enrolled_dir(&legacy);

        assert_eq!(adopt_state_dir(&preferred, &legacy), preferred);
        assert!(preferred.join(CONFIG_FILE).exists());
        assert!(!legacy.exists());
    }

    #[test]
    fn state_dir_keeps_using_the_legacy_one_rather_than_splitting_state() {
        // Preferred holds something but no enrollment (daemon settings from
        // the app, say). Merging two directories is not atomic, and a
        // half-merged state directory is worse than an unmigrated one, so
        // this keeps using the enrolled directory where it is.
        let root = tempfile::tempdir().unwrap();
        let preferred = root.path().join("local");
        let legacy = root.path().join("roaming");
        std::fs::create_dir_all(&preferred).unwrap();
        std::fs::write(preferred.join(DAEMON_SETTINGS_FILE), b"{}").unwrap();
        enrolled_dir(&legacy);

        assert_eq!(adopt_state_dir(&preferred, &legacy), legacy);
        assert!(legacy.join(CONFIG_FILE).exists());
        assert!(preferred.join(DAEMON_SETTINGS_FILE).exists());
    }

    #[test]
    fn state_dir_is_the_preferred_one_when_nothing_is_enrolled_anywhere() {
        let root = tempfile::tempdir().unwrap();
        let preferred = root.path().join("local");
        let legacy = root.path().join("roaming");

        assert_eq!(adopt_state_dir(&preferred, &legacy), preferred);
        assert!(!legacy.exists());
    }

    fn sample_config() -> ContributorConfig {
        ContributorConfig {
            inference_receipt_endpoint: None,
            inference_receipt_check_attestation: false,
            schema_version: CONTRIBUTOR_CONFIG_SCHEMA_VERSION.to_string(),
            issuer_url: "https://issuer.example".into(),
            ingest_url: "https://ingest.example".into(),
            audience: "trace-commons-upload".into(),
            tenant_id: "tenant-abc".into(),
            instance_id: "instance-1".into(),
            user_subject: "user-1".into(),
            device_key_id: "sha256:00".into(),
            consent_scopes: vec!["debugging_evaluation".into()],
            pii_filter: None,
            allowed_hosts: None,
            display_handle: None,
            public_bio: None,
            public_since: None,
            witness: None,
        }
    }

    #[test]
    fn config_round_trip_and_permissions() {
        let (_d, store) = store();
        assert!(store.load_config().unwrap().is_none());
        store.save_config(&sample_config()).unwrap();
        let loaded = store.load_config().unwrap().unwrap();
        assert_eq!(loaded.tenant_id, "tenant-abc");
        // Unix permission bits do not exist on Windows; the file's mode is
        // only meaningful to assert on unix.
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(store_path(&store, "contributor.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A config written before this field existed reads as off. The
    /// check must never switch itself on for an existing install.
    #[test]
    fn the_attestation_check_is_off_for_a_config_that_predates_it() {
        let json = r#"{"schema_version":"1","issuer_url":"https://i","ingest_url":"https://g","audience":"a","tenant_id":"t","instance_id":"i","user_subject":"s","device_key_id":"d","consent_scopes":[]}"#;
        let cfg: ContributorConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.inference_receipt_check_attestation);
    }

    #[test]
    fn device_key_round_trip_and_permissions() {
        let (_d, store) = store();
        assert!(store.load_device_key().unwrap().is_none());
        store.save_device_key(b"fake-der-bytes").unwrap();
        assert_eq!(store.load_device_key().unwrap().unwrap(), b"fake-der-bytes");
        // Unix permission bits do not exist on Windows; the file's mode is
        // only meaningful to assert on unix.
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(store.device_key_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn receipts_append_load_and_skip_garbage() {
        let (_d, store) = store();
        let r = Receipt {
            submission_id: uuid::Uuid::new_v4(),
            session_hash: "sha256:aa".into(),
            source: "claude-code".into(),
            submitted_at: chrono::Utc::now(),
            status: "accepted".into(),
        };
        store.append_receipt(&r).unwrap();
        // Simulate a corrupt line.
        std::fs::write(
            store_path(&store, "receipts.jsonl"),
            format!("{}\nnot-json\n", serde_json::to_string(&r).unwrap()),
        )
        .unwrap();
        let loaded = store.load_receipts().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_hash, "sha256:aa");
    }

    #[test]
    fn near_ai_notice_shown_once_then_silent() {
        let (_d, store) = store();
        // Marker absent: first call reports "shown" and creates the marker.
        assert!(store.ensure_near_ai_notice_shown().unwrap());
        assert!(store_path(&store, "near-ai-notice-shown").exists());
        // Marker present: subsequent calls stay silent.
        assert!(!store.ensure_near_ai_notice_shown().unwrap());
        assert!(!store.ensure_near_ai_notice_shown().unwrap());
    }

    #[test]
    fn wipe_removes_state() {
        let (_d, store) = store();
        store.save_config(&sample_config()).unwrap();
        store.save_device_key(b"k").unwrap();
        assert!(store.ensure_near_ai_notice_shown().unwrap());
        store.wipe().unwrap();
        assert!(store.load_config().unwrap().is_none());
        assert!(store.load_device_key().unwrap().is_none());
        // Logout must also clear the first-use notice marker so a
        // re-enrolled user sees the notice again.
        assert!(store.ensure_near_ai_notice_shown().unwrap());
    }

    #[test]
    fn wipe_removes_token_reviews_and_preserves_agent_sources() {
        let (_d, store) = store();
        std::fs::create_dir_all(store.dir.join("token-bundles")).unwrap();
        std::fs::write(store.dir.join("token-bundles/review.json"), b"private").unwrap();
        std::fs::write(store.dir.join("agent-session.jsonl"), b"original").unwrap();
        store.wipe().unwrap();
        assert!(!store.dir.join("token-bundles").exists());
        assert_eq!(
            std::fs::read(store.dir.join("agent-session.jsonl")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn wipe_removes_daemon_state() {
        // Daemon state outliving a logout would hand the next person to
        // enroll on this machine the previous contributor's auto-upload
        // opt-ins and their contribution history.
        let (_d, store) = store();
        let names = [
            DAEMON_SETTINGS_FILE,
            DAEMON_STATE_FILE,
            DAEMON_PROJECTS_FILE,
            DAEMON_QUEUE_FILE,
            DAEMON_HISTORY_FILE,
            DAEMON_AUDIT_FILE,
            ACCOUNT_SESSION_FILE,
        ];
        for name in names {
            store.write_daemon_file(name, b"{}").unwrap();
        }
        store.wipe().unwrap();
        for name in names {
            assert!(
                store.read_daemon_file(name).unwrap().is_none(),
                "{name} survived logout"
            );
        }
    }

    #[test]
    fn wipe_removes_orphaned_daemon_temp_files() {
        let (_d, store) = store();
        let orphan = store.dir().join(".daemon-queue.jsonl.tmp-deadbeef");
        std::fs::write(&orphan, b"leftover").unwrap();
        store.wipe().unwrap();
        assert!(!orphan.exists());
    }

    #[test]
    fn wipe_removes_orphaned_temp_files() {
        let (_d, store) = store();
        let orphan = store.dir().join(".device.pk8.tmp-deadbeef");
        std::fs::write(&orphan, b"leftover-key-material").unwrap();
        assert!(orphan.exists());
        store.wipe().unwrap();
        assert!(!orphan.exists());
    }

    // Test helper: expose the file path for assertions.
    fn store_path(store: &ConfigStore, name: &str) -> std::path::PathBuf {
        store.dir().join(name)
    }
    #[test]
    fn native_receipt_endpoint_requires_explicit_https_allowed_host_without_credentials() {
        let allowed = HostAllowlist::from_csv("receipts.example");
        assert!(
            validate_inference_receipt_endpoint("https://receipts.example/v1", &allowed).is_ok()
        );
        for value in [
            "http://receipts.example/v1",
            "https://other.example/v1",
            "https://user:secret@receipts.example/v1",
            "https://receipts.example/v1?token=secret",
            "https://receipts.example/v1#fragment",
            "not a URL",
            "",
        ] {
            assert!(validate_inference_receipt_endpoint(value, &allowed).is_err());
        }
        assert!(
            validate_inference_receipt_endpoint(
                "https://receipts.example/v1",
                &HostAllowlist::permissive()
            )
            .is_err()
        );
    }

    /// The endpoint a contributor has no basis to type arrives from the
    /// commons, exactly as the witness already does. The environment stays
    /// ahead of it so an operator running the daemon on a host they control
    /// keeps the last word.
    #[test]
    fn an_operator_environment_endpoint_outranks_the_published_one() {
        let operator = HostAllowlist::from_csv("receipts.example");
        let derived = HostAllowlist::from_csv("published.example");
        assert_eq!(
            receipt_endpoint_to_adopt(
                None,
                Some("https://receipts.example/v1"),
                &operator,
                Some("https://published.example/v1"),
                &derived
            )
            .as_deref(),
            Some("https://receipts.example/v1")
        );
    }

    /// The whole point: a contributor who exported nothing still ends up with
    /// an endpoint.
    #[test]
    fn a_published_endpoint_is_adopted_when_the_environment_says_nothing() {
        let derived = HostAllowlist::from_csv("published.example");
        assert_eq!(
            receipt_endpoint_to_adopt(
                None,
                None,
                &HostAllowlist::permissive(),
                Some("https://published.example/v1"),
                &derived
            )
            .as_deref(),
            Some("https://published.example/v1"),
            "a published value is vetted by the list its own source derived, not by the \
             environment list that happens to be permissive on every shipped app"
        );
    }

    /// A saved endpoint is a decision already taken -- by an operator, or by
    /// an earlier signup. Adoption fills a hole; it does not overwrite an
    /// answer.
    #[test]
    fn an_endpoint_already_saved_is_never_replaced() {
        let allowed = HostAllowlist::from_csv("receipts.example,published.example");
        assert_eq!(
            receipt_endpoint_to_adopt(
                Some("https://receipts.example/v1"),
                Some("https://published.example/v1"),
                &allowed,
                Some("https://published.example/v1"),
                &allowed
            ),
            None,
            "nothing to adopt means nothing to write"
        );
    }

    /// The commons publishes this value and the commons is not trusted to
    /// pick it: a published endpoint runs the same gauntlet an operator's
    /// does, against the list its own source derived, or it is not adopted.
    #[test]
    fn a_published_endpoint_the_derived_list_refuses_is_not_adopted() {
        let derived = HostAllowlist::from_csv("published.example");
        for refused in [
            "http://published.example/v1",
            "https://elsewhere.example/v1",
            "https://user:secret@published.example/v1",
            "https://published.example/v1?token=secret",
            "https://published.example/v1#fragment",
            "not a URL",
            "",
            "   ",
        ] {
            assert_eq!(
                receipt_endpoint_to_adopt(
                    None,
                    None,
                    &HostAllowlist::permissive(),
                    Some(refused),
                    &derived
                ),
                None,
                "{refused} was adopted"
            );
        }
    }

    /// The gate that would otherwise be decorative.
    ///
    /// If a published endpoint were vetted by the environment allowlist, it
    /// would be vetted by nothing on every machine where no operator set
    /// `TRACE_COMMONS_ALLOWED_HOSTS` -- which is the default for every shipped
    /// app. A non-enforcing list must refuse, not wave through.
    #[test]
    fn a_permissive_list_admits_no_endpoint_from_either_source() {
        let permissive = HostAllowlist::permissive();
        assert_eq!(
            receipt_endpoint_to_adopt(
                None,
                None,
                &permissive,
                Some("https://whatever-the-server-said.example/v1"),
                &permissive
            ),
            None,
            "a capabilities response would otherwise name any host it liked"
        );
        assert_eq!(
            receipt_endpoint_to_adopt(
                None,
                Some("https://receipts.example/v1"),
                &permissive,
                None,
                &permissive
            ),
            None
        );
    }

    /// An operator endpoint is validated too, and is refused rather than
    /// silently falling through to the published one: a typo in an operator's
    /// own variable must not quietly hand the choice back to the server.
    #[test]
    fn a_bad_environment_endpoint_does_not_fall_through_to_the_published_one() {
        let operator = HostAllowlist::from_csv("receipts.example");
        let derived = HostAllowlist::from_csv("published.example");
        assert_eq!(
            receipt_endpoint_to_adopt(
                None,
                Some("http://typo.example/v1"),
                &operator,
                Some("https://published.example/v1"),
                &derived
            ),
            None
        );
    }

    // `inference_receipt_check_attestation_from_env` reads process-wide env;
    // serialize the mutating tests so they do not race each other.
    static ATTESTATION_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_attestation_env(value: Option<&str>) {
        // SAFETY: serialized through ATTESTATION_ENV_LOCK.
        unsafe {
            match value {
                Some(v) => std::env::set_var(TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION, v),
                None => std::env::remove_var(TRACE_COMMONS_INFERENCE_RECEIPT_CHECK_ATTESTATION),
            }
        }
    }

    #[test]
    fn attestation_check_env_only_the_literal_true_turns_it_on() {
        let _guard = ATTESTATION_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        set_attestation_env(Some("true"));
        assert!(inference_receipt_check_attestation_from_env());

        set_attestation_env(Some(" TRUE "));
        assert!(inference_receipt_check_attestation_from_env());

        set_attestation_env(Some("1"));
        assert!(!inference_receipt_check_attestation_from_env());

        set_attestation_env(Some("yes"));
        assert!(!inference_receipt_check_attestation_from_env());

        set_attestation_env(Some(""));
        assert!(!inference_receipt_check_attestation_from_env());

        set_attestation_env(None);
        assert!(!inference_receipt_check_attestation_from_env());
    }
}
