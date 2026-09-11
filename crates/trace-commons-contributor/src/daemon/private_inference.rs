//! Running IronWire inside this daemon.
//!
//! IronWire proxies inference, so it must not be started by discovery: the
//! `private_inference` setting is the contributor's declaration and it
//! defaults to off. Finding a pointer on disk is never enough.
//!
//! The home is `$IRONWIRE_HOME`, else `~/.ironwire` -- deliberately the same
//! home the `ironwire` CLI uses, so a contributor who installs it sees one
//! ledger, one token, one pointer, and the routing reader keeps talking to
//! 127.0.0.1 exactly as before.
//!
//! Nothing here logs a prompt, a completion, a token, or a body. Fixed
//! labels, a port, and counts.
//!
//! # An IronWire this daemon did not start is left alone
//!
//! A responding pointer is advisory and causes us to leave that endpoint
//! alone; it does not authenticate the service or prove home ownership.
//! A held exclusive home lock also refuses startup. These are [`PrivateInferenceState::RunningElsewhere`]: nothing is
//! bound, nothing is stopped, and the existing instance keeps serving. A
//! contributor's own proxy is not something to fight for a port.
//!
//! # A proxy that is running but cannot route is not green
//!
//! `StartupReport::no_backends` says the registry came up empty: the proxy
//! answers health and nothing will ever route through it. Reporting that as
//! `Running` would put a green light over a dead proxy, so it is its own
//! state -- [`PrivateInferenceState::RunningWithoutBackends`] -- with its own
//! label on the wire.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ironwire_proxy::embed::{
    self, CredentialFiles, EmbedError, EmbedOptions, EmbeddedProxy, ExitError, HostSecret,
    StartupProbes, UpdateChecks,
};

/// How long a liveness probe of an existing instance may take.
///
/// This runs on the daemon's poll tick, so it must be short enough that a
/// pointer naming a port nothing answers cannot stall the pass.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_POINTER_BYTES: u64 = 64 * 1024;

/// Nothing has been asked for, or the switch was turned off.
pub const LABEL_OFF: &str = "off";
/// Shutdown was requested, but owned requests or cleanup are still draining.
pub const LABEL_STOPPING: &str = "stopping";
/// This daemon owns a proxy that came up with a usable backend registry.
pub const LABEL_RUNNING: &str = "running";
/// This daemon owns a proxy whose backend registry is empty.
pub const LABEL_RUNNING_NO_BACKENDS: &str = "running_no_backends";
/// Running, and answered by credentials the contributor's tools already had.
pub const LABEL_RUNNING_ANSWERED_ELSEWHERE: &str = "running_answered_elsewhere";
/// Running, and which account answers could not be read.
pub const LABEL_RUNNING_DESTINATION_UNKNOWN: &str = "running_destination_unknown";
/// A pointer responds or the exclusive home lock is held; readiness is unproven.
pub const LABEL_RUNNING_ELSEWHERE: &str = "running_elsewhere";
/// Something that is not this daemon's proxy holds the port.
pub const LABEL_PORT_IN_USE: &str = "port_in_use";
/// The proxy refused to start for any other reason.
pub const LABEL_START_FAILED: &str = "start_failed";
/// Startup, serving, or cleanup failed; ownership may remain unconfirmed.
pub const LABEL_CRASHED: &str = "crashed";

/// What the daemon can truthfully say about private inference right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateInferenceState {
    /// The switch is off, and nothing is bound.
    Off,
    /// The owned proxy is draining; its home and listener are not yet released.
    Stopping {
        /// The previously bound port; None while an unfinished start drains.
        port: Option<u16>,
    },
    /// This daemon's proxy is serving on `port` and can route.
    Running {
        /// The bound loopback port.
        port: u16,
    },
    /// This daemon's proxy is serving on `port` with no backend registered,
    /// so nothing will route through it.
    RunningWithoutBackends {
        /// The bound loopback port.
        port: u16,
    },
    /// A pointer responds or the home lock is held. This daemon bound nothing
    /// and stopped nothing; the response alone is not identity or readiness proof.
    RunningElsewhere {
        /// Published port, or the requested port if a lock owner has not published.
        port: u16,
    },
    /// A refusal, by fixed label.
    Failed {
        /// One of [`LABEL_PORT_IN_USE`], [`LABEL_START_FAILED`],
        /// [`LABEL_CRASHED`].
        label: &'static str,
    },
}

impl PrivateInferenceState {
    /// The lowercase label a client renders and a shell matches on.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Off => LABEL_OFF,
            Self::Stopping { .. } => LABEL_STOPPING,
            Self::Running { .. } => LABEL_RUNNING,
            Self::RunningWithoutBackends { .. } => LABEL_RUNNING_NO_BACKENDS,
            Self::RunningElsewhere { .. } => LABEL_RUNNING_ELSEWHERE,
            Self::Failed { label } => label,
        }
    }

    /// The label to render, given what is known about who answers.
    ///
    /// Only [`Self::Running`] splits. Every other state describes the proxy's
    /// lifecycle, which the destination question does not bear on, so they
    /// delegate to [`Self::label`] rather than multiplying a matrix of
    /// lifecycle against routing.
    ///
    /// The three-way argument is the point. `Some(true)` is the plain running
    /// sentence; `Some(false)` says the calls are answered by credentials the
    /// contributor's tools already had; `None` says the question could not be
    /// answered and claims nothing. A two-valued version of this would have to
    /// pick a side when the read fails, and picking "answered here" is the
    /// lie this whole surface exists to stop telling.
    #[must_use]
    pub fn label_for(&self, nearai_authenticated: Option<bool>) -> &'static str {
        match self {
            Self::Running { .. } => match nearai_authenticated {
                Some(true) => LABEL_RUNNING,
                Some(false) => LABEL_RUNNING_ANSWERED_ELSEWHERE,
                None => LABEL_RUNNING_DESTINATION_UNKNOWN,
            },
            other => other.label(),
        }
    }

    /// The port, when there is one to report.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Stopping { port } => *port,
            Self::Running { port }
            | Self::RunningWithoutBackends { port }
            | Self::RunningElsewhere { port } => Some(*port),
            Self::Off | Self::Failed { .. } => None,
        }
    }
}

/// The IronWire home this daemon would use: `$IRONWIRE_HOME`, else
/// `~/.ironwire`.
///
/// `None` when neither can be resolved, which is the one case where private
/// inference cannot be offered at all.
#[must_use]
pub fn ironwire_home() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("IRONWIRE_HOME") {
        let home = PathBuf::from(home);
        if !home.as_os_str().is_empty() {
            return Some(home);
        }
    }
    dirs::home_dir().map(|h| h.join(".ironwire"))
}

/// What an unrequested exit means, whatever the outcome carried.
///
/// A proxy that ended without being asked to is not serving, and a clean
/// `Ok(())` is no better news than an error: the contributor asked for
/// private inference and it is not there. One label covers both so a client
/// never has to distinguish "stopped itself quietly" from "stopped itself
/// loudly".
fn state_after_unrequested_exit(_exit: Result<(), ExitError>) -> PrivateInferenceState {
    PrivateInferenceState::Failed {
        label: LABEL_CRASHED,
    }
}

/// What a successful start means, given the registry the startup report
/// describes.
///
/// A pure function of the two facts that decide it, because the interesting
/// half -- an empty registry -- cannot be produced from a temporary home:
/// IronWire's default configuration registers backends, so a test that
/// wanted `no_backends` would have to hand-build a configuration file whose
/// format belongs to another crate and would drift silently. The mapping is
/// what matters here, and it is tested directly.
fn state_after_start(port: u16, no_backends: bool) -> PrivateInferenceState {
    if no_backends {
        PrivateInferenceState::RunningWithoutBackends { port }
    } else {
        PrivateInferenceState::Running { port }
    }
}

/// IronWire's discovery pointer, as much of it as this module trusts.
///
/// The token path is deliberately not read here: this only needs to know
/// whether something is answering, and on which loopback port.
#[derive(serde::Deserialize)]
struct Pointer {
    control_url: String,
}

/// Open once without following a replacement symlink or blocking on a FIFO.
/// Constants match the shipped platforms' fcntl.h; unsupported Unix targets
/// decline advisory discovery rather than guessing their open ABI.
#[cfg(unix)]
fn pointer_open_flags() -> Option<i32> {
    let flags = if cfg!(target_os = "macos") {
        0x0004 | 0x0100 // O_NONBLOCK | O_NOFOLLOW (Darwin)
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        0x0800 | 0x20000
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        0x0800 | 0x08000
    } else {
        return None;
    };
    Some(flags)
}

#[cfg(unix)]
fn open_checked_pointer(path: &Path, checked: &std::fs::Metadata) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let flags = pointer_open_flags()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file()
        || opened.dev() != checked.dev()
        || opened.ino() != checked.ino()
        || opened.uid() != checked.uid()
        || opened.mode() & 0o022 != 0
    {
        return None;
    }
    Some(file)
}

#[cfg(windows)]
fn open_checked_pointer(path: &Path, _checked: &std::fs::Metadata) -> Option<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .ok()?;
    let opened = file.metadata().ok()?;
    // Windows policy is regular-file/reparse shape, not a Unix uid/mode or
    // DACL assertion. Validate the opened object rather than the old pathname.
    if !opened.is_file() || opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return None;
    }
    Some(file)
}

#[cfg(not(any(unix, windows)))]
fn open_checked_pointer(_path: &Path, _checked: &std::fs::Metadata) -> Option<std::fs::File> {
    None
}

/// The loopback port a pointer in `home` names, if it names one.
fn pointed_port(home: &Path) -> Option<u16> {
    let path = home.join("endpoint.json");
    let metadata = super::ironwire_pointer::trustworthy_file(&path)?;
    if metadata.len() > MAX_POINTER_BYTES {
        return None;
    }
    // Bound the read itself too: the file can grow after the metadata check.
    let mut body = Vec::new();
    open_checked_pointer(&path, &metadata)?
        .take(MAX_POINTER_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() as u64 > MAX_POINTER_BYTES {
        return None;
    }
    let pointer: Pointer = serde_json::from_slice(&body).ok()?;
    let url = url::Url::parse(&pointer.control_url).ok()?;
    let host = url.host_str()?;
    if url.scheme() != "http"
        || !matches!(host, "127.0.0.1" | "localhost")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    url.port_or_known_default().filter(|port| *port != 0)
}

/// An advisory response on the pointer's loopback port, not identity proof.
/// No token is read or sent. A response conservatively avoids takeover; only
/// IronWire's exclusive home lock is authoritative about ownership on start.
async fn existing_instance(home: &Path) -> Option<u16> {
    let port = pointed_port(home)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build()
        .ok()?;
    let response = client
        .get(format!("http://127.0.0.1:{port}/_ironwire/health"))
        .send()
        .await
        .ok()?;
    response.status().is_success().then_some(port)
}

/// Metadata routing may follow only a proxy owned by this daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedEndpoint {
    pub port: u16,
    pub home: PathBuf,
}

pub(crate) fn effective_metadata_declaration(
    declared: Option<&super::settings::IronWireDeclaration>,
    enabled: bool,
    owned: Option<&OwnedEndpoint>,
) -> Option<super::settings::IronWireDeclaration> {
    if let Some(declared) = declared {
        return Some(declared.clone());
    }
    enabled
        .then_some(owned)
        .flatten()
        .map(|owned| super::settings::IronWireDeclaration::Watch {
            port: owned.port,
            token_dir: Some(owned.home.clone()),
        })
}

/// Everything this daemon chooses about an embedded start, beyond the home
/// and the port.
///
/// **This replaces a workaround.** Until upstream #40 and #45 there was no API
/// for either of these, so this module wrote `[updates]\ncheck = false` into
/// `$IRONWIRE_HOME/config.toml` -- a file that may be a real contributor's,
/// shared with the `ironwire` CLI -- and had no way at all to decline the
/// startup probes. That write is gone, along with its staging file, its
/// occupied-slot rule and its atomic rename: none of it is needed once the
/// choice can be stated in code, and none of it could ever reach the probes.
///
/// Two separate choices, and they are not the same question:
///
/// - [`UpdateChecks::Off`] declines the two requests IronWire makes on its own
///   behalf -- the release check, which `UpdatePolicy::HostManaged` already
///   suppressed, and the signed provider-catalog refresh, which it did not.
///   The refresh is the one the config file was written for: sixty seconds
///   after start and every six hours after, for as long as the contributor
///   leaves the switch on, and it cannot succeed and could not be used if it
///   did -- the host it names does not resolve and the key it verifies against
///   is an all-zero placeholder. A periodic outbound lookup from a
///   contributor's machine that they did not ask for and that buys them
///   nothing is not a thing this client leaves switched on.
///
/// - [`StartupProbes::Configured`] narrows the startup catalogue discovery,
///   which no configuration file this daemon could write would have touched.
///   `build_registry` registers the Claude subscription, the Codex
///   subscription and the API-key backends from credentials it finds in the
///   environment with no entry naming them, and registers NEAR AI
///   unconditionally -- so today every contributor who turns the switch on
///   makes a `GET /models` to NEAR AI at startup, on behalf of a backend
///   nobody named.
///
/// `Configured` rather than `Off` is deliberate. `Off` probes nothing ever,
/// which would also drop the probe for a backend the contributor *did* declare
/// in their own `config.toml` -- and a probe is real work, not just a request:
/// it learns the model catalogue the provider actually serves and surfaces an
/// expired credential at startup instead of at the first real call. Taking
/// that away from someone who deliberately named a backend is a regression for
/// them and buys no privacy, because they asked for it. `Configured` removes
/// exactly the requests nobody asked for and keeps exactly the ones somebody
/// did, which is the same rule this module already follows about the config
/// file itself: never act on a slot the contributor owns.
///
/// It is not a network kill switch and must not be described as one. A
/// contributor who declares a backend still gets one probe per declared
/// backend at startup, by their own choice.
/// The credential argument is the daemon's NEAR AI inference key, or `None`
/// when the contributor has not obtained one.
///
/// `None` is not "a source that answers nothing" -- it is *no source*, and
/// the difference is the whole reason this takes an `Option` rather than
/// always installing a closure. A source is a claim of ownership over every
/// name, so installing one that answers nothing would leave IronWire unable
/// to read a name it would otherwise have found for itself.
///
/// When a key *is* present, the closure answers exactly one name and nothing
/// else. It cannot answer for a subscription: those are key-less by
/// construction, a Claude Code or Codex login being a token in a file rather
/// than a value any name-keyed source can supply.
///
/// Which is why the key arm also selects [`CredentialFiles::Discover`], and
/// that pairing is the load-bearing part of this function. IronWire's
/// `credentials` field used to be one switch governing two questions -- whose
/// answers count for a name, *and* whether the credential files Claude Code
/// and Codex write may be read at all -- so supplying any source turned the
/// second off. Under that API a contributor who obtained a NEAR AI key would
/// have had their working Claude subscription silently stop being a
/// destination, and nothing would have announced it: the NEAR AI backend is
/// registered unconditionally, key or no key, so the registry is never empty,
/// `StartupReport::no_backends` never fires, and the daemon goes on reporting
/// `running` while answering from fewer backends than the contributor has.
/// ironwire#53 separated the two questions for exactly this case. We answer
/// the one name we hold a key for; every login the contributor already had
/// goes on answering for itself.
///
/// Selecting `Discover` is an acceptance, not a free win: a request can go to
/// a backend registered from a login this daemon never named. That is the
/// right trade here, because those destinations are ones the contributor set
/// up deliberately and had before this switch existed -- taking them away is
/// the change that would need consent, not leaving them.
///
/// The name half deliberately does not move with it. Under `Discover` the
/// process environment is still not consulted, so a stray `ANTHROPIC_API_KEY`
/// in the daemon's environment still registers nothing; only the files on
/// disk are read.
///
/// Nothing here can leak the key. `HostSecret` has no `Debug` and zeroes on
/// drop, and `EmbedOptions`' own `Debug` renders this field as "host-owned"
/// or "discovered" and never a value.
fn embed_options(credential: Option<HostSecret>) -> EmbedOptions {
    let base = EmbedOptions::default()
        .with_update_checks(UpdateChecks::Off)
        .with_startup_probes(StartupProbes::Configured);
    match credential {
        Some(key) => base
            .with_credentials(move |name| (name == NEAR_AI_CREDENTIAL_NAME).then(|| key.clone()))
            .with_credential_files(CredentialFiles::Discover),
        None => base,
    }
}

/// The one environment name this daemon will ever answer for IronWire.
///
/// It is answered through the credential source rather than by setting the
/// variable, and that is a decision rather than a preference: `set_var` is
/// `unsafe` in Rust 2024, and a credential placed in this process's
/// environment is readable by every other thing running in the daemon,
/// including code we did not write.
const NEAR_AI_CREDENTIAL_NAME: &str = "NEARAI_API_KEY";

/// One daemon's private-inference instance: at most one proxy, and the state
/// the daemon reports for it.
pub struct PrivateInference {
    home: PathBuf,
    /// `None` takes the port from IronWire's own configuration; `Some(0)`
    /// asks for an ephemeral one.
    port: Option<u16>,
    proxy: Option<EmbeddedProxy>,
    owned_home: Option<PathBuf>,
    // Kept across canceled callers and deadlines. Dropping a wait must not
    // turn a still-owned listener into Off or permit another bind.
    starting: Option<tokio::task::JoinHandle<Result<EmbeddedProxy, EmbedError>>>,
    stopping: Option<tokio::task::JoinHandle<bool>>,
    cleanup_unconfirmed: bool,
    recovery_requested: bool,
    requested_generation: Option<u64>,
    /// The runtime a proxy's tasks must be spawned onto, when it is not the
    /// one this call happens to be running on.
    ///
    /// `embed::start` puts the axum server and IronWire's housekeeping on
    /// the ambient runtime via `tokio::spawn`, so whichever runtime is in
    /// context when it is called owns the proxy for its whole life. On the
    /// daemon's own poll tick that is the daemon runtime and nothing is
    /// needed. On the synchronous path it is a throwaway current-thread
    /// runtime built inside a scoped thread, which is dropped microseconds
    /// later -- taking every one of the proxy's tasks with it while the
    /// response says `running`. That path sets this.
    runtime: Option<tokio::runtime::Handle>,
    /// The NEAR AI inference key to answer with, when the contributor has
    /// one. Read from settings on each reconcile pass rather than captured at
    /// construction, because a ceremony can complete while the daemon runs.
    /// A change takes effect at the next start: IronWire reads its
    /// credentials once, when the registry is built.
    credential: Option<HostSecret>,
    token_capture_enabled: Option<bool>,
    state: PrivateInferenceState,
    /// A proxy this daemon started has ended on its own. Sticky until the
    /// switch is turned off and on again: restarting it every poll tick
    /// would hide a proxy that cannot stay up behind a state that keeps
    /// flickering back to green.
    crashed: bool,
    /// How many proxies this instance has started, for [`Self::starts`].
    /// Test-only: nothing in production asks, and a field written and never
    /// read is exactly what the warnings-as-errors build refuses.
    #[cfg(test)]
    starts: u64,
}

/// Why a start did not produce a proxy.
///
/// A separate type from `EmbedError` because one of the two ways to fail is
/// not IronWire's: the spawned start can fail to join at all. Folding that
/// into an `EmbedError` variant would put a specific, wrong cause -- a bind
/// failure, say -- on a condition that never reached the bind.
enum StartRefusal {
    /// IronWire refused, and said why.
    Embed(EmbedError),
    /// The start was spawned onto the daemon runtime and never came back:
    /// it panicked, or that runtime went away underneath it.
    Spawn,
}

impl PrivateInference {
    /// Host IronWire out of `home`, on whatever port its own configuration
    /// names.
    #[must_use]
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            port: None,
            proxy: None,
            owned_home: None,
            starting: None,
            stopping: None,
            cleanup_unconfirmed: false,
            recovery_requested: false,
            requested_generation: None,
            runtime: None,
            credential: None,
            token_capture_enabled: None,
            state: PrivateInferenceState::Off,
            crashed: false,
            #[cfg(test)]
            starts: 0,
        }
    }

    /// Host IronWire out of `home` on an explicit port. `0` asks the OS for
    /// an ephemeral one, which is what tests use so they cannot collide with
    /// a developer's own IronWire.
    #[must_use]
    pub fn with_port(home: PathBuf, port: u16) -> Self {
        Self {
            port: Some(port),
            ..Self::new(home)
        }
    }

    #[cfg(test)]
    pub(crate) fn with_pending_start_for_test(
        home: PathBuf,
        task: tokio::task::JoinHandle<Result<EmbeddedProxy, EmbedError>>,
    ) -> Self {
        Self {
            starting: Some(task),
            ..Self::new(home)
        }
    }

    #[cfg(test)]
    pub(crate) fn with_shutdown_for_test(
        home: PathBuf,
        port: u16,
        task: tokio::task::JoinHandle<bool>,
    ) -> Self {
        Self {
            stopping: Some(task),
            state: PrivateInferenceState::Stopping { port: Some(port) },
            ..Self::new(home)
        }
    }

    /// Name the runtime this instance's proxy must live on.
    ///
    /// Idempotent and cheap, so the reconcile pass sets it every time
    /// rather than relying on a one-shot at construction: `PrivateInference`
    /// is built by `DaemonShared::load`, which is synchronous and is called
    /// from places that are not inside any runtime at all, so there is no
    /// handle to capture there.
    ///
    /// A `Handle` and not an `EnterGuard`: entering a runtime sets a
    /// thread-local, and `apply` awaits, so a guard taken here would have to
    /// be held across await points -- where a future resumed on a different
    /// worker thread would find the context missing and drop the guard
    /// against a thread that never had it. Spawning the start *onto* the
    /// handle is the version that does not depend on which thread polls
    /// what.
    pub fn set_runtime(&mut self, runtime: Option<tokio::runtime::Handle>) {
        self.runtime = runtime;
    }

    /// Hand the proxy the credential it should answer `NEARAI_API_KEY` with,
    /// or `None` when the contributor has obtained none.
    ///
    /// Called on every reconcile pass, from the same read of settings that
    /// decides whether the proxy runs at all, so a ceremony that completes
    /// mid-run is picked up without restarting the daemon. It takes effect at
    /// the proxy's next start, because IronWire resolves its credentials once,
    /// while building the registry.
    ///
    /// That next start is not left to chance. Handing the key to this
    /// instance and stopping there is what made a completed ceremony change
    /// nothing a contributor could see: `DaemonShared` advances the
    /// private-inference generation when the stored credential changes, and
    /// [`Self::accept_generation`] turns that into the stop-and-start that
    /// actually rebuilds the registry.
    pub fn set_token_capture(&mut self, enabled: Option<bool>) {
        self.token_capture_enabled = enabled;
    }

    pub fn set_credential(&mut self, credential: Option<HostSecret>) {
        self.credential = credential;
    }

    /// Whether a credential is held, for the reconcile test that proves one
    /// reaches here from settings. Presence only; the value never leaves.
    #[cfg(test)]
    pub(crate) fn holds_credential(&self) -> bool {
        self.credential.is_some()
    }

    /// How many proxies this instance has started.
    ///
    /// Counted unconditionally and read only by tests, because a restart is
    /// otherwise observable only as a new ephemeral port -- and a port the
    /// kernel happens to hand back is a test that passes by luck. The
    /// question "did the key reach IronWire" is answerable only by "was the
    /// registry built again", and this is that.
    #[cfg(test)]
    pub(crate) fn starts(&self) -> u64 {
        self.starts
    }

    /// Whether accepted settings superseded the request this instance observed.
    pub(crate) fn accept_generation(&mut self, generation: u64) -> bool {
        let changed = self
            .requested_generation
            .replace(generation)
            .is_some_and(|old| old != generation);
        if changed && self.cleanup_unconfirmed {
            self.recovery_requested = true;
        }
        changed
    }

    pub(crate) fn has_pending_ownership(&self) -> bool {
        self.proxy.is_some()
            || self.starting.is_some()
            || self.stopping.is_some()
            || self.cleanup_unconfirmed
    }

    #[cfg(test)]
    pub(crate) async fn end_owned_for_test(&mut self) {
        // Finish the real listener, then install the same local outcome as
        // poll observing an unsolicited exit. Shared routing stays stale.
        self.proxy
            .take()
            .expect("owned test proxy")
            .shutdown()
            .await;
        self.crashed = true;
        self.state = state_after_unrequested_exit(Ok(()));
    }

    pub(crate) fn owned_endpoint(&self) -> Option<OwnedEndpoint> {
        let proxy = self.proxy.as_ref().filter(|proxy| !proxy.is_finished())?;
        Some(OwnedEndpoint {
            port: proxy.port(),
            home: self.owned_home.clone()?,
        })
    }

    /// What the daemon reports right now.
    #[must_use]
    pub fn state(&self) -> PrivateInferenceState {
        self.state.clone()
    }

    /// Stop, and where it is safe to, finish stopping -- so the caller's
    /// following `apply(true)` starts a new proxy on this pass rather than
    /// finding a shutdown in flight and declining.
    ///
    /// The drain is conditional and the condition is the whole point.
    /// `apply(false)` spawns the shutdown and returns precisely so a stop
    /// cannot park the daemon's lifecycle lock on a future with no deadline
    /// of its own, and the future it would park on is real: a shutdown task
    /// built over a *pending start* awaits that start first, and a start
    /// awaits IronWire binding a port. Waiting for that here would wedge the
    /// pass, and with it every later one.
    ///
    /// So this drains only when what is being stopped is a proxy that is
    /// already running and nothing else is in flight -- a plain
    /// `proxy.shutdown()`, which ends on its own. Every other shape falls
    /// back to the two-pass cycle each generation change has always had.
    pub(crate) async fn cycle(&mut self) {
        let drainable = self.proxy.is_some() && self.starting.is_none() && self.stopping.is_none();
        self.apply(false).await;
        if drainable {
            self.finish_stop().await;
        }
    }

    /// Bring the instance in line with the switch. Idempotent both ways.
    pub async fn apply(&mut self, on: bool) {
        self.poll().await;
        if self.cleanup_unconfirmed && self.starting.is_none() && (!on || !self.recovery_requested)
        {
            return;
        }
        // A new accepted opt-in may retry, but only acquisition of the same
        // upstream home lock proves the uncertain prior owner has released it.
        // Do not turn an unknown drain into Off, or trust its discovery pointer.
        let recovering = self.cleanup_unconfirmed;
        self.recovery_requested = false;
        if !on {
            if let Some(starting) = self.starting.take() {
                let runtime = self
                    .runtime
                    .clone()
                    .unwrap_or_else(tokio::runtime::Handle::current);
                let prior_cleanup_unknown = self.cleanup_unconfirmed;
                self.stopping = Some(runtime.spawn(async move {
                    match starting.await {
                        Ok(Ok(proxy)) => {
                            proxy.shutdown().await;
                            true
                        }
                        Ok(Err(_)) => !prior_cleanup_unknown,
                        Err(_) => false,
                    }
                }));
                self.state = PrivateInferenceState::Stopping { port: None };
            }
            if let Some(proxy) = self.proxy.take() {
                self.owned_home = None;
                let port = proxy.port();
                let runtime = self
                    .runtime
                    .clone()
                    .unwrap_or_else(tokio::runtime::Handle::current);
                self.stopping = Some(runtime.spawn(async move {
                    proxy.shutdown().await;
                    true
                }));
                self.state = PrivateInferenceState::Stopping { port: Some(port) };
            }
            if self.stopping.is_none() {
                self.crashed = false;
                self.state = PrivateInferenceState::Off;
            }
            return;
        }
        if self.proxy.is_some() || self.stopping.is_some() || self.crashed {
            return;
        }
        if !recovering
            && self.starting.is_none()
            && let Some(port) = existing_instance(&self.home).await
        {
            tracing::info!(
                pass = "private_inference",
                port,
                "an existing IronWire owns this home"
            );
            self.state = PrivateInferenceState::RunningElsewhere { port };
            return;
        }
        match self.start_proxy().await {
            Ok(proxy) => {
                self.cleanup_unconfirmed = false;
                let port = proxy.port();
                self.state = state_after_start(port, proxy.startup_report().no_backends);
                // Capture the resolved home once, while adopting this proxy;
                // later changes to the spelling of a relative path cannot
                // silently retarget its metadata reader.
                self.owned_home = self.home.canonicalize().ok();
                if self.owned_home.is_none() {
                    tracing::warn!(
                        reason = "private-inference-home-unresolved",
                        "owned metadata routing unavailable"
                    );
                }
                self.proxy = Some(proxy);
                tracing::info!(
                    pass = "private_inference",
                    port,
                    state = self.state.label(),
                    "proxy started"
                );
            }
            Err(error) => {
                // `Lock` is not a failure to report as one: it means
                // another IronWire already owns this home, which is the
                // documented meaning of `running_elsewhere`. The pointer
                // probe above would usually have caught it, but that probe
                // is advisory -- the pointer can be missing, stale, or not
                // yet written by an owner that is still starting -- so the
                // home lock is the authoritative answer and this is where
                // it arrives. Upstream documents the carried port as the
                // owner's published one *or* the port we asked for, so the
                // label is exact and the number is the best available.
                let error = match error {
                    StartRefusal::Embed(error) => error,
                    StartRefusal::Spawn => {
                        self.cleanup_unconfirmed = true;
                        tracing::warn!(
                            pass = "private_inference",
                            reason = LABEL_CRASHED,
                            "the proxy start did not come back from the daemon runtime"
                        );
                        self.state = PrivateInferenceState::Failed {
                            label: LABEL_CRASHED,
                        };
                        return;
                    }
                };
                if recovering {
                    self.state = PrivateInferenceState::Failed {
                        label: LABEL_CRASHED,
                    };
                    return;
                }
                if let EmbedError::Lock { port } = error {
                    tracing::info!(
                        pass = "private_inference",
                        port,
                        "an existing IronWire owns this home"
                    );
                    self.state = PrivateInferenceState::RunningElsewhere { port };
                    return;
                }
                let label = match error {
                    EmbedError::PortInUse { .. } => LABEL_PORT_IN_USE,
                    _ => LABEL_START_FAILED,
                };
                tracing::warn!(
                    pass = "private_inference",
                    reason = label,
                    "proxy refused to start"
                );
                self.state = PrivateInferenceState::Failed { label };
            }
        }
    }

    /// Start on the daemon runtime and retain the task across canceled callers.
    /// A missing adopted runtime uses the caller's current runtime, as before.
    async fn start_proxy(&mut self) -> Result<EmbeddedProxy, StartRefusal> {
        if self.starting.is_none() {
            #[cfg(test)]
            {
                self.starts += 1;
            }
            let runtime = self
                .runtime
                .clone()
                .unwrap_or_else(tokio::runtime::Handle::current);
            let home = self.home.clone();
            let port = self.port;
            let credential = self.credential.clone();
            let capture_enabled = self.token_capture_enabled;
            self.starting = Some(runtime.spawn(async move {
                let mut options = embed_options(credential);
                options.token_capture_enabled = capture_enabled;
                embed::start_with_options(&home, port, options, |_, _| {}).await
            }));
        }
        // Await through the retained handle. Canceling a caller leaves the
        // startup owned so a stop can drain any eventual proxy it produces.
        let started = self
            .starting
            .as_mut()
            .expect("retained proxy startup")
            .await;
        self.starting = None;
        match started {
            Ok(started) => started.map_err(StartRefusal::Embed),
            Err(_) => Err(StartRefusal::Spawn),
        }
    }

    /// Wait for the retained shutdown task. Canceling this wait retains ownership.
    pub(crate) async fn finish_stop(&mut self) -> bool {
        self.apply(false).await;
        if let Some(task) = self.stopping.as_mut() {
            // Await by reference so cancellation retains ownership.
            let completed = task.await;
            self.stopping = None;
            self.record_stop_outcome(completed);
        }
        self.state == PrivateInferenceState::Off
    }

    fn record_stop_outcome(&mut self, completed: Result<bool, tokio::task::JoinError>) {
        if matches!(completed, Ok(true)) {
            self.cleanup_unconfirmed = false;
            self.state = PrivateInferenceState::Off;
            self.crashed = false;
        } else {
            self.cleanup_unconfirmed = true;
            self.state = PrivateInferenceState::Failed {
                label: LABEL_CRASHED,
            };
        }
    }

    /// Notice a proxy that ended without being asked to.
    ///
    /// Cheap enough for the daemon's existing poll: `is_finished` does not
    /// await, and `wait` is only reached once the task has already ended.
    /// A proxy that ends must never take the daemon down, so nothing here
    /// propagates.
    pub async fn poll(&mut self) {
        if self
            .stopping
            .as_ref()
            .is_some_and(|task| task.is_finished())
        {
            let completed = self.stopping.take().expect("finished shutdown task").await;
            self.record_stop_outcome(completed);
        }
        let Some(proxy) = self.proxy.as_mut() else {
            return;
        };
        if !proxy.is_finished() {
            return;
        }
        let exit = proxy.wait().await;
        self.proxy = None;
        self.owned_home = None;
        self.crashed = true;
        self.state = state_after_unrequested_exit(exit);
        tracing::warn!(
            pass = "private_inference",
            reason = LABEL_CRASHED,
            "proxy ended without being asked to"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Start against a home whose previous owner has released it.
    ///
    /// IronWire's home guard closes its lock descriptor without first calling
    /// `flock(LOCK_UN)`, and `flock` ownership belongs to the open file
    /// description rather than to the descriptor: `fork` duplicates it and
    /// `O_CLOEXEC` only takes effect at the following `exec`, so a child that
    /// any other test in this binary spawns carries a copy of that descriptor
    /// and keeps the lock held past the release. Closing is not a release
    /// there, and the first acquisition afterwards can see `WouldBlock` with
    /// no owner at all.
    ///
    /// Retrying does not soften what is being asserted. Ownership that really
    /// was retained is held by a live proxy and never frees, so a bounded
    /// retry still fails; only an inherited descriptor on its way to `exec`
    /// clears. See `HeldLock` in `compute::process` for the release this
    /// upstream guard is missing.
    ///
    /// This is a workaround with an expiry condition, not a permanent shape:
    /// nearai/ironwire#54 adds the missing `unlock` to that guard. Remove this
    /// helper and go back to a plain `embed::start(...).unwrap()` when that
    /// merges and the pin moves.
    async fn start_once_the_home_is_free(home: &Path) -> EmbeddedProxy {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match embed::start(home, Some(0)).await {
                Ok(proxy) => return proxy,
                Err(EmbedError::Lock { port }) if tokio::time::Instant::now() < deadline => {
                    assert_eq!(port, 0, "a live owner published a port, so it is not free");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("the released home never became startable: {error:?}"),
            }
        }
    }

    /// Counts every event IronWire's catalog refresh emits, and nothing else.
    ///
    /// The refresh logs on both outcomes -- applied, unchanged, or skipped
    /// after a failure -- so any event from that module is the network call
    /// having been made. No event from it is the task not existing.
    struct CatalogWatch(Arc<AtomicUsize>);

    impl CatalogWatch {
        const TARGET: &'static str = "ironwire_proxy::embed::catalog";
    }

    impl tracing::Subscriber for CatalogWatch {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == Self::TARGET
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() == Self::TARGET {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Without a key of ours, IronWire must be left entirely on its own
    /// discovery -- and with one, we must answer that one name and no other
    /// while every destination the contributor already had keeps answering.
    ///
    /// The file half is the load-bearing one and the least obvious. Handing
    /// IronWire a credential source is a claim of ownership over every name,
    /// and it used to carry a second meaning with it: reading of the
    /// credential files Claude Code and Codex write was turned off with it,
    /// so obtaining a NEAR AI key would have cost a contributor their working
    /// subscription. Nothing would have reported it, either -- the NEAR AI
    /// backend is registered whether or not a key was found, so the registry
    /// is never empty and the state stays `running`. `CredentialFiles`
    /// separates the two questions; this pins that we answer them separately.
    #[test]
    fn no_key_of_ours_leaves_every_other_destination_alone() {
        assert!(
            embed_options(None).credentials.is_none(),
            "a contributor with no key of ours must reach IronWire's own \
             discovery, or their Claude and Codex subscriptions stop \
             answering with nothing to say so"
        );
        assert_eq!(
            embed_options(None).credential_files,
            CredentialFiles::FollowCredentialOwner,
            "with no source of ours, IronWire owns the names, and following \
             that owner is what reads the files"
        );

        let options = embed_options(Some(HostSecret::from("sk-minted".to_string())));
        assert_eq!(
            options.credential_files,
            CredentialFiles::Discover,
            "holding a key of ours must not cost a contributor the Claude or \
             Codex login they already had -- those are files, not names, and \
             no source of ours can answer for them"
        );
        let source = options
            .credentials
            .as_ref()
            .expect("a held key is answered for");
        assert!(source(NEAR_AI_CREDENTIAL_NAME).is_some());
        // Exactly one name. Answering a second would put this daemon in the
        // path of a credential it never obtained and does not own.
        for other in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "NEARAI_API_KEY_2",
            "nearai_api_key",
            "",
        ] {
            assert!(source(other).is_none(), "{other}");
        }
    }

    /// The choices, stated once, so a later edit that quietly widens them
    /// fails here rather than on a contributor's machine.
    #[test]
    fn the_daemon_declines_both_kinds_of_request_it_never_asked_for() {
        let options = embed_options(None);
        assert_eq!(
            options.update_checks,
            UpdateChecks::Off,
            "the release check and the catalog refresh are back on"
        );
        assert_eq!(
            options.startup_probes,
            StartupProbes::Configured,
            "startup probes are no longer limited to backends an entry names"
        );
        // Not narrowed to `Off`: a contributor who declared a backend asked
        // for that probe, and it is what tells them at startup rather than at
        // their first call that the credential expired.
        assert_ne!(options.startup_probes, StartupProbes::Off);
        // Unchanged from what `embed::start` gave us: this host ships and
        // upgrades the library.
        assert_eq!(
            options.update_policy,
            ironwire_proxy::embed::UpdatePolicy::HostManaged
        );
    }

    /// The workaround this replaced wrote `[updates] check = false` into the
    /// home. Nothing does now, and a home the daemon started out of must come
    /// back with no file this daemon put there -- including for a contributor
    /// who has none of their own, which is the case the old code wrote into.
    #[tokio::test]
    async fn a_start_leaves_the_home_configuration_alone_and_still_runs() {
        let home = tempfile::tempdir().unwrap();
        let mut host = PrivateInference::with_port(home.path().to_path_buf(), 0);
        host.apply(true).await;
        assert!(
            matches!(
                host.state(),
                PrivateInferenceState::Running { .. }
                    | PrivateInferenceState::RunningWithoutBackends { .. }
            ),
            "{:?}",
            host.state()
        );
        assert!(
            !home.path().join("config.toml").exists(),
            "the daemon wrote a configuration file into somebody's home again"
        );
        assert!(
            !home.path().join(".config.toml.trace-commons").exists(),
            "a staging file from the deleted workaround is still being written"
        );
        assert!(host.finish_stop().await);
    }

    /// IronWire's own account of the start, rather than our account of what we
    /// asked for. A `config.toml` that asks for the checks is deliberately
    /// present: this daemon's instance declines on its own behalf whatever the
    /// file says, and the file is still not touched -- an `ironwire` CLI run
    /// out of this same home is a different process and still gets what the
    /// contributor wrote there.
    #[tokio::test]
    async fn ironwire_reports_the_checks_declined_and_the_file_untouched() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config.toml");
        std::fs::write(&config, "[updates]\ncheck = true\n").unwrap();

        let proxy = embed::start_with_options(home.path(), Some(0), embed_options(None), |_, _| {})
            .await
            .expect("start");
        assert!(
            !proxy.startup_report().update_checks,
            "IronWire says it will make the requests we declined"
        );
        proxy.shutdown().await;

        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "[updates]\ncheck = true\n",
            "the contributor's own file was rewritten"
        );
    }

    /// Watch for the call itself, rather than reading the code that makes it.
    ///
    /// Ignored because it can only be answered in real time: the first fetch
    /// is deliberately delayed sixty seconds so it never competes with a
    /// contributor's first request. Run it with
    /// `cargo test -p trace-commons-contributor --lib -- --ignored --exact \
    ///  daemon::private_inference::tests::the_catalog_fetch_happens_by_default_and_not_under_our_options`.
    ///
    /// The first half is the positive control, and it is the reason this test
    /// means anything: a watcher that never fires would let the second half
    /// pass while the call was still being made every six hours.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "waits out IronWire's sixty-second first-check delay twice"]
    async fn the_catalog_fetch_happens_by_default_and_not_under_our_options() {
        const WATCH: Duration = Duration::from_secs(90);
        let seen = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::set_global_default(CatalogWatch(seen.clone())).unwrap();

        // Default options on a home that asks for the checks: the call is
        // made. This is what a caller that did nothing would get.
        let asked = tempfile::tempdir().unwrap();
        std::fs::write(
            asked.path().join("config.toml"),
            "[updates]\ncheck = true\n",
        )
        .unwrap();
        let proxy = embed::start_with_options(
            asked.path(),
            Some(0),
            ironwire_proxy::embed::EmbedOptions::default(),
            |_, _| {},
        )
        .await
        .expect("start");
        tokio::time::sleep(WATCH).await;
        let asked_for_it = seen.load(Ordering::SeqCst);
        proxy.shutdown().await;
        assert!(asked_for_it > 0, "the default path never made the call");

        // Our options, through the daemon, on a home nobody configured.
        seen.store(0, Ordering::SeqCst);
        let quiet = tempfile::tempdir().unwrap();
        let mut host = PrivateInference::with_port(quiet.path().to_path_buf(), 0);
        host.apply(true).await;
        tokio::time::sleep(WATCH).await;
        let unasked = seen.load(Ordering::SeqCst);
        assert!(host.finish_stop().await);
        assert_eq!(unasked, 0, "the call was still made {unasked} time(s)");
    }

    #[test]
    fn effective_metadata_preserves_explicit_consent_and_requires_owned_opt_in() {
        use super::super::settings::IronWireDeclaration;
        let owned = OwnedEndpoint {
            port: 3210,
            home: PathBuf::from("/owned"),
        };
        for declaration in [
            IronWireDeclaration::Off,
            IronWireDeclaration::Watch {
                port: 1234,
                token_dir: Some(PathBuf::from("/custom")),
            },
        ] {
            for enabled in [false, true] {
                for endpoint in [None, Some(&owned)] {
                    assert_eq!(
                        effective_metadata_declaration(Some(&declaration), enabled, endpoint),
                        Some(declaration.clone())
                    );
                }
            }
        }
        assert_eq!(
            effective_metadata_declaration(None, false, Some(&owned)),
            None
        );
        assert_eq!(effective_metadata_declaration(None, true, None), None);
        assert_eq!(
            effective_metadata_declaration(None, true, Some(&owned)),
            Some(IronWireDeclaration::Watch {
                port: 3210,
                token_dir: Some(PathBuf::from("/owned"))
            })
        );
    }

    #[tokio::test]
    async fn a_canceled_drain_wait_retains_ownership_and_blocks_rebinding() {
        let home = tempfile::tempdir().unwrap();
        let absent = home.path().join("unused");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = pending.await;
            drop(listener);
            true
        });
        let task_id = task.id();
        let mut host = PrivateInference::with_shutdown_for_test(absent.clone(), port, task);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), host.finish_stop())
                .await
                .is_err()
        );
        assert_eq!(
            host.state(),
            PrivateInferenceState::Stopping { port: Some(port) }
        );
        assert_eq!(host.stopping.as_ref().unwrap().id(), task_id);
        host.apply(true).await;
        assert_eq!(
            host.state(),
            PrivateInferenceState::Stopping { port: Some(port) }
        );
        assert!(!absent.exists());
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), host.finish_stop())
                .await
                .unwrap()
        );
        assert_eq!(host.state(), PrivateInferenceState::Off);
        assert!(host.stopping.is_none());
        // The completed task has dropped the listener. Rebinding this freed
        // ephemeral port here would race unrelated parallel proxy tests;
        // the real start/stop test separately exercises listener release.
    }

    #[tokio::test]
    async fn canceled_start_is_retained_and_its_eventual_proxy_is_drained() {
        let home = tempfile::tempdir().unwrap();
        let start_home = home.path().to_path_buf();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            pending.await.unwrap();
            embed::start(&start_home, Some(0)).await
        });
        let task_id = task.id();
        let mut host = PrivateInference::with_port(home.path().to_path_buf(), 0);
        host.starting = Some(task);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), host.apply(true))
                .await
                .is_err()
        );
        assert_eq!(host.starting.as_ref().unwrap().id(), task_id);
        host.apply(false).await;
        assert_eq!(host.state(), PrivateInferenceState::Stopping { port: None });
        assert!(host.starting.is_none());
        host.apply(true).await;
        assert_eq!(host.state(), PrivateInferenceState::Stopping { port: None });
        release.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), host.finish_stop())
                .await
                .unwrap()
        );
        assert_eq!(host.state(), PrivateInferenceState::Off);
        assert!(!home.path().join("endpoint.json").exists());
        // Reusing the isolated home proves the late startup's ownership was
        // released; it cannot leave a server or home lock behind after Off.
        let next = start_once_the_home_is_free(home.path()).await;
        next.shutdown().await;
    }

    #[tokio::test]
    async fn failed_shutdown_never_claims_off_or_restarts() {
        let home = tempfile::tempdir().unwrap();
        let absent = home.path().join("unused");
        let task = tokio::spawn(async {
            panic!("controlled shutdown panic");
        });
        let mut host = PrivateInference::with_shutdown_for_test(absent.clone(), 1, task);
        assert!(!host.finish_stop().await);
        host.apply(false).await;
        host.apply(true).await;
        assert_eq!(
            host.state(),
            PrivateInferenceState::Failed {
                label: LABEL_CRASHED
            }
        );
        assert!(!absent.exists());
    }

    #[tokio::test]
    async fn explicit_retry_requires_the_previous_home_owner_to_release() {
        let home = tempfile::tempdir().unwrap();
        let owner = embed::start(home.path(), Some(0)).await.unwrap();
        let failed = tokio::spawn(async { false });
        let mut host = PrivateInference::with_shutdown_for_test(
            home.path().to_path_buf(),
            owner.port(),
            failed,
        );
        host.port = Some(0);
        host.accept_generation(0);
        assert!(!host.finish_stop().await);
        host.accept_generation(1);
        host.apply(false).await;
        assert_eq!(host.state().label(), LABEL_CRASHED);
        host.accept_generation(2);
        host.apply(true).await;
        assert_eq!(host.state().label(), LABEL_CRASHED);
        assert!(host.proxy.is_none());
        owner.shutdown().await;
        // A failed retry is not retried every poll, even after the lock frees.
        host.apply(true).await;
        assert!(host.proxy.is_none());
        host.accept_generation(3);
        host.apply(false).await;
        host.accept_generation(4);
        host.apply(true).await;
        assert!(host.proxy.is_some());
        assert!(!host.cleanup_unconfirmed);
        assert!(host.finish_stop().await);
    }

    #[tokio::test]
    async fn canceled_recovery_still_drains_without_erasing_prior_uncertainty() {
        let home = tempfile::tempdir().unwrap();
        let owner = embed::start(home.path(), Some(0)).await.unwrap();
        let retry_home = home.path().to_path_buf();
        let (release, pending) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            pending.await.unwrap();
            embed::start(&retry_home, Some(0)).await
        });
        let mut host =
            PrivateInference::with_pending_start_for_test(home.path().to_path_buf(), task);
        host.cleanup_unconfirmed = true;
        host.recovery_requested = true;
        assert!(
            tokio::time::timeout(Duration::from_millis(25), host.apply(true))
                .await
                .is_err()
        );
        host.apply(false).await;
        assert!(host.stopping.is_some());
        release.send(()).unwrap();
        assert!(!host.finish_stop().await);
        assert!(host.cleanup_unconfirmed);
        assert_eq!(host.state().label(), LABEL_CRASHED);
        owner.shutdown().await;
    }

    #[tokio::test]
    async fn failed_start_join_is_unknown_until_explicit_retry() {
        let home = tempfile::tempdir().unwrap();
        let absent = home.path().join("not-created");
        let task = tokio::spawn(async { panic!("controlled start panic") });
        let mut host = PrivateInference::with_pending_start_for_test(absent.clone(), task);
        host.accept_generation(0);
        host.apply(true).await;
        assert_eq!(host.state().label(), LABEL_CRASHED);
        host.apply(false).await;
        host.apply(true).await;
        assert!(host.cleanup_unconfirmed);
        assert!(!absent.exists());
    }

    #[test]
    fn discovery_pointer_is_bounded_and_accepts_only_plain_loopback_roots() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("endpoint.json");
        for url in [
            "https://127.0.0.1:1234",
            "http://example.com:1234",
            "http://user:secret@127.0.0.1:1234",
            "http://127.0.0.1:1234/path",
            "http://127.0.0.1:1234?query",
            "http://127.0.0.1:1234#fragment",
            "http://127.0.0.1:0",
            "http://[::1]:1234",
        ] {
            std::fs::write(&path, serde_json::json!({"control_url":url}).to_string()).unwrap();
            assert_eq!(pointed_port(home.path()), None, "{url}");
        }
        for url in ["http://127.0.0.1:1234", "http://localhost:1234/"] {
            std::fs::write(&path, serde_json::json!({"control_url":url}).to_string()).unwrap();
            assert_eq!(pointed_port(home.path()), Some(1234));
        }
        let mut bounded = br#"{"control_url":"http://127.0.0.1:1234"}"#.to_vec();
        bounded.resize(MAX_POINTER_BYTES as usize, b' ');
        std::fs::write(&path, &bounded).unwrap();
        assert_eq!(pointed_port(home.path()), Some(1234));
        bounded.push(b' ');
        std::fs::write(&path, &bounded).unwrap();
        assert_eq!(pointed_port(home.path()), None);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(pointed_port(home.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn discovery_pointer_refuses_symlinks_and_other_writers() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("endpoint.json");
        let target = home.path().join("real.json");
        std::fs::write(&target, r#"{"control_url":"http://127.0.0.1:1234"}"#).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(pointed_port(home.path()), None);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&target, &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(pointed_port(home.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn checked_pointer_cannot_be_replaced_by_a_symlink_or_another_inode() {
        let home = tempfile::tempdir().unwrap();
        write_pointer(home.path(), 1234);
        let path = home.path().join("endpoint.json");
        let checked = super::super::ironwire_pointer::trustworthy_file(&path).unwrap();
        let original = home.path().join("original.json");
        std::fs::rename(&path, &original).unwrap();
        std::os::unix::fs::symlink(&original, &path).unwrap();
        // Same original inode behind a symlink: identity checks alone would
        // accept it, so this specifically exercises no-follow opening.
        assert!(open_checked_pointer(&path, &checked).is_none());
        std::fs::remove_file(&path).unwrap();
        write_pointer(home.path(), 4321);
        assert!(open_checked_pointer(&path, &checked).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn checked_pointer_fifo_swap_is_refused_without_waiting_for_a_writer() {
        let home = tempfile::tempdir().unwrap();
        write_pointer(home.path(), 1234);
        let path = home.path().join("endpoint.json");
        let checked = super::super::ironwire_pointer::trustworthy_file(&path).unwrap();
        std::fs::rename(&path, home.path().join("original.json")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let open_path = path.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let opener = std::thread::spawn(move || {
            sent.send(open_checked_pointer(&open_path, &checked).is_none())
                .unwrap();
        });
        let immediate = received.recv_timeout(Duration::from_secs(1));
        if immediate.is_err() {
            // A broken blocking-open implementation must fail the test,
            // not hang the suite: pair its FIFO reader with a writer.
            use std::os::unix::fs::OpenOptionsExt;
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while !opener.is_finished() && std::time::Instant::now() < deadline {
                // Nonblocking even if the reader was merely delayed and has
                // already finished: cleanup must not introduce its own hang.
                if let Ok(writer) = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(pointer_open_flags().expect("supported pointer open flags"))
                    .open(&path)
                {
                    drop(writer);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = received.recv_timeout(Duration::from_secs(1));
        }
        if opener.is_finished() {
            opener.join().unwrap();
        }
        assert_eq!(
            immediate.ok(),
            Some(true),
            "FIFO swap blocked or was accepted"
        );
    }

    #[tokio::test]
    async fn discovery_probe_never_follows_a_health_redirect() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&hits);
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_task = tokio::spawn(async move {
            axum::serve(
                target,
                axum::Router::new().fallback(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    async { axum::http::StatusCode::OK }
                }),
            )
            .await
            .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(move || async move {
                    (
                        axum::http::StatusCode::FOUND,
                        [(
                            axum::http::header::LOCATION,
                            format!("http://127.0.0.1:{target_port}/outside"),
                        )],
                    )
                }),
            )
            .await
            .unwrap();
        });
        let home = tempfile::tempdir().unwrap();
        write_pointer(home.path(), port);
        assert_eq!(existing_instance(home.path()).await, None);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        task.abort();
        target_task.abort();
    }

    #[test]
    fn discovery_probe_ignores_environment_proxy_in_isolated_process() {
        const CHILD: &str = "TC_PRIVATE_PROBE_CHILD_HOME";
        if let Some(home) = std::env::var_os(CHILD) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            assert!(
                runtime
                    .block_on(existing_instance(Path::new(&home)))
                    .is_some()
            );
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        write_pointer(home.path(), listener.local_addr().unwrap().port());
        // The child, not a clock, decides when waiting is pointless.
        //
        // This loop used to stop after a hard ten seconds measured from before
        // the child was even spawned, so the budget covered process creation,
        // the Windows loader, libtest startup over ~1700 test names and the
        // tokio runtime build -- and only its last two seconds covered the
        // probe being measured. On a loaded windows-latest runner the setup
        // consumed it, the listener was dropped while the child was still
        // starting, and the child's probe was then refused by a socket that no
        // longer existed. The test could not tell its own timeout apart from
        // the regression it exists to catch, and reported the regression. See
        // #780.
        //
        // Waiting for the child instead is bounded without being timed: the
        // child's probe carries PROBE_TIMEOUT, so it always exits. A slow
        // runner keeps it alive and cannot fail this test; a child that reached
        // a proxy instead of loopback gets an immediate refusal from
        // 127.0.0.1:1, exits, and ends the wait at once. Nothing here needs to
        // guess how long a runner takes to start a process.
        //
        // Note this removes no protection against a child that hangs forever:
        // the parent's wait below is unbounded and always was, so the old
        // deadline never bounded the suite's runtime. It only decided when to
        // stop listening, which is the whole defect.
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child_finished = std::sync::Arc::clone(&finished);
        let responder = std::thread::spawn(move || {
            use std::io::Write;
            let answer = |listener: &std::net::TcpListener| match listener.accept() {
                Ok((mut stream, _)) => {
                    // A socket accepted from a non-blocking listener inherits
                    // O_NONBLOCK on macOS and the BSDs. That made the read
                    // timeout below inert and the read return WouldBlock the
                    // instant the connection completed -- which is at the
                    // handshake, before the child has put its GET on the wire.
                    // Answering there and returning dropped the stream and
                    // closed the connection under a request still being sent,
                    // so the child's send() failed, existing_instance returned
                    // None, and the test reported the regression it exists to
                    // catch. Under load the child is slower to write and the
                    // window widens. Blocking mode makes the timeout real, so
                    // the request is waited for rather than raced. See #780.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    // Answer a whole request head, not whatever happens to
                    // have arrived: a partial read is the same race one buffer
                    // further along.
                    let mut request = Vec::new();
                    let mut chunk = [0; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => request.extend_from_slice(&chunk[..read]),
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    true
                }
                Err(_) => false,
            };
            loop {
                if answer(&listener) {
                    return true;
                }
                if child_finished.load(std::sync::atomic::Ordering::SeqCst) {
                    // The kernel keeps a completed connection in the backlog
                    // after its peer is gone, so the last poll has to happen
                    // after the exit is observed rather than before it.
                    return answer(&listener);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "daemon::private_inference::tests::discovery_probe_ignores_environment_proxy_in_isolated_process", "--nocapture"])
            .env(CHILD, home.path())
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.wait_with_output().unwrap();
        finished.store(true, std::sync::atomic::Ordering::SeqCst);
        let answered = responder.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            answered,
            "the direct loopback service must receive the health request"
        );
    }

    /// The pointer IronWire publishes in its home, as a test writes it.
    fn write_pointer(home: &Path, port: u16) {
        let body = serde_json::json!({
            "control_url": format!("http://127.0.0.1:{port}"),
            "token_path": home.join("control.token"),
        });
        std::fs::write(home.join("endpoint.json"), body.to_string()).expect("a pointer");
    }

    /// Off is the default and starting nothing is not a failure. A daemon
    /// that has never been asked for private inference reports `Off`, not
    /// an error, and binds no port.
    #[tokio::test]
    async fn the_switch_is_off_until_asked() {
        let home = tempfile::tempdir().expect("a temp home");
        let mut host = PrivateInference::new(home.path().to_path_buf());
        assert_eq!(host.state(), PrivateInferenceState::Off);
        host.apply(false).await;
        assert!(host.finish_stop().await);
        assert_eq!(host.state(), PrivateInferenceState::Off);
    }

    /// Turning it on binds, serves, and reports the bound port; turning it
    /// off releases it. The port is ephemeral so this cannot collide with a
    /// developer's own IronWire.
    #[tokio::test]
    async fn turning_it_on_serves_and_turning_it_off_releases() {
        let home = tempfile::tempdir().expect("a temp home");
        let mut host = PrivateInference::with_port(home.path().to_path_buf(), 0);

        host.apply(true).await;
        let port = match host.state() {
            PrivateInferenceState::Running { port } => port,
            other => panic!("expected Running, got {other:?}"),
        };
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap();
        let health = http
            .get(format!("http://127.0.0.1:{port}/_ironwire/health"))
            .send()
            .await
            .unwrap();
        assert!(health.status().is_success());
        health.bytes().await.unwrap();
        drop(http);
        // Close the fixture's client connection before stopping the listener.
        // Otherwise Windows may keep the accepted socket's port in TIME_WAIT
        // even after the owner correctly joins and drops its listener.
        #[cfg(windows)]
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        #[cfg(not(windows))]
        tokio::task::yield_now().await;

        host.apply(false).await;
        assert!(host.finish_stop().await);
        assert_eq!(host.state(), PrivateInferenceState::Off);
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_ok(),
            "turning it off must release the port"
        );
    }

    /// A proxy that came up with an empty registry serves health and routes
    /// nothing, so it must not be reported as `Running`. Sub-project C
    /// renders this state, and rendering it green is the failure this
    /// distinction exists to prevent.
    /// Only the running state splits, and the unknown case must not borrow
    /// the plain running label.
    #[test]
    fn the_destination_only_splits_the_running_state() {
        let running = PrivateInferenceState::Running { port: 8463 };
        assert_eq!(running.label_for(Some(true)), LABEL_RUNNING);
        assert_eq!(
            running.label_for(Some(false)),
            LABEL_RUNNING_ANSWERED_ELSEWHERE
        );
        assert_eq!(
            running.label_for(None),
            LABEL_RUNNING_DESTINATION_UNKNOWN,
            "an unread destination must not be reported as the plain running state"
        );

        // Every other state ignores the question entirely.
        for state in [
            PrivateInferenceState::Off,
            PrivateInferenceState::Stopping { port: None },
            PrivateInferenceState::RunningWithoutBackends { port: 1 },
            PrivateInferenceState::RunningElsewhere { port: 1 },
        ] {
            for answer in [Some(true), Some(false), None] {
                assert_eq!(
                    state.label_for(answer),
                    state.label(),
                    "{:?} must not vary with the destination",
                    state.label()
                );
            }
        }
    }

    #[test]
    fn a_proxy_with_no_backends_is_not_reported_as_running() {
        assert_eq!(
            state_after_start(8463, true),
            PrivateInferenceState::RunningWithoutBackends { port: 8463 }
        );
        assert_eq!(
            state_after_start(8463, false),
            PrivateInferenceState::Running { port: 8463 }
        );
    }

    /// An IronWire this daemon did not start is left alone. The state says
    /// so, nothing is bound, and the other process keeps running -- a
    /// contributor's own proxy is not something to fight for a port.
    #[tokio::test]
    async fn someone_elses_ironwire_is_not_replaced() {
        let home = tempfile::tempdir().expect("a temp home");
        let theirs = ironwire_proxy::embed::start(home.path(), Some(0))
            .await
            .expect("their proxy starts");
        let port = theirs.port();
        write_pointer(home.path(), port);

        let mut host = PrivateInference::with_port(home.path().to_path_buf(), port);
        host.apply(true).await;

        assert_eq!(
            host.state(),
            PrivateInferenceState::RunningElsewhere { port }
        );
        assert!(
            reqwest::get(format!("http://127.0.0.1:{port}/_ironwire/health"))
                .await
                .is_ok_and(|r| r.status().is_success()),
            "their proxy must still be serving"
        );

        theirs.shutdown().await;
    }

    /// A pointer left behind by an IronWire that is gone must not stop this
    /// daemon from starting its own.
    ///
    /// The pointer file outlives the process that wrote it whenever that
    /// process was killed rather than shut down, so a daemon that treated
    /// any pointer as proof of a live owner would refuse forever, on a
    /// machine where nothing is running, until someone found and deleted a
    /// file they were never told about. The probe is what separates the two,
    /// and this is the branch that says so.
    #[tokio::test]
    async fn a_pointer_to_a_dead_port_does_not_stop_a_start() {
        let home = tempfile::tempdir().expect("a temp home");

        // A port that is definitely not answering: bind it, read the number
        // back, then drop the listener.
        let dead = {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("a port to abandon");
            listener.local_addr().unwrap().port()
        };
        write_pointer(home.path(), dead);

        let mut host = PrivateInference::with_port(home.path().to_path_buf(), 0);
        host.apply(true).await;

        let port = match host.state() {
            PrivateInferenceState::Running { port } => port,
            other => panic!("a stale pointer must not block a start, got {other:?}"),
        };
        assert_ne!(port, dead, "the start must have bound its own port");
        assert!(
            reqwest::get(format!("http://127.0.0.1:{port}/_ironwire/health"))
                .await
                .is_ok_and(|r| r.status().is_success())
        );

        host.apply(false).await;
    }

    /// An IronWire owning the home with no pointer to find is still
    /// `running_elsewhere`, not a failure.
    ///
    /// The pointer probe is advisory: it can be missing, stale, or not yet
    /// written by an owner still starting up. When it misses, the home lock
    /// is what answers, and `EmbedError::Lock` means exactly what the probe
    /// would have said -- another IronWire owns this home. Reporting that as
    /// a failed start would tell a contributor their proxy is broken when
    /// the truth is that theirs is already running.
    #[tokio::test]
    async fn a_locked_home_with_no_pointer_is_still_running_elsewhere() {
        let home = tempfile::tempdir().expect("a temp home");
        let theirs = ironwire_proxy::embed::start(home.path(), Some(0))
            .await
            .expect("their proxy starts");

        // Whatever pointer their start published, take it away: this is the
        // case where discovery has nothing to offer and only the home lock
        // knows.
        let _ = std::fs::remove_file(home.path().join("endpoint.json"));

        let mut host = PrivateInference::with_port(home.path().to_path_buf(), 0);
        host.apply(true).await;

        assert!(
            matches!(host.state(), PrivateInferenceState::RunningElsewhere { .. }),
            "a locked home is someone else's proxy, got {:?}",
            host.state()
        );

        theirs.shutdown().await;
    }

    /// A port held by something that is not IronWire is a refusal by name,
    /// not a panic and not a silent Off.
    #[tokio::test]
    async fn a_port_held_by_a_stranger_is_a_named_refusal() {
        let home = tempfile::tempdir().expect("a temp home");
        let squatter = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a squatter binds");
        let port = squatter.local_addr().unwrap().port();

        let mut host = PrivateInference::with_port(home.path().to_path_buf(), port);
        host.apply(true).await;

        assert_eq!(
            host.state(),
            PrivateInferenceState::Failed {
                label: LABEL_PORT_IN_USE
            }
        );
    }

    /// Every unrequested exit is the same fact to a contributor: the proxy
    /// they asked for is not there. A quiet `Ok` is no better news than an
    /// error, so all three map to one label.
    #[test]
    fn an_unrequested_exit_is_always_crashed() {
        for exit in [Ok(()), Err(ExitError::Server), Err(ExitError::Task)] {
            assert_eq!(
                state_after_unrequested_exit(exit),
                PrivateInferenceState::Failed {
                    label: LABEL_CRASHED
                }
            );
        }
    }

    /// The wire labels are distinct, so a shell matching on one cannot
    /// silently render another.
    #[test]
    fn every_state_has_its_own_label() {
        let states = [
            PrivateInferenceState::Off,
            PrivateInferenceState::Stopping { port: Some(1) },
            PrivateInferenceState::Running { port: 1 },
            PrivateInferenceState::RunningWithoutBackends { port: 1 },
            PrivateInferenceState::RunningElsewhere { port: 1 },
            PrivateInferenceState::Failed {
                label: LABEL_PORT_IN_USE,
            },
            PrivateInferenceState::Failed {
                label: LABEL_START_FAILED,
            },
            PrivateInferenceState::Failed {
                label: LABEL_CRASHED,
            },
        ];
        let mut labels: Vec<&str> = states.iter().map(PrivateInferenceState::label).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);
    }
}
