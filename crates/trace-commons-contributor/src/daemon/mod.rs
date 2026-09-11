//! The background upload daemon.
//!
//! The daemon watches the local coding-agent session roots, decides which
//! sessions are finished and uploadable, tells the contributor about them,
//! uploads the ones they approve, and auto-uploads the projects they have
//! explicitly opted in. It serves a versioned IPC contract so native tray and
//! window applications can drive all of that without reimplementing any of it.
//!
//! Every upload takes the same path an interactive `submit` takes, via
//! `submit::SubmitContext`. There is no second pipeline.
//!
//! Privacy posture, which the rest of this module tree is built to preserve:
//!
//! - A local filesystem path appears only in `daemon-queue.jsonl` and
//!   `daemon-state.json`. It never reaches a receipt, a history record, a log
//!   line, or the wire. Consumers get `project_label`.
//! - Nothing is uploaded from a project the contributor has not opted in, and
//!   sessions whose working directory cannot be resolved can never be opted in
//!   at all.
//! - A configured privacy filter that is unavailable stops the pipeline. It
//!   never degrades to sending unfiltered text.

pub mod account_onboarding;
pub mod admission_setup;
pub mod approved_envelope;
pub mod attestation_mark;
pub mod audit;
pub mod client;
pub(crate) mod cloud_credential_lifecycle;
#[cfg(test)]
mod cloud_credential_lifecycle_tests;
#[cfg(test)]
pub(crate) mod cloud_credential_test_support;
pub mod community;
pub mod contribution_eligibility;
pub(crate) mod credential_store;
pub mod eligibility;
pub mod enroll;
pub mod harness;
pub mod health;
pub mod history;
pub mod install;
pub mod ipc;
pub mod ironwire_pointer;
pub mod native_flow;
pub mod nearai_credential;
pub mod nearai_onboarding;
pub mod notify;
pub(crate) mod os_secret_store;
pub mod policy;
pub mod preview;
pub mod preview_scheduler;
pub mod private_inference;
pub mod profile;
pub mod project_key;
pub mod queue;
pub mod settings;
pub mod state;
pub mod stored_cloud_credentials;
#[cfg(test)]
pub(crate) mod test_paths;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod token_capture;
mod token_cleanup;
pub mod uploader;
pub mod watcher;
#[cfg(windows)]
pub mod win_pipe;
pub mod withdraw;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::config::{ConfigStore, DAEMON_LOCK_FILE, DAEMON_SOCK_FILE};

/// Why a daemon start did not succeed, as a fact the caller can act on.
///
/// `start_embedded` attaches one of these to the error it returns, so a
/// caller can tell the cases apart by `downcast_ref` rather than by matching
/// on prose. That matters most across the C ABI: `trace-commons-contributor-
/// ffi` maps each variant to a fixed label, and the alternative -- string
/// matching on `anyhow` text -- would break silently the first time someone
/// improved the wording.
///
/// The variants are deliberately coarse. Each one exists because a
/// contributor facing it has a *different next action*; a distinction that
/// does not change what somebody should do belongs in the error's context
/// chain, which is where the operator-facing detail already lives.
///
/// These carry no payload on purpose. The underlying `anyhow` errors embed
/// state-directory and lock-file paths for local stderr and journals, and the
/// FFI must be able to name the failure without carrying any of that across
/// the boundary. See that crate's module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFailure {
    /// Another daemon already holds the lock for this state directory.
    AlreadyRunning,
    /// The state directory could not be written -- the lock file itself could
    /// not be created or opened.
    StateDirectoryNotWritable,
    /// `daemon-settings.json` exists but this version cannot parse it.
    SettingsUnreadable,
    /// The control socket (or Windows named pipe) could not be bound. The
    /// usual cause is a state-directory path whose socket path exceeds the
    /// platform limit, or a stale socket file.
    IpcBindFailed,
}

impl std::fmt::Display for StartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::AlreadyRunning => {
                "another trace-commons-contributor daemon is already running for this state directory"
            }
            Self::StateDirectoryNotWritable => "the state directory could not be written",
            Self::SettingsUnreadable => "the daemon settings file could not be read",
            Self::IpcBindFailed => "the daemon control socket could not be bound",
        };
        f.write_str(text)
    }
}

impl std::error::Error for StartFailure {}

/// Run the daemon in the foreground. A service manager, or the contributor's
/// own terminal, is what puts it in the background.
///
/// Holds an exclusive lock for its whole life, so a second daemon against the
/// same state directory fails loudly instead of two of them racing over the
/// same queue.
///
/// `run_supervisor` is awaited *inline* here (not spawned and then joined)
/// on purpose: if this async fn's own future is itself dropped before
/// completion -- the ordinary way a caller races the daemon against, say, a
/// ctrl-C future in a `tokio::select!` -- Rust's structured-concurrency
/// cancellation stops the supervise loop's execution immediately, as part of
/// dropping this same stack frame, before `lock` (the file backing
/// `daemon.lock`) is also dropped and the lock released. An earlier version
/// of this function spawned the supervise loop as an independent task and
/// awaited its `JoinHandle` instead; `JoinHandle::drop` does not abort the
/// task, so dropping `run`'s future left the supervisor detached and still
/// mutating the queue after the lock had already been released to a second
/// daemon -- exactly the corruption `daemon.lock` exists to prevent. See
/// `EmbeddedDaemon`'s and `run_supervisor`'s docs for the embedding case
/// that still needs the loop to run as a background task.
pub async fn run(store: ConfigStore, dry_run: bool) -> Result<()> {
    let embedded = start_embedded(store).await?;
    let result = run_supervisor(Arc::clone(&embedded.shared), dry_run).await;
    embedded.close();
    result
}

struct PrivateInferenceShutdown(std::sync::Weak<ipc::DaemonShared>);

impl Drop for PrivateInferenceShutdown {
    fn drop(&mut self) {
        if let Some(shared) = self.0.upgrade() {
            shared.request_private_inference_stop();
        }
    }
}

/// The pieces of a running daemon that a caller needing direct, in-process
/// access to `shared` -- rather than only running the loop to completion the
/// way `run` does -- holds onto.
///
/// This is what `trace-commons-contributor-ffi` embeds: the C ABI's
/// `tc_daemon_start` calls `start_embedded` instead of `run` so it gets back
/// the same `Arc<DaemonShared>` the loop is mutating, for `tc_call` and
/// `tc_preview_open` to act on directly via `ipc::handle_local` /
/// `ipc::open_preview` -- not a second, independently-loaded, and therefore
/// divergent, view of the on-disk state.
///
/// Deliberately does **not** itself run the supervise loop (the periodic
/// watch/upload/digest/history pass): `run` awaits `run_supervisor` inline
/// for cancel-safety (see its doc). An embedder that needs the loop running
/// in the background, independent of any one call's lifetime, spawns
/// `run_supervisor` itself and keeps the resulting `JoinHandle` for its own
/// explicit shutdown.
pub struct EmbeddedDaemon {
    // Drop this before the last shared Arc, even if no server task remains.
    private_inference_shutdown: PrivateInferenceShutdown,
    pub shared: Arc<ipc::DaemonShared>,
    lock_path: std::path::PathBuf,
    lock: std::fs::File,
    server: tokio::task::JoinHandle<Result<()>>,
    /// The bounded preview pool. Started here rather than inside
    /// `DaemonShared` because each worker holds an `Arc<DaemonShared>`
    /// through its runner, and a pool the shared state owned would keep
    /// that state alive for the life of the process.
    preview_workers: Vec<tokio::task::JoinHandle<()>>,
}

impl EmbeddedDaemon {
    /// Stop serving the socket and release the exclusive lock. Requests
    /// terminal proxy cleanup, which may continue while the runtime lives.
    /// Does *not*
    /// touch `shared.shutdown` or stop anything running the supervise loop
    /// -- `EmbeddedDaemon` no longer owns that task (see the struct doc), so
    /// a caller that spawned `run_supervisor` itself is responsible for
    /// signalling and awaiting it before (or after; order does not matter
    /// for correctness, only for how long the loop keeps working past the
    /// request) calling this.
    pub fn close(self) {
        drop(self.private_inference_shutdown);
        self.server.abort();
        // Ask the pool to stop first, so a worker between jobs exits on its
        // own; abort then covers the one that is mid-build, which cannot be
        // interrupted at a finer grain than the task (see
        // `preview_scheduler::PreviewScheduler::cancel`).
        self.shared.previews.stop();
        for worker in self.preview_workers {
            worker.abort();
        }
        let _ = self.shared.store.remove_daemon_file(DAEMON_SOCK_FILE);
        drop(self.lock);
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Take the daemon's exclusive lock, build the shared state, and bind and
/// spawn the socket server -- everything `run` does before it starts the
/// supervise loop, returned as pieces instead of run to completion.
///
/// Locking happens exactly once per call, the same as `run` used to: this
/// function (not `run`) is now the one place that takes `daemon.lock`, so a
/// second `start_embedded` -- or a second `run` -- against the same state
/// directory still fails loudly on the `try_lock`, whether or not the caller
/// is the same process. That failure, and every other one here, carries a
/// [`StartFailure`] the caller can `downcast_ref` -- so distinguishing "lock
/// held by another daemon" from a state-directory permissions problem or a
/// socket bind failure is a type match rather than a search through prose
/// that any later rewording would break.
///
/// The lock file does not outlive a failed start. `close` unlinks it on clean
/// shutdown, so its presence means "a daemon is running here"; leaving it
/// behind on a failure that never reached a running daemon states something
/// false to every other reader. The one exception is a start that lost the
/// `try_lock`: that file belongs to the daemon holding it, and this function
/// must not touch it.
pub async fn start_embedded(store: ConfigStore) -> Result<EmbeddedDaemon> {
    let lock_path = store.daemon_path(DAEMON_LOCK_FILE);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        // A fixed label, not `format!("opening {}", path.display())`: this
        // error reaches a service-manager journal, and the state-directory
        // path there carries the OS username. The caller already knows
        // which state directory it asked for.
        .open(&lock_path)
        .context("opening the daemon lock file in the state directory")
        .context(StartFailure::StateDirectoryNotWritable)?;
    if lock.try_lock().is_err() {
        // Return before the cleanup scope below is entered. The lock file
        // belongs to the daemon that holds it, and a loser that unlinked it
        // would hand the next starter a false all-clear against a daemon
        // still serving the socket.
        return Err(anyhow::Error::new(StartFailure::AlreadyRunning));
    }

    // A verified update parked by an earlier check is applied here, at the
    // daemon's natural start, rather than swapped underneath a running
    // process. The binary this process is executing is unaffected -- on unix
    // it holds the old inode, and on Windows the old image is renamed aside
    // -- so the new code runs from the following start. `trace-commons-
    // contributor update` is the path for applying one immediately.
    //
    // Failures here are never fatal to starting the daemon: not updating is
    // always better than not running. The label is fixed, and no path is
    // logged.
    if let Ok(exe) = std::env::current_exe() {
        match crate::update::run::apply_staged(&exe) {
            Ok(Some(_version)) => {
                tracing::info!("applied a staged update; it takes effect at the next start");
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(reason = %e, "staged update was refused"),
        }
    }

    // Everything past the lock runs inside this block so that any failure
    // can release the lock and unlink the file on the way out.
    //
    // `close` removes the lock file on clean shutdown, which makes its
    // presence the thing every other reader treats as "a daemon is running
    // here". A failed start that left the file behind would be asserting
    // something untrue -- and it did: during this project's own development
    // a zero-byte `daemon.lock` from a failed start was read as proof the
    // daemon had started, and produced a confident wrong diagnosis.
    let started = async {
        let shared =
            Arc::new(tokio::task::spawn_blocking(move || ipc::DaemonShared::load(store)).await??);
        // Claim this runtime for anything the daemon hosts that outlives one
        // request. This block is `async` and runs on the real daemon runtime
        // in both entry points, which is the whole reason the call belongs
        // here rather than in `load` -- `load` is synchronous and has callers
        // that are inside no runtime at all. Without this a proxy started
        // through the synchronous IPC path would be spawned onto the
        // throwaway runtime that path builds, and would die with it.
        shared.adopt_runtime();
        // The two transports are the same protocol over different plumbing: a
        // unix socket guarded by its 0700 state directory, or a Windows named
        // pipe guarded by its DACL. See `win_pipe` for why the Windows side
        // carries the whole access control itself.
        #[cfg(unix)]
        let listener = ipc::bind(&shared.store)
            .await
            .context(StartFailure::IpcBindFailed)?;
        #[cfg(windows)]
        let listener = win_pipe::bind(&shared.store)
            .await
            .context(StartFailure::IpcBindFailed)?;

        // The preview pool. Two workers, started before the socket is
        // served, so the first `preview_request` a shell sends never finds
        // an empty pool.
        let preview_runner: Arc<dyn preview_scheduler::PreviewJobRunner> = Arc::new(
            preview_scheduler::DaemonPreviewRunner::new(Arc::clone(&shared)),
        );
        let preview_workers =
            preview_scheduler::spawn_workers(Arc::clone(&shared.previews), preview_runner);

        let serve_shared = Arc::clone(&shared);
        #[cfg(unix)]
        let server = tokio::spawn(async move { ipc::serve(listener, serve_shared).await });
        #[cfg(windows)]
        let server = tokio::spawn(async move { win_pipe::serve(listener, serve_shared).await });

        Ok::<_, anyhow::Error>((shared, server, preview_workers))
    }
    .await;

    match started {
        Ok((shared, server, preview_workers)) => Ok(EmbeddedDaemon {
            private_inference_shutdown: PrivateInferenceShutdown(Arc::downgrade(&shared)),
            shared,
            lock_path,
            lock,
            server,
            preview_workers,
        }),
        Err(e) => {
            // Release before unlinking, so the lock is genuinely available to
            // the next start rather than only appearing to be: a stranded
            // advisory lock on an unlinked inode would present as contention
            // with a daemon that does not exist.
            drop(lock);
            let _ = std::fs::remove_file(&lock_path);
            Err(e)
        }
    }
}

/// Run the periodic watch/upload/digest/history pass to completion -- i.e.,
/// until `shared`'s shutdown flag or signal fires. This is `supervise`,
/// exposed under a stable name so a caller holding only an
/// `Arc<DaemonShared>` (`supervise` itself is private) can run it -- either
/// awaited inline, as `run` does for cancel-safety, or `tokio::spawn`ed as
/// its own background task by an embedder that needs the loop running
/// independent of any one call's lifetime (see `EmbeddedDaemon`'s doc).
pub async fn run_supervisor(shared: Arc<ipc::DaemonShared>, dry_run: bool) -> Result<()> {
    supervise(shared, dry_run).await
}

/// Run `f` -- blocking, non-yielding work with no `.await` of its own
/// (filesystem scanning, hashing, reading a receipts file) -- off whichever
/// worker is currently executing this task, via `tokio::task::
/// block_in_place`, when the current runtime is multi-thread. That is the
/// only flavor `block_in_place` supports (it panics under
/// `current_thread`, the default `#[tokio::test]` flavor most of this
/// crate's async tests use, so `f` just runs inline there instead -- the
/// same as it always did) and the only one where running `f` off-worker
/// actually matters: on a `current_thread` runtime there is only ever one
/// worker regardless.
///
/// Without this, blocking work called from inside an async task can
/// monopolize a runtime's sole worker thread for its entire duration,
/// starving every other task -- the socket server, `tc_subscribe`
/// delivery, even a reentrant `tc_daemon_stop`'s own wait on the
/// supervisor's `JoinHandle`. First found in `watcher::tick`'s session-root
/// scan; `drain_approved`'s `find_session` re-scan and `refresh_history`'s
/// receipts read go through this too, for the same reason -- see each call
/// site.
pub(crate) fn run_blocking<R>(f: impl FnOnce() -> R) -> R {
    let multi_thread = tokio::runtime::Handle::try_current()
        .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        .unwrap_or(false);
    if multi_thread {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

/// Run periodic work, then give owned proxy cleanup a five-second wait budget.
/// The retained drain task continues while the daemon runtime lives; the budget
/// includes waiting for any in-progress startup. Expiry does not claim Off.
///
/// A panic or dropped run future skips this awaited path. Closing or dropping
/// EmbeddedDaemon requests terminal cleanup as a backstop. Runtime/process
/// destruction can interrupt pending streams; neither path promises complete
/// drainage after the host runtime has gone away.
async fn supervise(shared: Arc<ipc::DaemonShared>, dry_run: bool) -> Result<()> {
    shared.reconcile_private_inference().await;
    let result = supervise_passes(&shared, dry_run).await;
    shared.stop_private_inference().await;
    result
}

/// The periodic work: watch, expire, and decide about digests, until asked to
/// stop.
async fn supervise_passes(shared: &Arc<ipc::DaemonShared>, dry_run: bool) -> Result<()> {
    let poll_interval = {
        let s = shared.settings.lock().expect("settings lock");
        std::time::Duration::from_secs(s.poll_interval_secs.max(1))
    };
    let mut ticker = tokio::time::interval(poll_interval);
    let mut proxy_cleanup_tick = tokio::time::interval(std::time::Duration::from_millis(100));
    proxy_cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut token_cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(300));
    token_cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut token_cleanup_tasks = tokio::task::JoinSet::new();
    let mut sigterm = signal_stream();
    let shutdown_signal = Arc::clone(&shared.shutdown_signal);

    loop {
        // Checked at the top as well as after the select, so a request that
        // arrived while the previous pass was still working is acted on
        // immediately rather than waiting out another poll interval.
        if shared.shutdown.load(Ordering::Relaxed) {
            tracing::info!("daemon stopping on request");
            return Ok(());
        }
        tokio::select! {
            _ = shutdown_signal.notified() => {
                tracing::info!("daemon stopping on request");
                return Ok(());
            }
            _ = shared.private_inference_changed.notified() => {
                shared.reconcile_private_inference().await;
            }
            _ = proxy_cleanup_tick.tick(), if shared.private_inference_is_stopping() => {
                shared.reconcile_private_inference().await;
            }
            _ = token_cleanup_tick.tick(), if !dry_run && token_cleanup_tasks.is_empty() => {
                let shared = Arc::clone(shared);
                token_cleanup_tasks.spawn(async move {
                    if token_cleanup::pass(&shared).await.is_err() {
                        tracing::warn!(pass = "token-cleanup", "daemon pass failed");
                    }
                });
            }
            _ = token_cleanup_tasks.join_next(), if !token_cleanup_tasks.is_empty() => {}
            _ = ticker.tick() => {
                let now = Utc::now();
                // Ahead of `watcher::tick` so the sources it builds via
                // `source_roots_with_routing` see this pass's snapshot
                // rather than the previous one. A no-op when nothing was
                // declared; otherwise bounded by the ledger's own short
                // timeout, so this cannot stall the tick.
                shared.refresh_routing().await;
                // Applies a switch a client set over a transport that does
                // not reach `handle_request_async` (the C ABI's pre-start
                // settings override writes the file directly), and notices
                // a proxy that ended on its own. Cheap when there is
                // nothing to do, which is the ordinary case.
                shared.reconcile_private_inference().await;
                // Fixed labels, never `error = %e`. These errors are
                // `anyhow::Error`s whose outermost context routinely embeds
                // a filesystem path -- `write_atomic_0600`'s "creating temp
                // file <dir>/...", `ConfigStore::open`'s state-directory
                // context, `load_receipts`' "reading <path>". Under a
                // service manager these land in the journal, where the path
                // carries the OS username. The condition worth logging is
                // *which pass* failed, and health carries the rest.
                if watcher::tick(shared, now).await.is_err() {
                    tracing::warn!(pass = "watch", "daemon pass failed");
                }
                expire_and_digest(shared, now);
                // Everything above is read-only bookkeeping; uploading is
                // what dry-run withholds.
                if !dry_run {
                    if let Err(e) = drain_approved(shared, now).await {
                        // The one detail that is safe and load-bearing: a
                        // fail-closed precondition is a fixed label by
                        // construction (`SubmitPreconditionFailure`), and
                        // it is what suspends queue expiry.
                        tracing::warn!(
                            pass = "upload",
                            reason = uploader::precondition_health_label(&e),
                            "daemon pass failed"
                        );
                    }
                    if refresh_history(shared, now).await.is_err() {
                        tracing::warn!(pass = "history", "daemon pass failed");
                    }
                    if refresh_community(shared, now).await.is_err() {
                        tracing::warn!(pass = "community", "daemon pass failed");
                    }
                }
            }
            _ = &mut sigterm => {
                tracing::info!("daemon stopping on signal");
                return Ok(());
            }
        }
        if shared.shutdown.load(Ordering::Relaxed) {
            tracing::info!("daemon stopping on request");
            return Ok(());
        }
    }
}

/// Upload everything that has been approved, whether by the contributor or by
/// their standing opt-in for the project.
///
/// One `SubmitContext` covers the whole pass, so the claim is minted once and
/// the privacy-filter canary runs once, exactly as an interactive `submit`
/// batch does.
async fn drain_approved(shared: &Arc<ipc::DaemonShared>, now: chrono::DateTime<Utc>) -> Result<()> {
    // Pause used to be checked only inside `watcher::tick`, so a pause
    // stopped *discovery* and nothing else: everything already `Approved`
    // -- including everything an armed project had auto-approved before the
    // pause -- kept uploading while `status` said paused. Pause has to mean
    // "nothing leaves this machine", or it means nothing.
    if shared.is_paused(now) {
        return Ok(());
    }
    // Quiesced for an update swap. Same gate as pause and for the same
    // reason -- this is the one place "nothing leaves this machine" is
    // enforced -- but a separate, in-memory flag, so an update never rewrites
    // the contributor's own persisted pause setting. See `DaemonShared::
    // quiesced`.
    if shared.quiesced.load(Ordering::Relaxed) {
        return Ok(());
    }

    // The post-approval hold. An entry approved a moment ago is skipped
    // until its hold elapses, so the undo a client offers after `approve`
    // is a real window rather than a race against this pass -- see
    // `queue::QueueEntry::approved_at`. It is deliberately a property of
    // the entry (`approved_at` + the configured hold) and not of this
    // loop's timing: tuning `poll_interval_secs`, or the uploader getting
    // faster, cannot shorten it.
    let approval_hold_secs = {
        let s = shared.settings.lock().expect("settings lock");
        s.approval_hold_secs
    };
    let approved: Vec<queue::QueueEntry> = {
        let q = shared.queue.lock().expect("queue lock");
        q.all()
            .iter()
            .filter(|e| {
                e.state == queue::QueueState::Approved && !e.hold_active(now, approval_hold_secs)
            })
            .cloned()
            .collect()
    };
    if approved.is_empty() {
        // Re-check enrollment when the queue is empty, so a stale not-logged-in
        // condition gets retracted if the contributor has logged back in.
        // This is sound: enrollment_is_live genuinely re-checks the condition.
        if uploader::enrollment_is_live(&shared.store) {
            let mut health = shared.health.lock().expect("health lock");
            health.resolve(health::LABEL_NOT_LOGGED_IN);
        }
        // Do NOT retract LABEL_CLAIM_MINT_FAILED or LABEL_INGEST_UNREACHABLE here.
        // The approved queue empties because upload entries move to Failed state when
        // uploads fail. Retracting those labels with no evidence would be dishonest:
        // ingest could still be down, and the HealthState.since field already tells
        // the consumer how old the information is. A label saying "last attempt failed
        // 3 hours ago" is accurate; one that silently says "now healthy" is not.
        return Ok(());
    }

    let Some(cfg) = shared.store.load_config()? else {
        let mut health = shared.health.lock().expect("health lock");
        health.fail(health::LABEL_NOT_LOGGED_IN, now);
        return Ok(());
    };
    let near_ai = {
        let s = shared.settings.lock().expect("settings lock");
        s.near_ai.clone()
    };
    let source_roots = shared.source_roots_with_routing();
    // These options are envelope-determining and are NOT covered by
    // `preview::input_fingerprint`, which fingerprints the config. They are
    // safe only because every one of them is a constant here.
    //
    // `no_reasoning` in particular: `submit_loaded` calls `strip_reasoning`
    // when it is set and `build_preview` never does, so the moment this
    // stops being a hardcoded `false` -- a daemon setting, a per-project
    // option -- a previewed entry and its upload describe different
    // content. A previewed entry would still be safe (its bytes are stored
    // and sent verbatim, so the preview would simply have shown reasoning
    // that then went out anyway), but an armed auto-upload entry would
    // silently change what it sends with nothing to notice. Whoever makes
    // it a setting must either fold it into `input_fingerprint` or make
    // `build_preview` honour it -- preferably both.
    let opts = crate::submit::SubmitOptions {
        dry_run: false,
        pii_filter: cfg.pii_filter.clone(),
        no_reasoning: false,
        machine_readable: true,
        unenrolled_preview: false,
        remediate_quarantined: false,
        // The daemon does not collect a verdict. Doing so belongs at approval
        // time, where the contributor is actually looking at the trace, and
        // that needs a queue field plus an `approve` parameter -- see the
        // note on `SubmitOptions` about this struct sitting outside the
        // approval fingerprint. Left for that change rather than guessed at.
        verdict: None,
    };
    // Both of these hit the filesystem synchronously with no `.await` of
    // their own -- `ConfigStore::open` creates/permissions the state dir,
    // `SubmitContext::new` reads the config and the receipts file -- so
    // they go off-worker for the same reason `watcher::tick`'s scan does.
    // See `run_blocking`'s doc.
    let store =
        run_blocking(|| crate::config::ConfigStore::open(shared.store.dir().to_path_buf()))?;
    let mut ctx = run_blocking(|| crate::submit::SubmitContext::new(&store, &cfg, &opts, near_ai))?;

    let sources = crate::source::all_sources(&source_roots);
    let mut changed = false;
    // Whether this pass put at least one trace on the wire. Drives both
    // halves of "sent, waiting to hear back": the local history rows, and
    // the nudged server read-back. See `note_uploads`.
    let mut uploaded_this_pass = false;
    // A fail-closed precondition (`SubmitPreconditionFailure`) aborts the
    // pass. It is held here rather than propagated with `?` so the pass's
    // own mutations -- the entries already resolved, the health label the
    // uploader just set -- are still persisted before it surfaces. The old
    // `?` threw all of that away, including the very label that suspends
    // expiry.
    let mut aborted: Option<anyhow::Error> = None;

    for entry in approved {
        // Claim the entry, atomically, before anything is read or sent. A
        // `cancel` that landed between the snapshot above and here wins and
        // the entry is skipped; from this point `cancel` is refused,
        // because the upload really is in flight. See
        // `Queue::claim_for_upload`.
        {
            let mut q = shared.queue.lock().expect("queue lock");
            let Some(current) = q.get(entry.entry_id).cloned() else {
                continue;
            };
            if current.state != queue::QueueState::Approved {
                continue;
            }
            // The approval covers the scopes that were in force when it was
            // given. `set_consent_scopes` can widen them at any moment with
            // nothing coupling it to already-approved entries, so an entry
            // whose scopes have moved is put back in front of the
            // contributor rather than sent under terms they never saw --
            // the same rule the re-hash guard applies to content.
            if current.approved_scopes.as_deref() != Some(cfg.consent_scopes.as_slice()) {
                q.revoke_approval(entry.entry_id, queue::REASON_SCOPES_CHANGED);
                changed = true;
                continue;
            }
            if !q.claim_for_upload(entry.entry_id) {
                continue;
            }
        }

        // Re-resolve the session through its own adapter, so the uploader can
        // re-read and re-hash the file before sending anything.
        // `find_session` re-scans every source (`source.discover()`), the
        // same blocking, non-yielding pass `watcher::tick` runs -- see
        // `run_blocking`'s doc.
        let Some((source, session_ref)) = run_blocking(|| find_session(&sources, &entry)) else {
            let mut q = shared.queue.lock().expect("queue lock");
            q.set_state(
                entry.entry_id,
                queue::QueueState::Failed,
                Some("session-file-vanished".to_string()),
            );
            changed = true;
            continue;
        };

        let result = {
            let mut state = shared.state.lock().expect("state lock").clone();
            let settings = shared.settings.lock().expect("settings lock").clone();
            let mut health = shared.health.lock().expect("health lock").clone();
            let mut up = uploader::Uploader {
                ctx: &mut ctx,
                store: &store,
                settings: &settings,
                state: &mut state,
                health: &mut health,
            };
            let result = up.upload_entry(source, &session_ref, &entry, now).await;
            // Copied back on the failure path too: the uploader sets the
            // fail-closed health label (canary, notice, identity) right
            // before it returns `Err`, and that label is what suspends
            // queue expiry.
            *shared.state.lock().expect("state lock") = state;
            *shared.health.lock().expect("health lock") = health;
            result
        };
        let decision = match result {
            Ok(d) => d,
            Err(e) => {
                aborted = Some(e);
                break;
            }
        };

        // Only a real upload counts toward the arming offer. The offer's
        // whole claim is "you have contributed from here N times", so N
        // counts sends, not settled entries. `AlreadySubmitted` means the
        // content hash was already held and nothing went out.
        //
        // Defensive rather than a live fix, and worth saying so: this arm is
        // not currently reachable through the watcher. A queue entry's id is
        // `entry_id_for(&transcript.session_hash)` (`watcher.rs`), so two
        // sessions with identical bytes collapse into one entry before
        // anything is uploaded, and the duplicate that would have produced
        // `AlreadySubmitted` never becomes a second entry. Verified by
        // trying to provoke it end to end, both with the twin written after
        // the first upload and with both present from the start: one entry,
        // one send, either way.
        //
        // It is gated anyway because the reachability is a property of the
        // watcher's id scheme, not of this decision, and nothing here would
        // notice if that scheme changed. No test accompanies it for the same
        // reason -- one would pass with or without the gate, which is a
        // claim of coverage rather than coverage.
        //
        // The queue bookkeeping below still treats the two alike: either way
        // the entry is settled server-side and should leave the queue.
        let newly_uploaded = matches!(decision, uploader::UploadDecision::Uploaded { .. });
        let mut q = shared.queue.lock().expect("queue lock");
        match decision {
            uploader::UploadDecision::Uploaded {
                submission_id,
                receipt,
            } => {
                // The submission shipped; now make the attestation mark tell
                // the truth about the receipt that did or did not come with
                // it. Without this a hosted call whose receipt 404'd would go
                // on reading `attested` -- the silent half of the defect, a
                // person believing they contributed attested work that
                // carried no proof. Only a mark that is currently `unknown`
                // is promoted to attested; an unattested mark is never
                // promoted, because it also answers for the marker and the
                // bodies, which a receipt says nothing about.
                let current = q.get(entry.entry_id).and_then(|e| e.attestation.clone());
                if let Some(mark) =
                    attestation_mark::writeback_after_upload(receipt, current.as_deref())
                {
                    q.record_attestation(entry.entry_id, mark.state, mark.reason);
                }
                q.set_state(entry.entry_id, queue::QueueState::Uploaded, None);
                q.set_submission_id(entry.entry_id, submission_id);
                uploaded_this_pass = true;
                // Counted here, against the project KEY, because this is the
                // last point that still holds one -- history is label-only by
                // design and two projects can share a final path segment. The
                // count is what backs the arming offer; see
                // `ProjectPolicy::arming_suggestion`.
                //
                // A failed save is not worth failing an upload that already
                // succeeded: the worst outcome is that an offer arrives one
                // contribution later than it might have.
                if newly_uploaded {
                    let mut policy = shared.policy.lock().expect("policy lock");
                    policy.record_contribution(&entry.project_key);
                    let _ = policy.save(&shared.store);
                }
            }
            uploader::UploadDecision::AlreadySubmitted { submission_id } => {
                q.set_state(entry.entry_id, queue::QueueState::Uploaded, None);
                q.set_submission_id(entry.entry_id, submission_id);
                uploaded_this_pass = true;
            }
            uploader::UploadDecision::Superseded { new_hash } => {
                let size = std::fs::metadata(&entry.path).map(|m| m.len()).unwrap_or(0);
                if let Some(fresh) = q.supersede(entry.entry_id, &new_hash, size, now) {
                    let max = shared
                        .settings
                        .lock()
                        .expect("settings lock")
                        .max_queue_entries;
                    let _ = q.upsert(fresh, max);
                }
            }
            uploader::UploadDecision::Refused { reason_label } => {
                // Decision 1: a refusal for an admission reason is evidence
                // about the entry, and the entry stops claiming otherwise.
                // Every other refusal label says nothing about
                // admissibility and rewrites nothing -- see
                // `contribution_eligibility::writeback_for`.
                if let Some(verdict) = contribution_eligibility::writeback_for(&reason_label) {
                    q.record_eligibility(entry.entry_id, verdict.state, verdict.reason);
                }
                // The same retraction on the mark, which every contributor
                // sees. A row still saying its session carries proof, after
                // a send of that session was turned away for want of that
                // proof, is the defect one layer up.
                if let Some(mark) = attestation_mark::writeback_for(&reason_label) {
                    q.record_attestation(entry.entry_id, mark.state, mark.reason);
                }
                q.set_state(
                    entry.entry_id,
                    queue::QueueState::Refused,
                    Some(reason_label),
                );
            }
            uploader::UploadDecision::ApprovalStale { reason_label } => {
                // The same re-offer path the consent-scope guard above
                // uses, and for the same reason: the approval covered
                // terms that no longer hold, so it is revoked and the
                // entry goes back in front of the contributor rather than
                // being recorded as a refusal of the trace itself.
                //
                // Deliberately not `Queue::supersede`: that path is keyed
                // on a *changed* session hash, and mints a replacement
                // entry whose id is derived from it. Here the session hash
                // is unchanged -- that is the whole point of the finding --
                // so the replacement's id would collide with the entry
                // just marked `Superseded`, `upsert` would treat it as
                // already tracked, and the entry would never be re-offered
                // at all.
                q.revoke_approval(entry.entry_id, &reason_label);
            }
            uploader::UploadDecision::Failed { reason_label } => {
                // Same rule on the failure side: `submit_one` can report an
                // admission refusal either way round depending on where in
                // the pipeline it surfaced, and a row that kept its claim
                // on one of the two paths would be the same defect with a
                // narrower reproduction.
                if let Some(verdict) = contribution_eligibility::writeback_for(&reason_label) {
                    q.record_eligibility(entry.entry_id, verdict.state, verdict.reason);
                }
                if let Some(mark) = attestation_mark::writeback_for(&reason_label) {
                    q.record_attestation(entry.entry_id, mark.state, mark.reason);
                }
                q.record_attempt(entry.entry_id, None);
                q.set_state(
                    entry.entry_id,
                    queue::QueueState::Failed,
                    Some(reason_label),
                );
            }
            uploader::UploadDecision::CapReached => {
                // Leave it approved: the cap lifts when the day rolls over.
                break;
            }
        }
        changed = true;
    }

    // Nothing may be left claimed. Every entry that reached a decision above
    // already has a terminal state; anything still `Uploading` is one this
    // pass broke out on (a daily cap, a fail-closed precondition), and
    // `Uploading` is a state nothing else would ever move it out of.
    {
        let mut q = shared.queue.lock().expect("queue lock");
        if q.release_in_flight() {
            changed = true;
        }
    }

    if changed {
        let q = shared.queue.lock().expect("queue lock");
        q.save(&shared.store)?;
        // Redacted trace content does not outlive the entry that needed it.
        // Everything this pass resolved -- uploaded, refused, failed,
        // superseded -- and everything whose approval it revoked has lost
        // its pin, so its stored envelope goes now rather than sitting in
        // the state directory. Best-effort: a file that cannot be removed
        // must not fail an upload pass that already succeeded.
        let _ = approved_envelope::sweep(&shared.store, &q.pinned_entry_ids());
        drop(q);
        let mut state = shared.state.lock().expect("state lock");
        state.save(&shared.store)?;
        drop(state);
        shared.publish(ipc::EVENT_QUEUE_CHANGED, serde_json::json!({}));
    }
    if uploaded_this_pass {
        note_uploads(shared, now)?;
    }

    // An exhausted budget is the one outcome of this pass that changes
    // nothing in the queue -- every affected entry stays `Approved` -- so
    // `changed` is false and the loop above publishes nothing. Without
    // this, a client that only redraws on an event sat on a stale status
    // while the very condition it needed to show had just been decided.
    // Published unconditionally rather than on a transition, because this
    // pass holds no memory of the previous one; it is one event per poll
    // interval at worst, and `status` is idempotent.
    if shared.daily_budget(now).blocked() {
        shared.publish(ipc::EVENT_STATUS_CHANGED, serde_json::json!({}));
    }

    if let Some(e) = aborted {
        return Err(e);
    }
    Ok(())
}

/// Record what a pass that actually uploaded now knows, without calling the
/// server.
///
/// Two things, both about the same gap. A trace that has just gone out has
/// no verdict yet, and until this existed nothing said so: `refresh_history`
/// runs on `history_poll_secs` (1800 by default), so for up to half an hour
/// after an upload the history cache still described the world as it was
/// before the upload, and the rollup's `submitted` bucket read zero while
/// traces were genuinely in flight. From outside, a submission that worked
/// perfectly looked exactly like one that had vanished.
///
/// 1. The receipts written by the upload are merged into the history cache
///    immediately, as `submitted`. Purely local -- see
///    `history::merge_new_receipts` for why this cannot overstate anything.
/// 2. A server read-back is scheduled for `POST_UPLOAD_HISTORY_DELAY_SECS`
///    from now, so verdicts arrive in about a minute and a half rather than
///    up to half an hour.
///
/// The schedule keeps the *earliest* pending deadline rather than pushing
/// it back, so a long burst spread over several passes still resolves to a
/// single read-back; and `refresh_history` will not honour it inside
/// `MIN_HISTORY_POLL_SPACING_SECS` of the last one, so approving two
/// hundred traces cannot turn into two hundred requests.
fn note_uploads(shared: &Arc<ipc::DaemonShared>, now: chrono::DateTime<Utc>) -> Result<()> {
    // A blocking file read with no `.await` of its own; see `run_blocking`.
    let receipts = run_blocking(|| shared.store.load_receipts())?;
    let labels = {
        let q = shared.queue.lock().expect("queue lock");
        let mut m = std::collections::BTreeMap::new();
        for e in q.all() {
            if let Some(id) = e.submission_id {
                // The opaque id beside the label: the key itself is a path
                // and never reaches a history record.
                m.insert(
                    id,
                    (
                        policy::project_id_for(&e.project_key),
                        e.project_label.clone(),
                    ),
                );
            }
        }
        m
    };
    let mut records = history::HistoryCache::load(&shared.store)?;
    if history::merge_new_receipts(&mut records, &receipts, &labels) {
        history::HistoryCache::save(&shared.store, &records)?;
        shared.publish(ipc::EVENT_QUEUE_CHANGED, serde_json::json!({}));
    }

    let due = now + chrono::Duration::seconds(POST_UPLOAD_HISTORY_DELAY_SECS);
    let mut state = shared.state.lock().expect("state lock");
    let earlier = state.history_refresh_due_at.is_some_and(|d| d <= due);
    if !earlier {
        state.history_refresh_due_at = Some(due);
        state.save(&shared.store)?;
    }
    Ok(())
}

/// One upload pass, exposed so an integration test can drive the same code
/// the supervisor runs rather than a reimplementation of it.
pub async fn drain_approved_for_test(
    shared: &Arc<ipc::DaemonShared>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    drain_approved(shared, now).await
}

/// Find the adapter and session reference matching a queue entry's path.
fn find_session<'a>(
    sources: &'a [Box<dyn crate::source::TraceSource>],
    entry: &queue::QueueEntry,
) -> Option<(
    &'a dyn crate::source::TraceSource,
    crate::source::SessionRef,
)> {
    for source in sources {
        let Ok(refs) = source.discover() else {
            continue;
        };
        if let Some(r) = refs.into_iter().find(|r| r.path == entry.path) {
            return Some((source.as_ref(), r));
        }
    }
    None
}

/// How long after an upload the server is asked for verdicts.
///
/// Not zero. The submission has only just landed and the server has not
/// scored it yet, so an immediate read-back would spend a request to learn
/// `submitted` -- which the local receipt already said, and which
/// `note_uploads` has already written into the cache. Ninety seconds is
/// long enough for a verdict to plausibly exist and short enough that a
/// contributor watching the window sees the outcome while still watching,
/// against the 1800-second interval it replaces.
const POST_UPLOAD_HISTORY_DELAY_SECS: i64 = 90;

/// The closest together two history read-backs may ever be.
///
/// `history_poll_secs` is partly politeness to the server, and a
/// burst-triggered refresh must not become a way around it. Uploads arrive
/// in bursts -- an armed project, a cap being raised, a batch approval -- so
/// without a floor a contributor approving two hundred traces could turn
/// one poll interval into a stream of requests. Two minutes, so the ninety
/// second nudge is honoured promptly in the ordinary case (the last
/// read-back is minutes old) and simply slips to the floor in the pathological
/// one.
const MIN_HISTORY_POLL_SPACING_SECS: i64 = 120;

/// Why -- or whether -- a history read-back happens on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HistoryRefresh {
    /// Not due; do nothing.
    Wait,
    /// The ordinary `history_poll_secs` interval has elapsed.
    OnInterval,
    /// A deadline set by an upload pass has come due.
    AfterUpload,
}

/// The whole gating rule, as a pure function so its edges can be pinned
/// without a server, a socket, or a clock.
///
/// A ripe upload deadline overrides the long interval, but never the floor:
/// inside `MIN_HISTORY_POLL_SPACING_SECS` of the last read-back the answer
/// is `Wait`, and the caller deliberately leaves the deadline in place so
/// the refresh happens at the floor rather than being lost.
pub(crate) fn history_refresh_decision(
    now: chrono::DateTime<Utc>,
    last_poll_at: Option<chrono::DateTime<Utc>>,
    due_at: Option<chrono::DateTime<Utc>>,
    interval: chrono::Duration,
) -> HistoryRefresh {
    let since_last = last_poll_at.map(|last| now.signed_duration_since(last));
    if due_at.is_some_and(|due| now >= due) {
        let floor = chrono::Duration::seconds(MIN_HISTORY_POLL_SPACING_SECS);
        if since_last.is_some_and(|d| d < floor) {
            return HistoryRefresh::Wait;
        }
        return HistoryRefresh::AfterUpload;
    }
    match since_last {
        Some(d) if d < interval => HistoryRefresh::Wait,
        _ => HistoryRefresh::OnInterval,
    }
}

/// Refresh the cached contribution history from the server, on its own
/// interval so history stays readable without every application polling.
///
/// Two things can make a refresh due: the ordinary `history_poll_secs`
/// interval, and a `history_refresh_due_at` deadline set by `note_uploads`
/// after a pass that actually uploaded. The nudge always yields to
/// `MIN_HISTORY_POLL_SPACING_SECS`, and when it does it is *kept* rather
/// than dropped, so a floored nudge fires at the floor instead of being
/// lost back to the half-hour interval.
async fn refresh_history(
    shared: &Arc<ipc::DaemonShared>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let interval = {
        let s = shared.settings.lock().expect("settings lock");
        chrono::Duration::seconds(s.history_poll_secs as i64)
    };
    let decision = {
        let state = shared.state.lock().expect("state lock");
        history_refresh_decision(
            now,
            state.last_history_poll_at,
            state.history_refresh_due_at,
            interval,
        )
    };
    match decision {
        HistoryRefresh::Wait => return Ok(()),
        HistoryRefresh::OnInterval => {}
        HistoryRefresh::AfterUpload => {
            // One attempt per deadline. Cleared before the request rather
            // than after it, so a burst is exactly one extra read-back even
            // when the server is down; the ordinary interval carries the
            // retry.
            let mut state = shared.state.lock().expect("state lock");
            state.history_refresh_due_at = None;
            state.save(&shared.store)?;
        }
    }
    let Some(cfg) = shared.store.load_config()? else {
        return Ok(());
    };
    let updates = match crate::submit::status(&shared.store, &cfg).await {
        Ok(u) => u,
        Err(_) => {
            // A failed poll serves the cache as-is; history is not worth a
            // health failure of its own.
            return Ok(());
        }
    };
    // A blocking file read with no `.await` of its own; see `run_blocking`'s
    // doc.
    let receipts = run_blocking(|| shared.store.load_receipts())?;
    let labels = {
        let q = shared.queue.lock().expect("queue lock");
        let mut m = std::collections::BTreeMap::new();
        for e in q.all() {
            if let Some(id) = e.submission_id {
                // The opaque id beside the label: the key itself is a path
                // and never reaches a history record.
                m.insert(
                    id,
                    (
                        policy::project_id_for(&e.project_key),
                        e.project_label.clone(),
                    ),
                );
            }
        }
        m
    };
    let records = history::join(&receipts, &updates, &labels, now);
    history::HistoryCache::save(&shared.store, &records)?;
    let mut state = shared.state.lock().expect("state lock");
    state.last_history_poll_at = Some(now);
    state.save(&shared.store)?;
    Ok(())
}

/// Refresh this contributor's line on the public community roster, on its own
/// interval, so `history_rollup` can answer with it without any client -- or
/// the handler itself -- making a network call.
///
/// The roster is public and unauthenticated, so this poll mints no claim and
/// carries no identity. The only thing linking it to this machine is the
/// handle the contributor chose to publish, which is why the whole pass is
/// skipped when there is no handle, and why a standing already cached is
/// dropped the moment the handle goes away.
async fn refresh_community(
    shared: &Arc<ipc::DaemonShared>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let interval = {
        let s = shared.settings.lock().expect("settings lock");
        chrono::Duration::seconds(s.community_poll_secs as i64)
    };
    {
        let state = shared.state.lock().expect("state lock");
        if let Some(last) = state.last_community_poll_at {
            if now.signed_duration_since(last) < interval {
                return Ok(());
            }
        }
    }
    let Some(cfg) = shared.store.load_config()? else {
        return Ok(());
    };
    let handle = cfg
        .display_handle
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty());
    let Some(handle) = handle else {
        // No handle: nothing to look up, and anything cached from a handle
        // that has since been cleared must go with it rather than keep being
        // served.
        let mut state = shared.state.lock().expect("state lock");
        if state.community.take().is_some() {
            state.save(&shared.store)?;
        }
        return Ok(());
    };
    let outcome =
        community::fetch_standing(&cfg.ingest_url, cfg.allowed_hosts.as_deref(), handle, now).await;
    let mut state = shared.state.lock().expect("state lock");
    match outcome {
        Ok(standing) => state.community = standing,
        Err(_) => {
            // A failed poll serves the cache as-is, which the serve path ages
            // out on its own. Like history, the roster is not worth a health
            // failure: it is a public read-back, not part of the upload path.
            //
            // The attempt is still stamped below rather than returning here.
            // The stamp is what spaces these polls out, so skipping it on
            // failure would turn an unreachable ingest into a roster GET on
            // every supervise tick -- a retry storm against a public endpoint,
            // caused by exactly the outage that makes it useless.
        }
    }
    state.last_community_poll_at = Some(now);
    state.save(&shared.store)?;
    Ok(())
}

/// Age out undecided entries, then decide whether a digest is due.
fn expire_and_digest(shared: &Arc<ipc::DaemonShared>, now: chrono::DateTime<Utc>) {
    let (ttl_days, digest_interval_secs, local_notifications) = {
        let s = shared.settings.lock().expect("settings lock");
        (
            s.queue_ttl_days,
            s.digest_interval_secs,
            s.local_notifications,
        )
    };
    let blocked = shared.health.lock().expect("health lock").blocks_expiry();

    let (queue_changed, pending_count, digest) = {
        let mut queue = shared.queue.lock().expect("queue lock");
        let expired = queue.expire(now, ttl_days, blocked);
        // Bookkeeping rows, not receipts: a superseded offer has a live
        // successor in the same file, and with subagent grouping a busy
        // conversation mints one per delegation. Compacted on the same pass
        // that ages entries out, so the file the daemon re-parses at every
        // start stays bounded without a second timer.
        let compacted = queue.compact_superseded();
        let pending = queue.pending();
        let count = pending.len();
        let text = notify::digest_text(&pending);
        (expired + compacted, count, text)
    };
    if queue_changed > 0 {
        let queue = shared.queue.lock().expect("queue lock");
        let _ = queue.save(&shared.store);
    }

    let last_digest_at = shared.state.lock().expect("state lock").last_digest_at;
    // What went out unasked since the last digest. An armed project never
    // queues anything, so without this an armed contributor is told nothing
    // ever -- see `notify::digest_due`. A cache that cannot be read is not a
    // reason to skip the digest: it degrades to the queue-only digest that
    // shipped before, rather than to silence.
    //
    // Behind the interval check, because this runs on every poll tick and the
    // poll is far more frequent than the digest interval. No contribution
    // count can make a digest fire early, so reading and parsing the history
    // file before the clock is even close is work whose result is discarded.
    // `interval_elapsed` is the same expression `digest_due` applies, not a
    // second opinion about it.
    let contributed = if notify::interval_elapsed(last_digest_at, now, digest_interval_secs) {
        history::contributed_since(
            &history::HistoryCache::load(&shared.store).unwrap_or_default(),
            last_digest_at,
        )
    } else {
        // Only reachable when `digest_due` is about to be false anyway: the
        // interval has not elapsed, so neither half of the digest can fire.
        history::ContributedSince::default()
    };
    if notify::digest_due(
        last_digest_at,
        now,
        digest_interval_secs,
        pending_count,
        contributed.count,
    ) {
        // Two sentences, either of which may be absent: what is waiting for
        // you, and what went without you. Joined rather than merged because
        // they are about different things and a contributor acts on only one
        // of them.
        let contribution = (contributed.count > 0).then(|| {
            notify::contribution_text(
                contributed.count,
                &contributed.project_labels,
                contributed.credit_pending,
            )
        });
        let body = match (pending_count > 0, contribution.as_deref()) {
            (true, Some(c)) => format!("{digest}\n{c}"),
            (true, None) => digest.clone(),
            (false, Some(c)) => c.to_string(),
            // `digest_due` cannot return true here, but a body built by
            // exhaustion cannot be wrong later if it can.
            (false, None) => digest.clone(),
        };
        shared.publish(
            ipc::EVENT_DIGEST_DUE,
            serde_json::json!({
                "pending": pending_count,
                "contributed": contributed.count,
                // Labels, never keys. A shell composes its own sentence from
                // these (each platform's notification centre words things
                // differently), so it needs the names and not just the count.
                "contributed_projects": contributed.project_labels,
                "credit_pending": contributed.credit_pending,
                "text": body,
            }),
        );
        if local_notifications {
            notify::emit_local(&body);
        }
        let mut state = shared.state.lock().expect("state lock");
        state.last_digest_at = Some(now);
        let _ = state.save(&shared.store);
    }
}

/// A future that resolves when the process is asked to terminate.
fn signal_stream() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return std::future::pending().await,
            };
            let mut interrupt = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return std::future::pending().await,
            };
            tokio::select! {
                _ = term.recv() => {}
                _ = interrupt.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::daemon::test_support::at;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn private_inference_dropped_embedded_daemon_stops_owned_proxy() {
        let (_dir, store) = crate::config::tests_support::temp_store();
        let mut embedded = start_embedded(store).await.unwrap();
        let home = tempfile::tempdir().unwrap();
        embedded
            .shared
            .install_private_inference_for_test(home.path().to_path_buf(), 0);
        embedded.shared.settings.lock().unwrap().private_inference = true;
        embedded.shared.reconcile_private_inference().await;
        assert!(home.path().join("endpoint.json").exists());
        // Remove unrelated task references so this exercises field drop order,
        // not a separately retained Shared Arc accidentally keeping the guard alive.
        embedded.server.abort();
        let _ = (&mut embedded.server).await;
        for worker in &mut embedded.preview_workers {
            worker.abort();
            let _ = worker.await;
        }
        assert_eq!(Arc::strong_count(&embedded.shared), 1);
        let weak = Arc::downgrade(&embedded.shared);
        let confirmed = embedded
            .shared
            .private_inference_stop_confirmation_for_test();
        drop(embedded);
        assert!(weak.upgrade().is_none());
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !confirmed.load(Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(!home.path().join("endpoint.json").exists());
        let next = ironwire_proxy::embed::start(home.path(), Some(0))
            .await
            .unwrap();
        next.shutdown().await;
    }

    /// The default `history_poll_secs`: half an hour.
    fn interval() -> chrono::Duration {
        chrono::Duration::seconds(1800)
    }

    #[test]
    fn history_waits_out_the_long_interval_when_nothing_was_uploaded() {
        // A tick with no upload behind it must not produce a read-back.
        assert_eq!(
            history_refresh_decision(
                at("2026-08-08T12:24:00Z"),
                Some(at("2026-08-08T12:00:00Z")),
                None,
                interval(),
            ),
            HistoryRefresh::Wait
        );
    }

    #[test]
    fn an_upload_makes_history_due_far_sooner_than_the_interval_would() {
        // 24 minutes after the last poll -- six minutes short of the
        // interval, and exactly the gap measured on the machine this came
        // from -- but a deadline set by an upload has come due.
        let now = at("2026-08-08T12:24:00Z");
        assert_eq!(
            history_refresh_decision(
                now,
                Some(at("2026-08-08T12:00:00Z")),
                Some(at("2026-08-08T12:23:00Z")),
                interval(),
            ),
            HistoryRefresh::AfterUpload
        );
    }

    #[test]
    fn a_deadline_that_has_not_arrived_yet_does_not_trigger_a_read_back() {
        assert_eq!(
            history_refresh_decision(
                at("2026-08-08T12:01:00Z"),
                Some(at("2026-08-08T12:00:00Z")),
                Some(at("2026-08-08T12:01:30Z")),
                interval(),
            ),
            HistoryRefresh::Wait
        );
    }

    #[test]
    fn a_burst_cannot_poll_faster_than_the_floor() {
        // Deadline ripe, but the last read-back was 60 seconds ago. The
        // floor is 120, so this tick waits.
        assert_eq!(
            history_refresh_decision(
                at("2026-08-08T12:01:00Z"),
                Some(at("2026-08-08T12:00:00Z")),
                Some(at("2026-08-08T12:00:30Z")),
                interval(),
            ),
            HistoryRefresh::Wait
        );
        // ...and fires as soon as the floor is cleared, because the caller
        // leaves the deadline set rather than dropping it.
        assert_eq!(
            history_refresh_decision(
                at("2026-08-08T12:02:00Z"),
                Some(at("2026-08-08T12:00:00Z")),
                Some(at("2026-08-08T12:00:30Z")),
                interval(),
            ),
            HistoryRefresh::AfterUpload
        );
    }

    #[test]
    fn the_interval_still_governs_when_no_upload_deadline_is_pending() {
        assert_eq!(
            history_refresh_decision(
                at("2026-08-08T12:30:00Z"),
                Some(at("2026-08-08T12:00:00Z")),
                None,
                interval(),
            ),
            HistoryRefresh::OnInterval
        );
    }

    #[test]
    fn a_daemon_that_has_never_polled_history_polls_on_its_first_tick() {
        assert_eq!(
            history_refresh_decision(at("2026-08-08T12:00:00Z"), None, None, interval()),
            HistoryRefresh::OnInterval
        );
    }

    #[tokio::test]
    async fn empty_approved_queue_does_not_retract_ingest_unreachable() {
        // When the approved queue is empty, do NOT retract ingest-unreachable.
        // The queue emptied because upload entries moved to Failed state when
        // uploads failed. With no evidence that ingest recovered, retracting
        // the label would be dishonest.
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().join("state")).unwrap();
        let shared = Arc::new(ipc::DaemonShared::load(store).unwrap());

        // Set ingest-unreachable manually
        {
            let mut health = shared.health.lock().expect("health lock");
            health.fail(health::LABEL_INGEST_UNREACHABLE, at("2026-08-08T12:00:00Z"));
        }
        assert!(!{ shared.health.lock().expect("health lock").ok() });

        // Call drain_approved with empty approved queue
        drain_approved_for_test(&shared, at("2026-08-08T13:00:00Z"))
            .await
            .unwrap();

        // ingest-unreachable should SURVIVE because no recovery was proven
        assert!(
            !{ shared.health.lock().expect("health lock").ok() },
            "ingest-unreachable must persist when queue is empty"
        );
        let label = {
            shared
                .health
                .lock()
                .expect("health lock")
                .last_error_label
                .clone()
        };
        assert_eq!(label.as_deref(), Some(health::LABEL_INGEST_UNREACHABLE));
    }

    #[tokio::test]
    async fn a_failed_roster_poll_still_waits_out_the_interval() {
        // The stamp is the only thing spacing these polls out. Writing it
        // only on success turned an unreachable ingest into a roster GET on
        // every supervise tick -- a retry storm against a public endpoint,
        // caused by exactly the outage that makes the poll useless.
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().join("state")).unwrap();
        store
            .save_config(&crate::config::ContributorConfig {
                inference_receipt_endpoint: None,
                inference_receipt_check_attestation: false,
                schema_version: crate::config::CONTRIBUTOR_CONFIG_SCHEMA_VERSION.to_string(),
                issuer_url: "http://127.0.0.1:9".to_string(),
                // Port 9 (discard) refuses immediately on loopback, so this
                // is a transport failure without a wait.
                ingest_url: "http://127.0.0.1:9".to_string(),
                audience: "aud".to_string(),
                tenant_id: "tenant-1".to_string(),
                instance_id: "instance-1".to_string(),
                user_subject: "alice".to_string(),
                device_key_id: "sha256:aa".to_string(),
                consent_scopes: vec!["debugging_evaluation".to_string()],
                pii_filter: None,
                allowed_hosts: Some("127.0.0.1".to_string()),
                display_handle: Some("quiet-otter".to_string()),
                public_bio: None,
                public_since: None,
                witness: None,
            })
            .unwrap();
        let shared = Arc::new(ipc::DaemonShared::load(store).unwrap());

        // A standing already cached: a failed poll serves it as-is rather
        // than blanking a section over one unreachable request.
        let cached = community::CommunityStanding {
            rank: Some(14),
            novelty_credit: 1240.0,
            accepted_in_window: 12,
            accept_rate: Some(0.75),
            window_label: "7d".to_string(),
            public_since: None,
            snapshot_at: Some(at("2026-08-17T12:00:00Z")),
            analytics_withheld: true,
        };
        {
            let mut state = shared.state.lock().expect("state lock");
            state.community = Some(cached.clone());
        }

        let first = at("2026-08-17T12:05:00Z");
        refresh_community(&shared, first).await.unwrap();
        {
            let state = shared.state.lock().expect("state lock");
            assert_eq!(
                state.last_community_poll_at,
                Some(first),
                "a failed poll must still record the attempt"
            );
            assert_eq!(
                state.community.as_ref(),
                Some(&cached),
                "a failed poll serves the cache as-is"
            );
        }

        // A tick a minute later is inside the interval, so the poll is
        // skipped entirely -- the stamp does not move.
        refresh_community(&shared, at("2026-08-17T12:06:00Z"))
            .await
            .unwrap();
        let state = shared.state.lock().expect("state lock");
        assert_eq!(
            state.last_community_poll_at,
            Some(first),
            "the next tick must not re-poll inside the interval"
        );
    }

    /// `trace-commons-contributor-ffi`'s own lock-contention test
    /// (`a_second_start_against_the_same_directory_fails_on_the_lock`)
    /// only asserts that `tc_daemon_start` returns NULL with a non-null
    /// `*err` -- which `tc_daemon_start` would also do if the *second*
    /// start failed for an unrelated reason (a socket-bind failure, a
    /// `ConfigStore::open` permissions error), since it collapses every
    /// failure into one fixed label before crossing the FFI boundary (see
    /// that crate's module doc on why). This test, against
    /// `start_embedded` directly rather than through the FFI, is the one
    /// that actually proves the second failure is the lock, not something
    /// else: it asserts on the typed `StartFailure` the error carries.
    /// Starting a daemon claims the runtime that hosted proxies must live
    /// on.
    ///
    /// The mechanism has its own test in `ipc`, which flips the switch
    /// through `handle_local` and probes the port afterwards -- but that
    /// test calls `adopt_runtime` itself, so it proves the mechanism works
    /// and not that anything calls it. This is the other half: delete the
    /// call in `start_embedded` and a real daemon goes back to starting
    /// proxies on whatever short-lived runtime the caller was standing on,
    /// with nothing failing until an app flips the switch.
    #[tokio::test]
    async fn a_started_daemon_claims_a_runtime_for_hosted_proxies() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let embedded = start_embedded(store).await.unwrap();
        assert!(
            embedded.shared.has_adopted_runtime(),
            "a started daemon must claim its runtime, or a proxy started \
             through the synchronous IPC path dies with the throwaway \
             runtime that path builds"
        );
        embedded.close();
    }

    #[tokio::test]
    async fn a_second_start_embedded_fails_specifically_on_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store_a = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let embedded = start_embedded(store_a).await.unwrap();

        let store_b = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let err = match start_embedded(store_b).await {
            Ok(_) => panic!("a second start_embedded against a locked directory must fail"),
            Err(e) => e,
        };
        assert_eq!(
            err.downcast_ref::<StartFailure>(),
            Some(&StartFailure::AlreadyRunning),
            "expected a lock-contention failure, got: {err:#}"
        );

        // The loser must not take the winner's lock file with it. This is the
        // other half of the cleanup rule: a failed start removes the lock only
        // when the lock was its own, never when the file belongs to a daemon
        // that is genuinely running.
        assert!(
            dir.path().join(DAEMON_LOCK_FILE).exists(),
            "a losing second start deleted the running daemon's lock file"
        );

        embedded.close();
    }

    /// Write a `daemon-settings.json` this version cannot parse.
    ///
    /// Hand-authored rather than built from `DaemonSettings`: a file with
    /// every required field present is exactly what this is arranging to
    /// avoid. It is also the file shape a person writes by hand, which is how
    /// the failure was first hit.
    fn write_unparseable_settings(dir: &std::path::Path) {
        std::fs::write(
            dir.join(crate::config::DAEMON_SETTINGS_FILE),
            r#"{"claude_root":"/tmp/x","codex_root":"/tmp/y"}"#,
        )
        .unwrap();
    }

    /// A start that fails must not leave `daemon.lock` behind.
    ///
    /// `close` removes the lock on clean shutdown, so the file's presence is
    /// what every other reader treats as "a daemon is running here". A failed
    /// start that leaves it is not untidy, it is a false statement -- it was
    /// read as proof of a running daemon during this project's own
    /// development and produced a wrong diagnosis.
    #[tokio::test]
    async fn a_failed_start_leaves_no_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        write_unparseable_settings(dir.path());

        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let err = match start_embedded(store).await {
            Ok(_) => panic!("start_embedded must fail on a settings file it cannot parse"),
            Err(e) => e,
        };
        assert_eq!(
            err.downcast_ref::<StartFailure>(),
            Some(&StartFailure::SettingsUnreadable),
            "expected a settings failure, got: {err:#}"
        );
        assert!(
            !dir.path().join(DAEMON_LOCK_FILE).exists(),
            "a failed start left daemon.lock behind, where it reads as a running daemon"
        );
    }

    /// The cleanup releases the lock rather than merely unlinking the file.
    #[tokio::test]
    async fn a_failed_start_does_not_strand_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        write_unparseable_settings(dir.path());
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        assert!(start_embedded(store).await.is_err());

        // Repair the settings and start for real. Had the failed attempt
        // stranded the lock, this would fail as contention against a daemon
        // that does not exist.
        std::fs::remove_file(dir.path().join(crate::config::DAEMON_SETTINGS_FILE)).unwrap();
        let store = crate::config::ConfigStore::open(dir.path().to_path_buf()).unwrap();
        let embedded = start_embedded(store)
            .await
            .expect("a start after a failed start must not see stale lock contention");
        embedded.close();
    }
}

pub(crate) mod commons_credentials;
