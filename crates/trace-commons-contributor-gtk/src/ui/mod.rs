//! The window, which on Linux is the primary surface.
//!
//! GNOME has no system tray, so nothing here may depend on one: every
//! capability is reachable from this window, and the tray -- where a desktop
//! has a real one -- would only ever be a shortcut into it. Nothing in this
//! application tells a contributor to install a shell extension.

pub mod balance;
pub mod community_brand;
pub mod credential;
mod css_contract;
pub mod funding;
pub mod history;
pub mod mark;
pub mod onboarding;
mod onboarding_nearai;
mod onboarding_wallet;
pub mod preview;
pub mod private_inference;
pub mod queue;
pub mod roots;
pub mod settings;
pub(crate) mod shortcuts;
pub mod style;
pub mod update;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use trace_commons_contributor::daemon::preview_scheduler::{STATE_READY, STATE_TOO_LARGE};

use crate::copy;
use crate::model::{ApproveResult, HistoryRollup, PreviewSummary, QueueEntry, Status};
use crate::worker::{Outcome, Worker};

pub const APP_ID: &str = "ai.tracecommons.Contributor";

/// The header bar's height, from §5.1's Linux column. Set as a size request
/// rather than in CSS because `AdwHeaderBar` derives its height from the
/// tallest thing packed into it, and the mark and the switcher are both
/// shorter than the bar the design draws.
const HEADER_HEIGHT: i32 = 46;

/// The reading column, shared by every screen in this window so the header's
/// switcher, the health banner and the queue's cards all sit on the same two
/// vertical lines.
const COLUMN_MAX: i32 = 840;
const COLUMN_TIGHTEN: i32 = 680;

/// The four screens, in the order the switcher shows them, with the icon
/// each one carries. One list, so the stack pages and the switcher items
/// cannot drift apart.
///
/// **Every icon name here must stay symbolic.** GTK recolours a symbolic
/// icon from its node's `color`, which is what lets style.css mute an
/// unselected item's icon and turn the selected one green without this code
/// setting anything. A full-colour icon ignores `color` and renders as-is,
/// so swapping one in would silently leave that item's icon un-recoloured
/// while the others kept working -- a difference that shows up in a
/// screenshot months later and in no diff at all.
///
/// The model-calls item's label is read from the shared copy module and
/// never retyped: the word this surface may not say is "private", and the
/// only way three shells keep saying the same true thing is by reading one
/// definition. The stack name below it is internal and is read by nobody.
pub(crate) const SCREENS: [(&str, &str, &str); 4] = [
    ("queue", "Queue", "view-list-symbolic"),
    ("history", "History", "document-open-recent-symbolic"),
    (
        PRIVATE_INFERENCE_SCREEN,
        copy::PRIVATE_INFERENCE_DESTINATION,
        "network-transmit-receive-symbolic",
    ),
    ("settings", "Settings", "emblem-system-symbolic"),
];

/// The stack's name for the model-calls screen. Named once because the
/// tray and every other shortcut into it has to spell it identically, and
/// `set_visible_child_name` on a name no page carries is a silent no-op.
pub const PRIVATE_INFERENCE_SCREEN: &str = "private-inference";

/// The switcher's icon, §5.1 item 1. Set in pixels rather than by an icon
/// size so it matches the label it sits beside at every text scale.
const SWITCHER_ICON: i32 = 13;

type Callback = Box<dyn FnOnce(&Rc<App>, Outcome)>;

/// An approval that has been made but has not left the machine yet.
///
/// `hold_until` is the daemon's own instant, read from the `approve`
/// response. Nothing here is computed from a duration this process picked --
/// see `docs/contributor-daemon-ipc-v1_1.md` on the approval hold.
pub struct PendingUndo {
    /// Every entry this approval covers. A row's Submit holds exactly one; a
    /// project group's Submit all holds every entry `approve` reported
    /// approved, which is why Undo must cancel each of them rather than
    /// assuming there is only ever one.
    pub entry_ids: Vec<String>,
    pub project_label: String,
    /// When this window offered the undo, which is what the bar's "held 41s"
    /// counts up from. It counts *up* on purpose: the app cannot see the
    /// watcher's sweep, so a countdown would be a promise it cannot keep.
    pub approved_at: chrono::DateTime<chrono::Utc>,
    pub hold_until: chrono::DateTime<chrono::Utc>,
}

pub struct App {
    pub worker: Worker,
    /// Where the model-calls switch stands, as the tray reads it.
    ///
    /// Written on every settings read (see `private_inference::render`) and
    /// read by nothing that paints: it is the switch's position, not a claim
    /// that a listener is running. It decides which way the tray's one
    /// action row points and nothing else.
    pub tray: crate::tray::TrayState,
    pub window: adw::ApplicationWindow,
    pub toasts: adw::ToastOverlay,
    pub stack: adw::ViewStack,

    /// `admission_evidence_required`, as `get_settings` last answered it.
    ///
    /// Held verbatim and NEVER negated. It is true for a contributor who
    /// signed up through NEAR and therefore has no invite, so it selects the
    /// candidate reading of the certificate-held section. A `!` anywhere on
    /// the way to `certificate::view` would swap both readings and compile.
    ///
    /// False until the first settings read, which is the reading that claims
    /// less: a section that has not been told yet must not assert
    /// attestation.
    pub evidence_admitted: std::cell::Cell<bool>,

    pub queue: queue::QueueView,
    pub history: history::HistoryView,
    /// The model-calls screen. Its own destination rather than a card on
    /// Settings: this is the one switch that makes this computer answer
    /// calls for whatever else is running on it, and it was undiscoverable
    /// five sections down a settings list.
    pub private_inference: private_inference::PrivateInferenceView,
    pub settings: settings::SettingsView,
    /// The update banner. Above the health banner is deliberate: an update
    /// is a standing fact about this machine, while health is about the
    /// current run.
    pub update: update::UpdateView,

    /// Health is rendered from `status.health.last_error_label` and nothing
    /// else: the daemon owns the precedence order and a client that
    /// reconstructed it would eventually disagree with the daemon about
    /// what is wrong.
    ///
    /// This is the clamped column, not the banner box inside it: showing and
    /// hiding the column is what also removes its top margin, so a window
    /// with nothing wrong has no gap under the header.
    health_banner: adw::Clamp,
    health_label: gtk::Label,
    health_button: gtk::Button,
    /// The count on the switcher's Queue item. Hidden at zero rather than
    /// drawn as a "0": an empty badge is a decoration, and the queue's own
    /// empty state already says the true thing.
    queue_badge: gtk::Label,

    callbacks: RefCell<HashMap<u64, Callback>>,
    pub entries: RefCell<Vec<QueueEntry>>,
    /// `list_projects` rows, held for the two counts they carry.
    ///
    /// The queue builds its folders from `entries` and always will -- the
    /// header must agree with the rows on screen, not with a number the
    /// contributor cannot check. What these rows are for is the ONE number
    /// the shell must not compute: how many of a group a project-wide
    /// `approve` would actually send. That is the daemon's filter, and a
    /// shell deriving it is a second implementation which agrees until the
    /// day the rule changes an arm.
    pub projects: RefCell<Vec<crate::model::Project>>,
    pub status: RefCell<Option<Status>>,
    /// The week band's three figures. Read here rather than passed down from
    /// `history` so the queue can draw the band without depending on which
    /// screen the contributor happens to be looking at.
    pub rollup: RefCell<HistoryRollup>,
    /// The approval the undo bar is currently offering to take back, if any.
    pub undo: RefCell<Option<PendingUndo>>,
    /// The handle for the once-a-second tick that moves the undo bar's
    /// elapsed figure, held so a second approval can stop the first one's
    /// timer instead of leaving it running. Approving is a loop -- the sheet
    /// approves and advances to the next entry -- so back-to-back approvals
    /// inside one hold window are the normal path, not an edge case.
    undo_tick: RefCell<Option<glib::SourceId>>,
    /// Preview summaries, keyed by entry id, so a row can show what would be
    /// sent without re-running the pipeline on every redraw. Filled in by
    /// `handle_preview_request_result` for a scheduled card preview, and by
    /// the preview sheet's own full preview when it pins one -- see
    /// `ui::preview::Sheet::load`.
    pub previews: RefCell<HashMap<String, PreviewSummary>>,
    /// Entries the daemon's admission control refused to preview at all,
    /// keyed by entry id, carrying `(raw_session_bytes, limit_bytes)` and
    /// nothing else -- never a would-send estimate. Mutually exclusive with
    /// `previews`: an entry lands in exactly one of the two, once, and never
    /// moves. See `docs/superpowers/specs/2026-08-20-preview-scheduler-design.md`.
    pub previews_too_large: RefCell<HashMap<String, (u64, u64)>>,
    /// Every pending entry this shell has asked the daemon's preview
    /// scheduler about. Superset of `previews.keys()` and
    /// `previews_too_large.keys()`: an id lands here the moment
    /// `preview_request` is sent and leaves only when the entry itself
    /// leaves the pending list, which is also the signal to tell the
    /// daemon `preview_cancel` -- see `App::reconcile_card_previews`.
    card_tracked: RefCell<std::collections::HashSet<String>>,
    /// Each rendered card's own widget, keyed by entry id, so a scroll
    /// settle can ask every card its bounds against the scroller without
    /// keeping a second copy of the queue's layout. Rebuilt every render,
    /// in step with `queue::render` rebuilding `QueueView::list` itself.
    card_widgets: RefCell<HashMap<String, gtk::Widget>>,
    /// The pending debounce timer for `preview_visible`, so a scroll drag
    /// reschedules the same single call rather than stacking one per
    /// `value-changed` signal.
    scroll_debounce: RefCell<Option<glib::SourceId>>,
    /// What each withdrawal attempt did, keyed by submission id.
    ///
    /// Kept here rather than in a screen-level banner because a failure
    /// next to a row that still reads "In the commons" leaves it genuinely
    /// ambiguous whether the trace was withdrawn. History rebuilds its rows
    /// wholesale on every refresh, so the outcome has to outlive the widget
    /// that reported it.
    pub withdrawals: RefCell<HashMap<String, history::Withdrawal>>,
    /// `queue_outcome_counts`: how many queued sessions ended each way.
    ///
    /// A `BTreeMap` so the disclosure lists them in a stable order rather
    /// than in whatever order a hash map happened to produce this second.
    pub outcome_counts: RefCell<std::collections::BTreeMap<String, u64>>,
    /// Kept for the session rather than written to disk. The point of
    /// persisting them is that the second trace is one keystroke, and a
    /// search term is the contributor's own sensitive string -- a client
    /// name, usually. It does not need to outlive the process to do its job.
    pub recent_searches: RefCell<Vec<String>>,
    /// Which level of the queue is showing. Resolved against the live
    /// folders on every render (`queue_folders::resolve`), so a folder that
    /// empties while it is open returns to the list.
    pub queue_location: RefCell<crate::queue_folders::Location>,
    /// The same, for history. A second field rather than one shared with the
    /// queue: the two screens hold different sets of projects -- history
    /// keeps a folder the queue has emptied -- and sharing one location
    /// would drop a contributor into a folder that does not exist on the
    /// screen they just switched to.
    pub history_location: RefCell<crate::queue_folders::Location>,
    quit_confirmed: Cell<bool>,
}

/// How long a scroll must sit still before `preview_visible` is sent.
///
/// Cheap and idempotent on the daemon's side, so this only needs to beat a
/// drag: any value that turns a continuous `value-changed` stream into a
/// single call after it stops is enough. There is no throughput reason to
/// tune it further -- see the design's "Priority" section.
const SCROLL_SETTLE_DEBOUNCE_MS: u64 = 250;

impl App {
    pub fn build(application: &adw::Application, worker: Worker) -> Rc<Self> {
        // Before any widget is built, so nothing is ever drawn in the
        // theme's palette and then repainted in this one.
        style::install();

        let window = adw::ApplicationWindow::builder()
            .application(application)
            .title(copy::APP_NAME)
            .default_width(980)
            .default_height(720)
            .build();

        let stack = adw::ViewStack::new();
        let queue = queue::QueueView::new();
        let history = history::HistoryView::new();
        let private_inference = private_inference::PrivateInferenceView::new();
        let settings = settings::SettingsView::new();
        let update = update::UpdateView::new();

        // Pages and switcher items are built from the same list, in the same
        // order, so a screen cannot be renamed in one place and not the
        // other.
        let pages: [&gtk::Box; 4] = [
            &queue.root,
            &history.root,
            &private_inference.root,
            &settings.root,
        ];
        for ((name, label, icon_name), page) in SCREENS.into_iter().zip(pages) {
            stack
                .add_titled(page, Some(name), label)
                .set_icon_name(Some(icon_name));
        }

        let queue_badge = gtk::Label::builder().visible(false).build();
        queue_badge.add_css_class("tc-count-badge");
        queue_badge.set_valign(gtk::Align::Center);

        // The bar's own close button is left to `AdwHeaderBar`'s window
        // controls rather than hand-built. The design draws a 24px round
        // `x` on a faint wash, which is exactly what GNOME's own decoration
        // already is -- and a hand-built one would lose the window menu, the
        // keyboard path to it, and whatever button layout the contributor
        // has chosen in their desktop settings.
        let header = adw::HeaderBar::builder()
            .title_widget(&view_switcher(&stack, &queue_badge))
            .build();
        header.add_css_class("tc-header");
        header.set_size_request(-1, HEADER_HEIGHT);
        // The mark, drawn from its own geometry rather than shipped as an
        // asset. 20px is the header-bar size the design spec names.
        header.pack_start(&mark::framed(20));

        let health_label = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .hexpand(true)
            .build();
        health_label.add_css_class("tc-body");
        let health_button = gtk::Button::builder().visible(false).build();
        health_button.add_css_class("tc-quiet");
        health_button.set_valign(gtk::Align::Center);
        // The glyph is what carries "weigh this" into greyscale; the gold
        // rule around the banner is the colour half of the same statement.
        let health_glyph = gtk::Label::new(Some(style::Tone::Attention.glyph()));
        health_glyph.add_css_class("tc-attention");
        health_glyph.add_css_class("tc-card-title");
        health_glyph.set_valign(gtk::Align::Start);
        let health_banner = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(style::space::M)
            .build();
        health_banner.append(&health_glyph);
        health_banner.append(&health_label);
        health_banner.append(&health_button);
        health_banner.add_css_class("tc-banner");

        // The banner sits above the stack rather than inside the queue, so a
        // contributor reading History or Settings still learns that
        // contributions are held up. The design draws it on the queue
        // because the queue is the only screen it drew; putting it here says
        // the same thing on every screen and never says it twice.
        //
        // It is clamped to the same column as the screens below it, which is
        // the only reason this is a clamp and not a bare margin: an
        // unclamped banner runs the full width of a maximised window while
        // the cards under it stop at 840, and the two stop looking like one
        // document.
        let banner_column = adw::Clamp::builder()
            .maximum_size(COLUMN_MAX)
            .tightening_threshold(COLUMN_TIGHTEN)
            .child(&health_banner)
            .visible(false)
            .margin_top(style::space::L)
            .margin_start(style::space::XL)
            .margin_end(style::space::XL)
            .build();

        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.add_css_class("tc-root");
        content.append(&header);
        content.append(&update.root);
        content.append(&banner_column);
        content.append(&stack);
        stack.set_vexpand(true);

        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&content));
        window.set_content(Some(&toasts));

        let app = Rc::new(Self {
            worker,
            tray: crate::tray::TrayState::default(),
            window,
            toasts,
            stack,
            evidence_admitted: std::cell::Cell::new(false),
            queue,
            history,
            private_inference,
            settings,
            update,
            health_banner: banner_column,
            health_label,
            health_button,
            queue_badge,
            callbacks: RefCell::new(HashMap::new()),
            entries: RefCell::new(Vec::new()),
            projects: RefCell::new(Vec::new()),
            status: RefCell::new(None),
            rollup: RefCell::new(HistoryRollup::default()),
            undo: RefCell::new(None),
            undo_tick: RefCell::new(None),
            previews: RefCell::new(HashMap::new()),
            previews_too_large: RefCell::new(HashMap::new()),
            card_tracked: RefCell::new(Default::default()),
            card_widgets: RefCell::new(HashMap::new()),
            scroll_debounce: RefCell::new(None),
            withdrawals: RefCell::new(HashMap::new()),
            outcome_counts: RefCell::new(Default::default()),
            recent_searches: RefCell::new(Vec::new()),
            queue_location: RefCell::new(crate::queue_folders::Location::Root),
            history_location: RefCell::new(crate::queue_folders::Location::Root),
            quit_confirmed: Cell::new(false),
        });

        app.wire_result_pump();
        app.wire_event_pump();
        app.wire_quit();
        app.wire_health_action();
        app.wire_tray();
        // After `wire_tray`, and reaching the same handler it does. GNOME
        // has no tray, so on most Linux desktops this is the only surface
        // besides the window's own controls -- and it is still an
        // accelerant, never the only path to anything.
        shortcuts::wire(&app, application);
        queue::wire(&app);
        history::wire(&app);
        private_inference::wire(&app);
        funding::wire(&app);
        settings::wire(&app);
        update::wire(&app);
        app.refresh();

        // Best-effort and platform-optional, in the order the design spec
        // gives them: the portal registration is the one that matters most
        // (it is where a GNOME user looks for this app at all), the tray
        // is the bonus. Neither can keep the window from opening -- both
        // run on their own threads. The portal request also classifies
        // whether any backend answered at all, so a desktop with none does
        // not silently no-op -- see `settings::wire_background_probe` for
        // where that classification is actually shown to a contributor.
        let portal_probe = crate::portal::spawn_request();
        settings::wire_background_probe(&app, portal_probe);

        app
    }

    /// The health banner's button, which until now was drawn and wired to
    /// nothing.
    ///
    /// `render_health` gives it a label and shows it whenever the daemon
    /// reports a label that carries an action, so it has always looked like
    /// a control. Clicking it did nothing at all -- the worst kind of
    /// affordance, because the banner it sits in exists to tell a
    /// contributor that contributions are held up, and the button is the
    /// only thing offering a way out.
    ///
    /// The label is read at click time rather than captured when the button
    /// was labelled: the banner is re-rendered on every status change, and a
    /// closure holding the label from three states ago would send someone to
    /// the screen for a problem they no longer have.
    fn wire_health_action(self: &Rc<Self>) {
        let app = self.clone();
        self.health_button.connect_clicked(move |_| {
            let label = app
                .status
                .borrow()
                .as_ref()
                .and_then(|s| s.health.last_error_label.clone());
            if let Some(label) = label {
                onboarding::present_for_health(&app, &label);
            }
        });
    }

    /// Drain worker results on the main loop and hand each to the closure
    /// that asked for it.
    fn wire_result_pump(self: &Rc<Self>) {
        let app = Rc::clone(self);
        glib::spawn_future_local(async move {
            while let Ok((id, outcome)) = app.worker.results.recv().await {
                let callback = app.callbacks.borrow_mut().remove(&id);
                if let Some(callback) = callback {
                    callback(&app, outcome);
                }
            }
        });
    }

    /// Daemon events are treated as "something moved, look again" rather
    /// than as deltas to apply. That is also the only correct response to
    /// `resync_required`, so there is one code path instead of two.
    ///
    /// `preview_ready` is the one exception to "look again by calling
    /// `refresh`", and the one event this connection reads a field off of at
    /// all -- see `DaemonEvent`'s doc comment for why an entry id is exempt
    /// from "names only" while everything else stays a bare name. Reading it
    /// is what turns "a card resolved" into a single targeted
    /// `preview_request` (`App::handle_preview_ready`) instead of a sweep
    /// over every card still outstanding: the first version of this feature
    /// swept on every event, which reduces to firing roughly one sweep per
    /// still-shrinking outstanding set while a queue drains -- fine at ten
    /// cards, a self-inflicted request storm at the five hundred this
    /// feature exists for.
    fn wire_event_pump(self: &Rc<Self>) {
        let app = Rc::clone(self);
        glib::spawn_future_local(async move {
            while let Ok(event) = app.worker.events.recv().await {
                match event.name.as_str() {
                    "digest_due" => {
                        app.refresh();
                        app.post_digest(event.digest.clone().unwrap_or_default());
                    }
                    "preview_ready" => app.handle_preview_ready(event.entry_id),
                    // A missed preview_ready is exactly the gap
                    // resync_required exists to cover, so both halves of
                    // "look again" run: the queue itself, and a full sweep
                    // of the scheduled previews a targeted request could
                    // never catch up on by itself. This is the one place a
                    // sweep still belongs -- it runs once per resync, not
                    // once per card resolved.
                    "resync_required" => {
                        app.refresh();
                        app.poll_outstanding_previews();
                    }
                    _ => app.refresh(),
                }
            }
        });
    }

    /// Quitting must say what continues, and the true sentence depends on
    /// which process is doing the watching.
    fn wire_quit(self: &Rc<Self>) {
        let app = Rc::clone(self);
        self.window.connect_close_request(move |window| {
            if app.quit_confirmed.get() {
                return glib::Propagation::Proceed;
            }
            let dialog = if app.worker.hosts_the_loop() {
                let d = adw::MessageDialog::new(
                    Some(window),
                    Some(concat!("Quit ", copy::app_name!(), "?")),
                    Some(copy::QUIT_HOSTING_BODY),
                );
                d.add_responses(&[
                    ("cancel", copy::QUIT_HOSTING_CANCEL),
                    ("quit", copy::QUIT_HOSTING_CONFIRM),
                ]);
                d
            } else {
                let d = adw::MessageDialog::new(
                    Some(window),
                    Some(concat!("Quit ", copy::app_name!(), "?")),
                    Some(copy::QUIT_ATTACHED_BODY),
                );
                d.add_responses(&[
                    ("quit", copy::QUIT_ATTACHED_CONFIRM),
                    ("quit-and-stop", copy::QUIT_ATTACHED_ALSO_STOP),
                ]);
                d
            };
            dialog.set_close_response("cancel");
            let app = Rc::clone(&app);
            dialog.connect_response(None, move |dialog, response| {
                dialog.close();
                match response {
                    "quit" => {
                        app.quit_confirmed.set(true);
                        app.window.close();
                    }
                    "quit-and-stop" => {
                        app.quit_confirmed.set(true);
                        // Stop the separate watcher too, since that is what
                        // the contributor just asked for. The window closes
                        // either way.
                        app.call("shutdown", serde_json::json!({}), |app, _| {
                            app.window.close();
                        });
                    }
                    _ => {}
                }
            });
            dialog.present();
            glib::Propagation::Stop
        });
    }

    /// The tray icon's entire vocabulary reaches the window through here:
    /// a click of any kind raises it, a menu press raises it at the screen
    /// that was pressed, and one row can stop this computer answering model
    /// calls.
    ///
    /// That last one is the only write anything outside this window can ask
    /// for, and it goes in one direction. There is no request that turns
    /// model calls ON -- `tray.rs` has no word for it -- because enabling it
    /// changes what anything else running here may send through, and the
    /// sentence saying so is on the screen the off-state row opens instead.
    /// Turning it off only ever reduces what this computer answers, which is
    /// why that direction is safe from a menu and the other is not.
    ///
    /// The window comes up either way: the daemon's answer to a stop is a
    /// sentence only the model-calls screen renders, and a change nobody can
    /// see the result of is the shape this surface avoids. See `tray.rs` for
    /// the rest, and for why absence of a tray (most Linux desktops,
    /// including plain GNOME) never reaches this at all.
    fn wire_tray(self: &Rc<Self>) {
        let rx = crate::tray::spawn(self.tray.clone());
        let app = Rc::clone(self);
        glib::spawn_future_local(async move {
            while let Ok(request) = rx.recv().await {
                apply_tray_request(&app, request);
            }
        });
    }

    /// One daemon call, with its answer delivered back on the main loop.
    pub fn call<F>(self: &Rc<Self>, method: &str, params: serde_json::Value, callback: F)
    where
        F: FnOnce(&Rc<App>, Result<serde_json::Value, String>) + 'static,
    {
        let id = self.worker.call(method, params);
        self.callbacks.borrow_mut().insert(
            id,
            Box::new(move |app, outcome| {
                if let Outcome::Call(result) = outcome {
                    callback(app, result)
                }
            }),
        );
    }

    /// How many times `needle` was in the entry's pre-redaction session
    /// text. `None` for any failure -- see `worker::Outcome::SearchOriginal`.
    pub fn search_original<F>(self: &Rc<Self>, entry_id: &str, needle: &str, callback: F)
    where
        F: FnOnce(&Rc<App>, Option<u32>) + 'static,
    {
        let id = self.worker.search_original(entry_id, needle);
        self.callbacks.borrow_mut().insert(
            id,
            Box::new(move |app, outcome| {
                if let Outcome::SearchOriginal(matches) = outcome {
                    callback(app, matches)
                }
            }),
        );
    }

    pub fn preview<F>(self: &Rc<Self>, entry_id: &str, callback: F)
    where
        F: FnOnce(&Rc<App>, Result<(PreviewSummary, Option<String>), String>) + 'static,
    {
        let id = self.worker.preview(entry_id);
        self.callbacks.borrow_mut().insert(
            id,
            Box::new(move |app, outcome| {
                if let Outcome::Preview(result) = outcome {
                    callback(app, result)
                }
            }),
        );
    }

    /// Re-read everything the window renders. Cheap, and the honest response
    /// to any event.
    pub fn refresh(self: &Rc<Self>) {
        self.call("status", serde_json::json!({}), |app, result| {
            if let Ok(Ok(status)) = result.map(serde_json::from_value::<Status>) {
                app.render_health(&status);
                settings::render_status(app, &status);
                // The witness lives in the contributor's config rather than
                // in daemon settings, so nothing in the settings answer
                // carries it and it is repainted here instead -- including
                // the last-submission row, which changes when a session
                // goes out and on no other event.
                settings::render_witness(app);
                // Both halves of "does this device need onboarding" are the
                // daemon's to answer, so the question is asked here rather
                // than at window construction, where neither is known yet.
                onboarding::present_if_needed(app, status.logged_in, status.tenant_id.as_deref());
                *app.status.borrow_mut() = Some(status);
            }
        });
        // Asked alongside the queue, not with `list_projects`, because this
        // is drawn on the queue screen and the daemon's answer changes on
        // exactly the events that change the queue -- an upload landing is
        // what moves a project past the threshold.
        self.call("arming_suggestion", serde_json::json!({}), |app, result| {
            let offer = result
                .ok()
                .and_then(|v| serde_json::from_value::<crate::model::ArmingOffer>(v).ok());
            queue::render_arming_offer(app, offer);
        });
        // The offer is about a daemon setting and both its answers are
        // daemon settings, so it is read from the daemon on every refresh
        // rather than latched in this window. A window-local latch would
        // re-ask on the next launch, which is the nagging the marker exists
        // to prevent.
        self.call("get_settings", serde_json::json!({}), |app, result| {
            let Ok(Ok(settings)) = result.map(serde_json::from_value::<crate::model::Settings>)
            else {
                return;
            };
            // The certificate-held section's reading, from the same read.
            // Re-rendered rather than latched: the flag can change under a
            // running window when a contributor completes signup.
            app.evidence_admitted
                .set(settings.admission_evidence_required == Some(true));
            queue::render_private_inference_offer(app, &settings);
            queue::render(app);
        });
        // The group counts, asked on the same refresh as the queue itself.
        // Only `contributable_count` is read from here: the folder's total
        // stays the rows on screen.
        self.call("list_projects", serde_json::json!({}), |app, result| {
            let Ok(value) = result else { return };
            let projects: Vec<crate::model::Project> =
                serde_json::from_value(value.get("projects").cloned().unwrap_or_default())
                    .unwrap_or_default();
            *app.projects.borrow_mut() = projects;
            queue::render(app);
        });
        self.call("list_pending", serde_json::json!({}), |app, result| {
            let Ok(value) = result else { return };
            let entries: Vec<QueueEntry> =
                serde_json::from_value(value.get("pending").cloned().unwrap_or_default())
                    .unwrap_or_default();
            *app.entries.borrow_mut() = entries;
            queue::render(app);
            app.reconcile_card_previews();
        });
        // Why sessions are no longer waiting, as counts.
        //
        // `list_pending` above returns pending entries and nothing else --
        // `queue.pending()` filters on exactly that state -- so the queue
        // cannot answer this from the entries it already holds, however
        // many resolved ones it looks for among them. This is the method
        // that answers it, and it is the only one that does.
        self.call(
            "queue_outcome_counts",
            serde_json::json!({}),
            |app, result| {
                let counts = result
                    .ok()
                    .and_then(|v| serde_json::from_value(v.get("reasons").cloned()?).ok())
                    .unwrap_or_default();
                *app.outcome_counts.borrow_mut() = counts;
                queue::render(app);
            },
        );
        // The queue's week band needs the same rollup History does. It is
        // read here rather than handed over by `history::refresh` so the
        // band is filled in whether or not History has ever been opened;
        // `history_rollup` is a read of counters the daemon already holds.
        self.call("history_rollup", serde_json::json!({}), |app, result| {
            if let Ok(Ok(rollup)) = result.map(serde_json::from_value::<HistoryRollup>) {
                *app.rollup.borrow_mut() = rollup;
                queue::render(app);
            }
        });
        history::refresh(self);
        private_inference::refresh(self);
        settings::refresh(self);
    }

    /// Keep the daemon's scheduled preview for every pending card in sync
    /// with the queue.
    ///
    /// This is the whole of the fan-out this shell now does: one
    /// `preview_request` per card that has not been asked about, and one
    /// `preview_cancel` for every entry that has stopped being pending --
    /// approved, dismissed, expired, or superseded. `dismiss` already
    /// cancels its own entry's scheduled preview implicitly (see the IPC
    /// doc's "Scheduled previews" section), so the cancel sent here for that
    /// case is a harmless no-op (`dropped: false`) rather than a duplicate
    /// of work the daemon already did; what this covers that `dismiss`
    /// cannot is every other way an entry leaves `pending`.
    fn reconcile_card_previews(self: &Rc<Self>) {
        let current: std::collections::HashSet<String> = self
            .entries
            .borrow()
            .iter()
            .filter(|e| e.state == "pending")
            .map(|e| e.entry_id.clone())
            .collect();
        let (gone, wanted) = card_preview_diff(&current, &self.card_tracked.borrow());

        for entry_id in gone {
            self.card_tracked.borrow_mut().remove(&entry_id);
            self.previews.borrow_mut().remove(&entry_id);
            self.previews_too_large.borrow_mut().remove(&entry_id);
            self.call(
                "preview_cancel",
                serde_json::json!({ "entry_id": entry_id }),
                |_app, _result| {},
            );
        }

        for entry_id in wanted {
            self.card_tracked.borrow_mut().insert(entry_id.clone());
            let key = entry_id.clone();
            self.call(
                "preview_request",
                serde_json::json!({ "entry_id": entry_id }),
                move |app, result| app.handle_preview_request_result(&key, result),
            );
        }
    }

    /// What `preview_request` (and, on a cache hit, `preview_ready`) answers
    /// with for one entry.
    ///
    /// `ready` and `too_large` are the only states that ever draw anything:
    /// `queued` and `running` mean the card stays "checking" until an event
    /// or a later poll answers again, and `failed` is left the same way
    /// rather than risking a wrong or alarming label -- the fan-out this
    /// replaces had the identical gap for a `preview` call that errored.
    fn handle_preview_request_result(
        self: &Rc<Self>,
        entry_id: &str,
        result: Result<serde_json::Value, String>,
    ) {
        let Ok(value) = result else { return };
        match parse_preview_outcome(&value) {
            Some(CardOutcome::Ready(summary)) => {
                self.previews
                    .borrow_mut()
                    .insert(entry_id.to_string(), *summary);
                queue::render(self);
            }
            Some(CardOutcome::TooLarge {
                raw_session_bytes,
                limit_bytes,
            }) => {
                self.previews_too_large
                    .borrow_mut()
                    .insert(entry_id.to_string(), (raw_session_bytes, limit_bytes));
                queue::render(self);
            }
            // `queued` / `running`: wait for `preview_ready` or a later
            // poll. `failed`, and any object this daemon build's contract
            // does not answer with: leave the card "checking" rather than
            // drawing a wrong or alarming label.
            None => {}
        }
    }

    /// Ask about exactly the one card a `preview_ready` event named.
    ///
    /// This is the whole of the fix for the request storm the naive version
    /// of this feature had: one event, one targeted `preview_request`, so
    /// filling an N-card queue costs O(N) requests -- one per card resolving
    /// -- rather than a full sweep of the outstanding set on every one of
    /// N events (O(N^2)). `preview_ready_wants_request` is the decision,
    /// pulled out so it is checkable without a daemon or a GTK loop; see its
    /// own doc comment and the tests beside it.
    ///
    /// `entry_id` is `None` only for an event this connection could not read
    /// one off of, which the contract says should not happen for
    /// `preview_ready` -- `resync_required`'s periodic full sweep is what
    /// backstops that case (and any other kind of missed event) without
    /// needing this path to guess.
    fn handle_preview_ready(self: &Rc<Self>, entry_id: Option<String>) {
        let Some(entry_id) = entry_id else { return };
        let wants_request = preview_ready_wants_request(
            &entry_id,
            &self.card_tracked.borrow(),
            &self.previews.borrow(),
            &self.previews_too_large.borrow(),
        );
        if !wants_request {
            return;
        }
        let key = entry_id.clone();
        self.call(
            "preview_request",
            serde_json::json!({ "entry_id": entry_id }),
            move |app, result| app.handle_preview_request_result(&key, result),
        );
    }

    /// Re-poll every card whose scheduled preview has not resolved yet.
    ///
    /// The daemon's answer to a repeat `preview_request` for an
    /// already-ready or already-refused entry is a cache hit with no work
    /// done, and for one still queued or running it is the same "keep
    /// waiting" answer as the first call -- so a full sweep is cheap and
    /// shrinks to nothing as cards resolve. That is what makes it the right
    /// response to `resync_required`, which really has lost track of
    /// everything and has no single id to target -- but it is exactly the
    /// wrong response to an ordinary `preview_ready`, which always names the
    /// one card that changed; see `handle_preview_ready`.
    fn poll_outstanding_previews(self: &Rc<Self>) {
        let outstanding: Vec<String> = {
            let tracked = self.card_tracked.borrow();
            let previews = self.previews.borrow();
            let too_large = self.previews_too_large.borrow();
            tracked
                .iter()
                .filter(|id| !previews.contains_key(*id) && !too_large.contains_key(*id))
                .cloned()
                .collect()
        };
        for entry_id in outstanding {
            let key = entry_id.clone();
            self.call(
                "preview_request",
                serde_json::json!({ "entry_id": entry_id }),
                move |app, result| app.handle_preview_request_result(&key, result),
            );
        }
    }

    /// Reschedule the debounced `preview_visible` call.
    ///
    /// Called on every scroll movement and after every render, so a drag
    /// through the whole list or a queue that just changed shape both
    /// settle on one call a quarter-second after the last thing happened,
    /// rather than one per pixel or one per render.
    pub fn schedule_visible_preview_update(self: &Rc<Self>) {
        if let Some(source) = self.scroll_debounce.borrow_mut().take() {
            source.remove();
        }
        let app = Rc::clone(self);
        let source = glib::timeout_add_local(
            std::time::Duration::from_millis(SCROLL_SETTLE_DEBOUNCE_MS),
            move || {
                app.scroll_debounce.borrow_mut().take();
                app.send_visible_previews();
                glib::ControlFlow::Break
            },
        );
        *self.scroll_debounce.borrow_mut() = Some(source);
    }

    /// Tell the daemon which cards are actually on screen right now.
    ///
    /// Wholesale, matching `preview_visible`'s own contract: this is not a
    /// diff against the last call, it is what is visible *now*, and
    /// visibility only ever reorders scheduled work -- see item 3 of "What
    /// each shell must do" in the preview-scheduler design.
    fn send_visible_previews(self: &Rc<Self>) {
        let ids: Vec<String> = self
            .card_widgets
            .borrow()
            .iter()
            .filter(|(_, widget)| self.card_is_visible(widget))
            .map(|(id, _)| id.clone())
            .collect();
        self.call(
            "preview_visible",
            serde_json::json!({ "entry_ids": ids }),
            |_app, _result| {},
        );
    }

    /// Whether a card's widget overlaps the queue's own scrolled viewport,
    /// measured in the scroller's coordinate space -- which already accounts
    /// for however far the list is scrolled, so this needs no adjustment
    /// value of its own.
    fn card_is_visible(&self, widget: &gtk::Widget) -> bool {
        let Some(bounds) = widget.compute_bounds(&self.queue.scroller) else {
            return false;
        };
        let viewport_height = self.queue.scroller.height() as f32;
        overlaps_viewport(bounds.y(), bounds.height(), viewport_height)
    }

    fn render_health(self: &Rc<Self>, status: &Status) {
        // Two independent conditions, and the banner shows both. The health
        // slot carries one label at a time by design, and `daily-cap-reached`
        // is last in its precedence order -- so a spent upload budget behind
        // a full queue was reported by neither, and the window looked simply
        // broken. The budget line is therefore drawn from
        // `status.daily_budget` rather than waiting for the label.
        let mut lines: Vec<String> = Vec::new();
        if let Some(label) = status.health.last_error_label.as_deref() {
            // The label's own sentence, except when it IS the cap: the
            // budget line below says the same thing with real numbers.
            if label != "daily-cap-reached" || !status.daily_budget.blocked {
                lines.push(copy::health_sentence(label).to_string());
            }
        }
        if status.daily_budget.blocked {
            lines.push(copy::daily_cap_sentence(
                status.daily_budget.blocked_entries,
                status.daily_budget.resets_at,
            ));
        }
        if lines.is_empty() {
            self.health_banner.set_visible(false);
            return;
        }
        self.health_label.set_text(&lines.join("\n\n"));
        // The action belongs to the health label; a spent budget has none,
        // because there is nothing for a contributor to do about it.
        match status
            .health
            .last_error_label
            .as_deref()
            .and_then(copy::health_action)
        {
            Some(action) => {
                self.health_button.set_label(action);
                self.health_button.set_visible(true);
            }
            None => self.health_button.set_visible(false),
        }
        self.health_banner.set_visible(true);
    }

    /// The digest, rate-limited to the daemon's configured interval rather
    /// than a fixed one. Its actions can only ever open the window or
    /// dismiss.
    ///
    /// Posted when either half has something to say. It used to return early
    /// on an empty pending list, which was right while every upload passed
    /// through review -- an empty queue then meant an idle period. An armed
    /// project queues nothing however much it sends, so that early return
    /// meant a contributor who armed everything was never told anything at
    /// all. The contributed half comes off the event (`DigestFacts`) because
    /// it describes traces that were never in this shell's entry list.
    fn post_digest(self: &Rc<Self>, facts: crate::backend::DigestFacts) {
        let entries = self.entries.borrow();
        let pending: Vec<&QueueEntry> = entries.iter().filter(|e| e.state == "pending").collect();
        let waiting = (!pending.is_empty()).then(|| {
            let mut labels: Vec<String> = pending.iter().map(|e| e.project_label.clone()).collect();
            labels.sort();
            labels.dedup();
            crate::notify::digest_body(pending.len(), &labels)
        });
        drop(entries);
        let contributed = crate::notify::contribution_body(
            facts.contributed,
            &facts.contributed_projects,
            facts.credit_pending,
        );
        // Two sentences, either of which may be absent: what is waiting for
        // you, and what went without you. Separate lines because they are
        // about different things and a contributor acts on only one.
        let body = match (waiting, contributed) {
            (Some(w), Some(c)) => format!("{w}\n{c}"),
            (Some(w), None) => w,
            (None, Some(c)) => c,
            (None, None) => return,
        };
        self.notify(copy::APP_NAME, &body);
    }

    /// Post a notification on a thread and, if the contributor pressed
    /// `Review`, bring the window forward at the queue.
    ///
    /// `Review` opens the window. That is the whole of what any notification
    /// action in this application can do.
    pub fn notify(self: &Rc<Self>, summary: &str, body: &str) {
        let (tx, rx) = async_channel::bounded(1);
        let summary = summary.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            if let Some(action) = crate::notify::post(&summary, &body) {
                let _ = tx.send_blocking(action);
            }
        });
        let app = Rc::clone(self);
        glib::spawn_future_local(async move {
            if let Ok(crate::notify::Action::Review) = rx.recv().await {
                app.stack.set_visible_child_name("queue");
                app.window.present();
            }
        });
    }

    pub fn toast(self: &Rc<Self>, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }

    /// Put the number of decisions owed on the switcher's Queue item.
    ///
    /// Called by `queue::render` rather than computed here, so there is
    /// exactly one place that decides which entries count as waiting.
    /// The sidebar's queue badge: the number, and a shield glyph beside it.
    ///
    /// The glyph is ADDED to the count, not substituted for it. At 149
    /// waiting sessions the number is the signal a contributor reads, and an
    /// icon meaning "there is a queue" says strictly less. What the glyph
    /// adds is the one thing the number cannot carry: whether anything in
    /// there wants looking at. See [`crate::shield`].
    pub fn set_queue_count(self: &Rc<Self>, waiting: usize, shield: crate::shield::Shield) {
        let label = match shield {
            // Nothing waiting: the badge is hidden anyway, so the glyph
            // would be a decoration on an invisible widget.
            crate::shield::Shield::Clear => waiting.to_string(),
            crate::shield::Shield::Waiting => format!("{waiting}"),
            crate::shield::Shield::Attention => {
                format!("{waiting} {}", style::Tone::Attention.glyph())
            }
        };
        self.queue_badge.set_label(&label);
        self.queue_badge.set_visible(waiting > 0);
        // A colour is never the only carrier: the glyph above is what
        // survives greyscale, and this is what makes it findable.
        if shield == crate::shield::Shield::Attention {
            self.queue_badge.add_css_class("tc-attention");
        } else {
            self.queue_badge.remove_css_class("tc-attention");
        }
    }

    /// Render the sentence `approve` earns -- see `crate::toast` -- and, when
    /// it says Undo belongs with it, offer one.
    ///
    /// This is the single place both the queue row's Submit and the project
    /// group's Submit all reach the toast, so the two controls cannot drift
    /// in how they read the same response. `entry_ids` is the set the undo
    /// bar's `Undo` must cancel: one id for a row, every entry a project
    /// call approved for a group.
    ///
    /// `offer_undo` is only called when the daemon returned a `hold_until`:
    /// `approve > 0` with no `hold_until` means the hold is configured off,
    /// which the rendered sentence already reports as sent, and there is
    /// nothing left to hold open.
    pub fn render_submit_response(
        self: &Rc<Self>,
        approve: &ApproveResult,
        entry_ids: Vec<String>,
        project_label: &str,
    ) {
        let skipped: Vec<&str> = approve
            .skipped
            .iter()
            .map(|s| s.reason_label.as_str())
            .collect();
        let rendered = crate::toast::toast(
            approve.approved,
            approve.total_redactions(),
            approve.flagged,
            &skipped,
        );
        // What a group selector left out for being ineligible, said after
        // the press as the folder said it before.
        //
        // NOT branched on. `group_withheld_line` answers the empty string
        // for zero, and an absent `excluded_ineligible` -- a single-entry
        // call, or an invited contributor, where no filter ran at all --
        // reads as zero here and draws nothing for the same reason. Reading
        // the absence as a real zero would be claiming "nothing was left
        // out" about a filter that never ran; drawing nothing claims
        // nothing either way.
        //
        // Appended to the toast rather than given a second one: a
        // contributor pressed one button and gets one answer.
        let withheld = crate::copy::group_withheld_line(approve.excluded_ineligible.unwrap_or(0));
        if withheld.is_empty() {
            self.toast(&rendered.line);
        } else {
            self.toast(&format!("{} {withheld}", rendered.line));
        }
        // `ApproveResult::offers_undo` is the single source of truth for
        // this decision -- see its doc comment for the defect it fixes --
        // so this checks it directly rather than re-deriving `rendered`'s
        // half of the same rule here.
        if approve.offers_undo() {
            if let Some(hold_until) = approve.hold_until {
                self.offer_undo(entry_ids, project_label, hold_until);
            }
        }
    }

    /// Offer to take back an approval, on the queue rather than in a toast.
    ///
    /// Recovery belongs on the surface a contributor is already looking at:
    /// a toast is gone in seconds and takes the only path back with it,
    /// whereas the bar stays for the whole of the daemon's hold and says in
    /// words what it can and cannot promise.
    ///
    /// `hold_until` is the daemon's instant from the `approve` response, and
    /// is mandatory here -- see [`App::render_submit_response`] for the
    /// caller-side rule about when it is safe to call this at all.
    pub fn offer_undo(
        self: &Rc<Self>,
        entry_ids: Vec<String>,
        project_label: &str,
        hold_until: chrono::DateTime<chrono::Utc>,
    ) {
        *self.undo.borrow_mut() = Some(PendingUndo {
            entry_ids,
            project_label: project_label.to_string(),
            approved_at: chrono::Utc::now(),
            hold_until,
        });
        queue::render_undo(self);

        // One tick per second, and it only moves the elapsed figure -- the
        // bar is not rebuilt, so a contributor whose pointer is on `Undo`
        // does not have it pulled out from under them.
        //
        // Any tick left over from a previous approval is stopped first. The
        // old one would not have stopped itself: it breaks on the pending
        // undo being absent or expired, and this call has just replaced it
        // with a later one, so it would keep ticking alongside the new timer
        // until the last hold ran out.
        self.stop_undo_tick();
        let app = Rc::clone(self);
        let source = glib::timeout_add_seconds_local(1, move || {
            let expired = app
                .undo
                .borrow()
                .as_ref()
                .is_none_or(|undo| chrono::Utc::now() >= undo.hold_until);
            if expired {
                app.undo.borrow_mut().take();
                // Forget our own handle before breaking, so a later
                // `stop_undo_tick` does not try to remove a source that has
                // already finished.
                app.undo_tick.borrow_mut().take();
                queue::render_undo(&app);
                return glib::ControlFlow::Break;
            }
            queue::render_undo(&app);
            glib::ControlFlow::Continue
        });
        *self.undo_tick.borrow_mut() = Some(source);
    }

    /// Stop the undo bar's tick if one is running. Idempotent.
    fn stop_undo_tick(&self) {
        if let Some(source) = self.undo_tick.borrow_mut().take() {
            source.remove();
        }
    }

    /// Withdraw the undo bar without cancelling: the hold simply runs out.
    pub fn dismiss_undo(self: &Rc<Self>) {
        self.stop_undo_tick();
        self.undo.borrow_mut().take();
        queue::render_undo(self);
    }
}

/// The segmented view switcher, §5.1's Linux column.
///
/// Carry out one [`crate::tray::TrayRequest`].
///
/// A free function rather than the body of `wire_tray`'s loop because the
/// toggle accelerator (`ui::shortcuts`) arrives here as well, and the two
/// surfaces must not each hold their own idea of what a request does. The
/// vocabulary is still the tray's two words, so what a keypress can ask for
/// is bounded by the same type: there is no request that starts answering.
///
/// The window comes up either way, including for the stop: the daemon's
/// answer is a sentence only the model-calls screen renders, and a change
/// nobody can see the result of is the shape both surfaces avoid.
pub(crate) fn apply_tray_request(app: &Rc<App>, request: crate::tray::TrayRequest) {
    match request {
        crate::tray::TrayRequest::Open(screen) => {
            app.stack.set_visible_child_name(screen);
        }
        crate::tray::TrayRequest::StopAnsweringModelCalls => {
            app.stack.set_visible_child_name(PRIVATE_INFERENCE_SCREEN);
            private_inference::turn_off(app);
        }
    }
    app.window.present();
}

/// Hand-built rather than an `AdwViewSwitcher` because the design puts a
/// count badge inside one item, and `AdwViewSwitcher` builds its own buttons
/// from the stack pages' titles and icons with nowhere to put one.
///
/// The stack, not this widget, is the source of truth for which screen is
/// showing: the tray and every notification action set the stack directly,
/// so the items follow it rather than the other way round.
fn view_switcher(stack: &adw::ViewStack, queue_badge: &gtk::Label) -> gtk::Box {
    let track = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(0)
        .valign(gtk::Align::Center)
        .build();
    track.add_css_class("tc-switcher");

    let mut items: Vec<(&'static str, gtk::ToggleButton)> = Vec::new();
    for (index, (name, label, icon_name)) in SCREENS.into_iter().enumerate() {
        let content = gtk::Box::new(gtk::Orientation::Horizontal, style::space::XXS);
        // A real `GtkImage`, not a glyph: §6.6 turns the selected item's icon
        // green while its label stays ink, and style.css matches that on the
        // `image` node rather than on a class this code would have to
        // remember to set.
        let icon = gtk::Image::from_icon_name(icon_name);
        icon.set_pixel_size(SWITCHER_ICON);
        content.append(&icon);
        content.append(&gtk::Label::new(Some(label)));
        if name == "queue" {
            content.append(queue_badge);
        }
        let item = gtk::ToggleButton::builder().child(&content).build();
        item.add_css_class("tc-tab");
        // `flat` drops Adwaita's own button face, so the track underneath is
        // what the unselected items sit on.
        item.add_css_class("flat");
        // How the accelerator is discovered. The chord and nothing else: the
        // item's own label is right beside it, and the text is GTK's --
        // `accelerator_get_label` in the contributor's keyboard and language
        // -- so no word of this is authored in this shell. A shortcuts
        // window would need section and group titles nobody has written,
        // which is the reason it is not one.
        item.set_tooltip_text(shortcuts::screen_accel_label(index).as_deref());
        if let Some((_, first)) = items.first() {
            item.set_group(Some(first));
        }
        let stack = stack.clone();
        item.connect_toggled(move |item| {
            if item.is_active() {
                stack.set_visible_child_name(name);
            }
        });
        track.append(&item);
        items.push((name, item));
    }

    let followers = items.clone();
    stack.connect_notify_local(Some("visible-child-name"), move |stack, _| {
        let Some(showing) = stack.visible_child_name() else {
            return;
        };
        for (name, item) in &followers {
            if *name == showing.as_str() {
                item.set_active(true);
            }
        }
    });
    if let Some((_, first)) = items.first() {
        first.set_active(true);
    }

    track
}

/// A heading and a paragraph, the shape most of this window is made of.
///
/// The heading is set as an eyebrow rather than as a bold sentence: these
/// are field labels over values, not section titles, and setting them as
/// titles made every list of facts read like a stack of headlines.
pub fn titled_paragraph(title: &str, body: &str) -> gtk::Box {
    let container = gtk::Box::new(gtk::Orientation::Vertical, style::space::XXS);
    container.append(&style::eyebrow(title));
    style::append_body(&container, body);
    container
}

/// What a `preview_request` (or a cache-hit `preview_ready`) result decoded
/// to, once the wire object has been read -- see
/// `App::handle_preview_request_result`.
enum CardOutcome {
    /// Boxed because the two variants are otherwise wildly unequal -- a
    /// summary is a few hundred bytes of maps and vectors, the refusal is
    /// two integers -- and every `Option<CardOutcome>` would carry the
    /// larger of the two.
    Ready(Box<PreviewSummary>),
    TooLarge {
        raw_session_bytes: u64,
        limit_bytes: u64,
    },
}

/// Decode a `preview_request` result object into what this shell draws.
///
/// `queued` and `running` -- and anything this build does not recognise --
/// decode to `None`: there is nothing to draw yet, and the caller's answer
/// to `None` is to leave the card exactly as it was. Pulled out from
/// `App::handle_preview_request_result` so the parsing can be checked
/// against real wire shapes without a running daemon.
fn parse_preview_outcome(value: &serde_json::Value) -> Option<CardOutcome> {
    match value.get("state").and_then(|v| v.as_str()) {
        Some(STATE_READY) => {
            let summary = serde_json::from_value(value.get("summary")?.clone()).ok()?;
            Some(CardOutcome::Ready(Box::new(summary)))
        }
        Some(STATE_TOO_LARGE) => Some(CardOutcome::TooLarge {
            raw_session_bytes: value.get("raw_session_bytes")?.as_u64()?,
            limit_bytes: value.get("limit_bytes")?.as_u64()?,
        }),
        _ => None,
    }
}

/// What `App::reconcile_card_previews` does to the tracked set, as pure data
/// rather than daemon calls -- so the actual decision (which ids to cancel,
/// which to request) is checkable without a running `App`.
///
/// Returns `(gone, wanted)`: `gone` is every tracked id no longer in
/// `current` (cancel and forget it), `wanted` is every current id not yet
/// tracked (request one). Both are sorted, only so a test can assert an
/// exact `Vec` rather than a set.
fn card_preview_diff(
    current: &std::collections::HashSet<String>,
    tracked: &std::collections::HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut gone: Vec<String> = tracked.difference(current).cloned().collect();
    let mut wanted: Vec<String> = current.difference(tracked).cloned().collect();
    gone.sort();
    wanted.sort();
    (gone, wanted)
}

/// Whether a widget spanning `[y, y + height)` in the scroller's coordinate
/// space overlaps the visible `[0, viewport_height)` band -- the same
/// interval-overlap test `App::card_is_visible` applies to a real widget's
/// `compute_bounds`, pulled out so the edge cases (exactly at an edge,
/// entirely above, entirely below, taller than the viewport) are checkable
/// with plain numbers.
fn overlaps_viewport(y: f32, height: f32, viewport_height: f32) -> bool {
    y < viewport_height && y + height > 0.0
}

/// Whether a `preview_ready` naming `entry_id` should trigger a fresh
/// `preview_request` -- pulled out of `App::handle_preview_ready` so the
/// per-event cost is checkable directly: this looks at exactly the one id
/// the event named, never at how many other entries are still outstanding,
/// which is what keeps the whole feature at O(N) requests to fill an
/// N-card queue rather than O(N^2). See the tests below, and
/// `App::handle_preview_ready`'s doc comment for the incident this replaces.
fn preview_ready_wants_request(
    entry_id: &str,
    tracked: &std::collections::HashSet<String>,
    previews: &HashMap<String, PreviewSummary>,
    too_large: &HashMap<String, (u64, u64)>,
) -> bool {
    tracked.contains(entry_id)
        && !previews.contains_key(entry_id)
        && !too_large.contains_key(entry_id)
}

#[cfg(test)]
mod card_preview_tests {
    use super::*;
    use std::collections::HashSet;

    fn set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_newly_pending_entry_is_wanted_and_nothing_is_gone() {
        let current = set(&["a", "b"]);
        let tracked = set(&["a"]);
        let (gone, wanted) = card_preview_diff(&current, &tracked);
        assert_eq!(gone, Vec::<String>::new());
        assert_eq!(wanted, vec!["b".to_string()]);
    }

    #[test]
    fn an_entry_that_left_pending_is_gone_and_nothing_new_is_wanted() {
        // Covers approval, dismissal, expiry, and supersession alike: this
        // function only sees "no longer in `current`", not why.
        let current = set(&["a"]);
        let tracked = set(&["a", "b"]);
        let (gone, wanted) = card_preview_diff(&current, &tracked);
        assert_eq!(gone, vec!["b".to_string()]);
        assert_eq!(wanted, Vec::<String>::new());
    }

    #[test]
    fn an_id_already_tracked_is_neither_gone_nor_wanted_again() {
        // The dedup that keeps a render loop from re-requesting a card every
        // time it redraws.
        let current = set(&["a"]);
        let tracked = set(&["a"]);
        let (gone, wanted) = card_preview_diff(&current, &tracked);
        assert!(gone.is_empty());
        assert!(wanted.is_empty());
    }

    #[test]
    fn a_queue_of_five_hundred_reduces_to_exactly_the_new_ones() {
        // The shape of the real incident: a large queue appearing at once
        // must produce exactly the wanted set, not a truncated prefix --
        // this replaces the old `PREVIEW_PREFETCH_LIMIT` fan-out, and the
        // whole point of moving to the daemon's scheduler is that the shell
        // no longer bounds this itself.
        let current: HashSet<String> = (0..500).map(|n| format!("e{n}")).collect();
        let tracked: HashSet<String> = HashSet::new();
        let (gone, wanted) = card_preview_diff(&current, &tracked);
        assert!(gone.is_empty());
        assert_eq!(wanted.len(), 500);
    }

    #[test]
    fn filling_a_five_hundred_card_queue_costs_one_check_per_ready_event() {
        // Pins the property the coordinator asked for directly: N cards
        // resolving, one `preview_ready` each, must cost O(N) decisions --
        // not O(N^2). The naive version of this feature swept every
        // outstanding entry on every `preview_ready`; resolving them one at
        // a time would have cost 500 + 499 + ... + 1 = 125,250 lookups to
        // drain the queue. This loop makes exactly one decision per event
        // and only ever inspects the one id that event names.
        const N: usize = 500;
        let tracked: HashSet<String> = (0..N).map(|n| format!("e{n}")).collect();
        let mut previews: HashMap<String, PreviewSummary> = HashMap::new();
        let too_large: HashMap<String, (u64, u64)> = HashMap::new();

        let mut checks = 0usize;
        let mut resolved = 0usize;
        for n in 0..N {
            let id = format!("e{n}");
            checks += 1;
            if preview_ready_wants_request(&id, &tracked, &previews, &too_large) {
                resolved += 1;
                // Mirror what `handle_preview_request_result` would do once
                // the daemon answers, so the next event (if this id somehow
                // repeated) sees it as settled rather than outstanding.
                previews.insert(
                    id,
                    PreviewSummary {
                        token_distribution_summary: None,
                        would_send_bytes: 0,
                        raw_session_bytes: 0,
                        event_count: 0,
                        opening_prompt: String::new(),
                        redactions: Default::default(),
                        redactions_distinct: Default::default(),
                        pii_labels_present: Vec::new(),
                        consent_scopes: Vec::new(),
                        residual_risk: String::new(),
                        envelope_digest: String::new(),
                        input_fingerprint: String::new(),
                        enrolled: true,
                    },
                );
            }
        }

        // One decision per event, for every event -- linear in N, and in
        // particular not the triangular-number growth (N*(N+1)/2) a
        // sweep-per-event design would have produced.
        assert_eq!(checks, N);
        assert_eq!(resolved, N);
    }

    #[test]
    fn a_ready_event_for_an_entry_this_shell_never_asked_about_requests_nothing() {
        // An entry another client scheduled, or one already swept from the
        // queue, must not turn into a request just because its ready event
        // reached this connection too.
        let tracked: HashSet<String> = HashSet::new();
        let previews: HashMap<String, PreviewSummary> = HashMap::new();
        let too_large: HashMap<String, (u64, u64)> = HashMap::new();
        assert!(!preview_ready_wants_request(
            "untracked",
            &tracked,
            &previews,
            &too_large
        ));
    }

    #[test]
    fn a_ready_event_for_an_already_resolved_entry_requests_nothing_again() {
        // A repeat or stray event for a card already drawn must not fire a
        // second `preview_request` -- the daemon would answer it from cache
        // for free, but there is still no reason to ask twice.
        let tracked: HashSet<String> = ["a".to_string()].into_iter().collect();
        let mut previews: HashMap<String, PreviewSummary> = HashMap::new();
        previews.insert(
            "a".to_string(),
            PreviewSummary {
                token_distribution_summary: None,
                would_send_bytes: 10,
                raw_session_bytes: 10,
                event_count: 1,
                opening_prompt: String::new(),
                redactions: Default::default(),
                redactions_distinct: Default::default(),
                pii_labels_present: Vec::new(),
                consent_scopes: Vec::new(),
                residual_risk: String::new(),
                envelope_digest: String::new(),
                input_fingerprint: String::new(),
                enrolled: true,
            },
        );
        let too_large: HashMap<String, (u64, u64)> = HashMap::new();
        assert!(!preview_ready_wants_request(
            "a", &tracked, &previews, &too_large
        ));
    }

    #[test]
    fn a_ready_event_for_a_tracked_unresolved_entry_requests_it() {
        let tracked: HashSet<String> = ["a".to_string()].into_iter().collect();
        let previews: HashMap<String, PreviewSummary> = HashMap::new();
        let too_large: HashMap<String, (u64, u64)> = HashMap::new();
        assert!(preview_ready_wants_request(
            "a", &tracked, &previews, &too_large
        ));
    }

    #[test]
    fn a_widget_entirely_above_the_viewport_does_not_overlap() {
        assert!(!overlaps_viewport(-200.0, 100.0, 600.0));
    }

    #[test]
    fn a_widget_entirely_below_the_viewport_does_not_overlap() {
        assert!(!overlaps_viewport(700.0, 100.0, 600.0));
    }

    #[test]
    fn a_widget_straddling_the_bottom_edge_overlaps() {
        assert!(overlaps_viewport(590.0, 100.0, 600.0));
    }

    #[test]
    fn a_widget_straddling_the_top_edge_overlaps() {
        assert!(overlaps_viewport(-50.0, 100.0, 600.0));
    }

    #[test]
    fn a_widget_taller_than_the_viewport_still_overlaps() {
        assert!(overlaps_viewport(-1000.0, 5000.0, 600.0));
    }

    #[test]
    fn a_widget_exactly_touching_the_bottom_edge_does_not_overlap() {
        // Half-open on purpose: a card whose top is exactly at the bottom
        // edge shows none of its own pixels.
        assert!(!overlaps_viewport(600.0, 100.0, 600.0));
    }

    #[test]
    fn a_ready_result_decodes_the_real_summary_fields() {
        let value = serde_json::json!({
            "entry_id": "e1",
            "state": "ready",
            "summary": {
                "would_send_bytes": 4096,
                "raw_session_bytes": 2048,
                "event_count": 12,
                "opening_prompt": "fix the thing",
                "redactions": {"generic_secret": 2},
                "pii_labels_present": ["email"],
                "consent_scopes": ["model_training"],
                "residual_risk": "low",
                "envelope_digest": "",
                "input_fingerprint": "fp1",
                "enrolled": true,
            },
        });
        match parse_preview_outcome(&value) {
            Some(CardOutcome::Ready(summary)) => {
                assert_eq!(summary.would_send_bytes, 4096);
                assert_eq!(summary.event_count, 12);
                assert_eq!(summary.opening_prompt, "fix the thing");
                assert_eq!(summary.redactions.get("generic_secret"), Some(&2));
            }
            other => panic!(
                "expected Ready, got a different outcome: {}",
                other.is_some()
            ),
        }
    }

    #[test]
    fn a_too_large_result_decodes_the_raw_size_and_the_limit_and_nothing_else() {
        let value = serde_json::json!({
            "entry_id": "e2",
            "state": "too_large",
            "raw_session_bytes": 385_875_968u64,
            "limit_bytes": 67_108_864u64,
        });
        match parse_preview_outcome(&value) {
            Some(CardOutcome::TooLarge {
                raw_session_bytes,
                limit_bytes,
            }) => {
                assert_eq!(raw_session_bytes, 385_875_968);
                assert_eq!(limit_bytes, 67_108_864);
            }
            other => panic!(
                "expected TooLarge, got a different outcome: {}",
                other.is_some()
            ),
        }
    }

    #[test]
    fn a_queued_result_decodes_to_nothing_to_draw() {
        let value = serde_json::json!({ "entry_id": "e3", "state": "queued" });
        assert!(parse_preview_outcome(&value).is_none());
    }

    #[test]
    fn a_running_result_decodes_to_nothing_to_draw() {
        let value = serde_json::json!({ "entry_id": "e4", "state": "running" });
        assert!(parse_preview_outcome(&value).is_none());
    }

    #[test]
    fn a_failed_result_decodes_to_nothing_to_draw_rather_than_a_wrong_label() {
        let value = serde_json::json!({
            "entry_id": "e5",
            "state": "failed",
            "code": "internal",
            "label": "preview-failed",
        });
        assert!(parse_preview_outcome(&value).is_none());
    }
}

#[cfg(test)]
mod screen_tests {
    use super::*;

    /// The switcher's items and the stack's pages are built by zipping
    /// `SCREENS` with `pages`, so a screen missing from one of the two would
    /// simply never be reachable rather than fail to compile. Both are
    /// fixed-size arrays of the same length for that reason; this pins the
    /// length itself, so the next screen has to grow both.
    #[test]
    fn every_screen_has_a_page() {
        assert_eq!(SCREENS.len(), 4);
        for (name, label, icon) in SCREENS {
            assert!(!name.is_empty(), "a screen needs a stack name");
            assert!(!label.is_empty(), "a screen needs a switcher label");
            assert!(
                icon.ends_with("-symbolic"),
                "{icon} must be symbolic to recolour"
            );
        }
    }

    /// The label is read from the shared copy module, never retyped here.
    #[test]
    fn the_private_ai_screen_takes_its_label_from_the_shared_copy() {
        let (name, label, _) = SCREENS
            .into_iter()
            .find(|(name, _, _)| *name == PRIVATE_INFERENCE_SCREEN)
            .expect("the Private AI screen is one of the switcher's items");
        assert_eq!(name, "private-inference");
        assert_eq!(label, copy::PRIVATE_INFERENCE_DESTINATION);
    }

    /// No switcher label may PROMISE privacy.
    ///
    /// The product name is stripped first, the same way the shared sweep in
    /// `private_inference_copy` strips it: the destination is called
    /// "Private AI" deliberately -- the mental model is a VPN, where the word
    /// has never meant the destination cannot see you -- while no sentence
    /// may claim a call is private, because each one still goes on to
    /// whoever was configured to answer it.
    ///
    /// This guard is a second statement of a rule that lives in the shared
    /// crate, and it drifted from it the moment the name changed: the sweep
    /// was narrowed and this was not, so the rename failed here alone. It is
    /// kept because a shell hardcoding a label is a thing only a shell test
    /// can catch -- but it now strips the same way, so the two cannot
    /// disagree about what the rule is.
    #[test]
    fn no_switcher_label_promises_privacy() {
        for (_, label, _) in SCREENS {
            let lowered = label
                .replace(copy::PRIVATE_INFERENCE_DESTINATION, "")
                .to_ascii_lowercase();
            for forbidden in ["private", "secure", "proxy", "backend"] {
                assert!(
                    !lowered.contains(forbidden),
                    "switcher label {label:?} must not say {forbidden:?}"
                );
            }
        }
    }
}
