//! Look inside, then decide.
//!
//! The design premise, from the shared spec: **never ask the contributor to
//! judge redaction quality.** They cannot, and showing redacted text beside
//! an Approve button asks for a rubber stamp. So the sheet answers the two
//! questions they can answer -- is this project OK to share at all, and is
//! there anything specific in here that must not leave -- and Search is the
//! first tab with the cursor already in it, because that is the highest
//! value affordance in the product: someone under an NDA gets certainty in
//! five seconds without reading 148 turns.
//!
//! `Contribute` exists here and nowhere else, it has no keyboard shortcut,
//! and it is followed by an undo counted against the daemon's own deadline.
//! It waits on one thing only: a real, pinned preview to approve against.
//!
//! It used to wait on two more -- the transcript tab having been on screen,
//! and an acknowledgement checkbox ticked by hand. Both are gone. A queue
//! row's `Submit` approves the same session with no preview opened at all,
//! so the gate never stood between anybody and a blind approval; all it did
//! was charge a click to the one contributor who chose to look. What the
//! checkbox asserted survives as `copy::GATE_STATEMENT`, printed on the
//! footer where the tick used to be asked for, because removing the
//! friction must not quietly remove the claim.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use super::App;
use super::style::{self, Tone, space};
use crate::copy;
use crate::model::{ApproveResult, PreviewSummary, human_bytes, human_when};
use crate::transcript_paging::{self, ResidentChunks, TranscriptDocument};

/// Open the preview sheet on the `index`-th pending entry.
pub fn open(app: &Rc<App>, index: usize) {
    open_with_search(app, index, None, None)
}

/// As `open`, with a search term already typed and, optionally, a tab other
/// than Search already showing. Used by the headless container run to
/// photograph a real search result and a real redacted transcript; a person
/// types theirs and clicks their own tab.
pub fn open_with_search(app: &Rc<App>, index: usize, term: Option<String>, tab: Option<String>) {
    let entries = app.entries.borrow();
    let pending: Vec<crate::model::QueueEntry> = entries
        .iter()
        .filter(|e| e.state == "pending")
        .cloned()
        .collect();
    drop(entries);
    if index >= pending.len() {
        return;
    }
    Sheet::present(app, pending, index, term, tab);
}

struct Sheet {
    app: Rc<App>,
    witness_button: gtk::Button,
    immutable_note: gtk::Label,
    admission_button: gtk::Button,
    admission_message: gtk::Label,
    admission_required: Cell<bool>,
    admission_supported: Cell<bool>,
    admission_busy: Cell<bool>,
    witness_requested: Cell<bool>,
    witness_busy: Cell<bool>,
    witness_supported: Cell<bool>,
    window: adw::Window,
    title: adw::WindowTitle,
    pending: Vec<crate::model::QueueEntry>,
    index: RefCell<usize>,

    /// The identity row of the sheet header: who ran this, with what, and
    /// when. The same three facts the queue row led with.
    identity_project: gtk::Label,
    identity_agent: gtk::Label,
    identity_when: gtk::Label,

    /// The same four fields the queue row carried, kept in view on every
    /// tab. A person who is deciding should not have to go back to a tab to
    /// re-read what the payload was.
    manifest_slot: gtk::Box,

    /// The two counts the tab strip carries: how many turns are in the
    /// trace, and how many permissions the contribution would run under.
    /// Both are read off the pinned preview, never typed in.
    count_whats_in_it: gtk::Label,
    count_permissions: gtk::Label,

    search_entry: gtk::SearchEntry,
    search_results: gtk::Box,
    search_summary: gtk::Label,
    recent_row: gtk::Box,

    whats_in_it: gtk::Box,
    /// The removed-summary panel, above the transcript on the same tab.
    ///
    /// Rebuilt from the pinned preview on every `fill`, like `whats_in_it`
    /// and `permissions`: it describes one session and must never survive
    /// the sheet advancing to the next one.
    removed_summary: gtk::Box,
    /// The transcript tab's body, chunked and evicting. See
    /// `crate::transcript_paging` for why it is not one text view.
    transcript: Rc<TranscriptPane>,
    /// Puts the whole redacted body on the clipboard. Selection is per
    /// chunk now, so this is how a person takes all of it at once; copying
    /// is a string copy rather than a layout, so it is bounded work however
    /// large the body is.
    copy_all: gtk::Button,
    permissions: gtk::Box,

    /// Whether the preview now showing is bindable to an approval at all.
    /// An unenrolled build previews against a placeholder identity, so there
    /// is nothing for a `Contribute` to cover.
    pinned: Cell<bool>,

    contribute: gtk::Button,
    /// Why `Contribute` is off, when eligibility is what turned it off.
    ///
    /// A dark button with no sentence beside it is the same defect one
    /// click deeper: the contributor is left to guess. Hidden entirely for
    /// an entry with no eligibility field, and for an eligible one -- there
    /// is nothing to explain about a control that works.
    eligibility_note: gtk::Label,
    /// The redacted body for the entry currently shown, when this
    /// deployment can serve one. See `backend`.
    body: RefCell<Option<String>>,

    /// The verdict toggle group, in `Worked` / `Partly` / `Failed` order --
    /// held so `load` can clear the selection when a new entry replaces
    /// the one this sheet was showing.
    verdict_buttons: Vec<gtk::ToggleButton>,
    /// The contributor's answer to `copy::VERDICT_QUESTION`, one of
    /// `worked` / `partly` / `failed`, or `None` when they have not
    /// answered. Reset to `None` on every `load` -- a new entry is a new
    /// decision, and no previous verdict may carry into it. Sent as
    /// `approve`'s `outcome` parameter, omitted entirely when `None`; see
    /// `ApproveTarget` in `ui::queue`.
    verdict: RefCell<Option<&'static str>>,
    /// The correction control: prompt, box and disclosure caption, held
    /// together so the verdict handler can show and hide all three as one
    /// thing. Hidden under `Worked` and under no answer at all.
    correction_group: gtk::Box,
    /// The box itself, held separately so `load` can empty it and
    /// `approve_current` can read it.
    correction_view: gtk::TextView,
}

/// One tab of the preview strip: the stack child it shows, its label, and
/// the icon that keeps it legible at a glance.
struct Tab {
    name: &'static str,
    label: &'static str,
    icon: &'static str,
}

/// The four tabs, in the order the shared spec gives them. Search is first
/// because it is the question a contributor can actually answer.
const TABS: [Tab; 4] = [
    Tab {
        name: "search",
        label: copy::TAB_SEARCH,
        icon: "system-search-symbolic",
    },
    Tab {
        name: "whats-in-it",
        label: copy::TAB_WHATS_IN_IT,
        icon: "view-list-symbolic",
    },
    Tab {
        name: "would-be-sent",
        label: copy::TAB_WOULD_BE_SENT,
        icon: "text-x-generic-symbolic",
    },
    Tab {
        name: "permissions",
        label: copy::TAB_PERMISSIONS,
        icon: "emblem-ok-symbolic",
    },
];

/// The stack child that shows the redacted body itself.
const TRANSCRIPT_TAB: &str = "would-be-sent";

impl Sheet {
    fn present(
        app: &Rc<App>,
        pending: Vec<crate::model::QueueEntry>,
        index: usize,
        term: Option<String>,
        tab: Option<String>,
    ) {
        let window = adw::Window::builder()
            .transient_for(&app.window)
            .modal(true)
            .default_width(900)
            .default_height(720)
            .build();

        let title = adw::WindowTitle::new("", "");
        let header = adw::HeaderBar::builder().title_widget(&title).build();
        header.add_css_class("tc-header");
        // The Turn, at the same 20px the main window's header bar uses. This
        // sheet is modal over that window, so both marks are on screen at
        // once -- a superseded mark here would be visible beside the adopted
        // one rather than merely stale.
        header.pack_start(&super::mark::framed(20));

        // The sheet header: who and when, then the manifest strip, then the
        // one sentence that has to survive every other word on the screen.
        // The spec draws it as a full-bleed band on the card surface; this
        // shell has no full-bleed surface class, so it is drawn as a card in
        // the same margins as everything else in the window.
        let identity_project = gtk::Label::builder().xalign(0.0).wrap(true).build();
        identity_project.add_css_class("tc-card-title");
        let identity_agent = gtk::Label::builder().xalign(0.0).build();
        identity_agent.add_css_class("tc-meta");
        let identity_when = gtk::Label::builder().xalign(1.0).build();
        identity_when.add_css_class("tc-meta");
        let identity_spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        identity_spacer.set_hexpand(true);
        let identity = gtk::Box::new(gtk::Orientation::Horizontal, space::S);
        identity.append(&identity_project);
        identity.append(&identity_agent);
        identity.append(&identity_spacer);
        identity.append(&identity_when);

        let manifest_slot = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();

        // Green, a padlock's worth of words, and a glyph -- the status of
        // the whole sheet, said before anything asks for a decision.
        let status_row = gtk::Box::new(gtk::Orientation::Horizontal, space::S);
        let status_chip = style::tag(copy::NOTHING_SENT_YET, Tone::Clear);
        status_chip.set_valign(gtk::Align::Center);
        let reassurance = gtk::Label::builder()
            .label(copy::NOTHING_SENT_REASSURANCE)
            .xalign(0.0)
            .wrap(true)
            .hexpand(true)
            .build();
        reassurance.add_css_class("tc-meta");
        status_row.append(&status_chip);
        status_row.append(&reassurance);

        let sheet_header = style::card(gtk::Orientation::Vertical, space::S);
        sheet_header.set_margin_top(space::M);
        sheet_header.set_margin_start(space::L);
        sheet_header.set_margin_end(space::L);
        sheet_header.append(&identity);
        sheet_header.append(&manifest_slot);
        sheet_header.append(&status_row);

        let stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::None)
            .vexpand(true)
            .build();

        // 1. Search, first and focused.
        let search_entry = gtk::SearchEntry::new();
        search_entry.set_placeholder_text(Some("Anything that must not leave this machine"));
        search_entry.set_hexpand(true);
        let search_button = gtk::Button::with_label(copy::SEARCH_SUBMIT);
        search_button.add_css_class("tc-quiet");
        let search_field = gtk::Box::new(gtk::Orientation::Horizontal, space::S);
        search_field.append(&search_entry);
        search_field.append(&search_button);

        // The match count is the loudest thing on the tab when there is
        // one, and the quietest when there is not. It is set at the screen
        // title's step because it is the answer the whole tab exists for.
        let search_summary = gtk::Label::builder().xalign(0.0).wrap(true).build();
        search_summary.add_css_class("tc-screen-title");
        let search_results = gtk::Box::new(gtk::Orientation::Vertical, space::S);
        let recent_row = gtk::Box::new(gtk::Orientation::Horizontal, space::XS);
        let recent_label = gtk::Label::new(Some(copy::RECENT_LABEL));
        recent_label.add_css_class("tc-meta");
        let recents = gtk::Box::new(gtk::Orientation::Horizontal, space::XS);
        recents.append(&recent_label);
        recents.append(&recent_row);
        let search_page = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::M)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::L)
            .margin_end(space::L)
            .build();
        style::append_body(&search_page, copy::SEARCH_PROMPT);
        search_page.append(&search_field);
        search_page.append(&recents);
        search_page.append(&search_summary);
        let results_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&search_results)
            .build();
        search_page.append(&results_scroller);
        stack.add_titled(&search_page, Some("search"), copy::TAB_SEARCH);

        // 2. What's in it.
        let whats_in_it = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::M)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::L)
            .margin_end(space::L)
            .build();
        let whats_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&whats_in_it)
            .build();
        stack.add_titled(&whats_scroller, Some("whats-in-it"), copy::TAB_WHATS_IN_IT);

        // 3. Exactly what would be sent.
        //
        // The body is chunked and only the chunks near the viewport are laid
        // out; see `TranscriptPane` and `crate::transcript_paging`. What used
        // to be here was a single text view clamped to 64 KB with a notice
        // saying the rest was not displayed. Every byte is reachable now, so
        // that sentence is gone with the clamp it described.
        let transcript = TranscriptPane::new();
        // The caption states the framing before the bytes arrive, and it
        // names a marker so the first chip a person meets is one they have
        // already been told about.
        let body_caption = gtk::Label::builder()
            .label(copy::TRANSCRIPT_CAPTION)
            .xalign(0.0)
            .wrap(true)
            .hexpand(true)
            .build();
        body_caption.add_css_class("tc-meta");
        let copy_all = gtk::Button::with_label(copy::TRANSCRIPT_COPY_ALL);
        copy_all.add_css_class("flat");
        copy_all.set_valign(gtk::Align::Start);
        copy_all.set_sensitive(false);
        let body_head = gtk::Box::new(gtk::Orientation::Horizontal, space::S);
        body_head.append(&body_caption);
        body_head.append(&copy_all);
        let body_panel = style::card(gtk::Orientation::Vertical, 0);
        body_panel.append(&transcript.scroller);
        // Above the marks rather than below them: it is the at-a-glance
        // half, and a person who reads only the top of this tab should
        // still have been told what left.
        let removed_summary = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::S)
            .build();
        let body_page = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::M)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::L)
            .margin_end(space::L)
            .build();
        body_page.append(&body_head);
        body_page.append(&removed_summary);
        body_page.append(&body_panel);
        stack.add_titled(&body_page, Some(TRANSCRIPT_TAB), copy::TAB_WOULD_BE_SENT);

        // 4. Permissions.
        let permissions = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::M)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::L)
            .margin_end(space::L)
            .build();
        // The permissions list is one document, so it is one card rather
        // than a run of loose paragraphs on the ground.
        permissions.add_css_class("tc-card");
        permissions.set_valign(gtk::Align::Start);
        let permissions_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&permissions)
            .build();
        stack.add_titled(
            &permissions_scroller,
            Some("permissions"),
            copy::TAB_PERMISSIONS,
        );

        stack.set_visible_child_name("search");

        // The tab strip: a segmented control rather than a
        // `GtkStackSwitcher`, because two of the four tabs carry a count and
        // a switcher has nowhere to put one. The selected item is a raised
        // pill on the surface colour with no border -- the Linux column of
        // the spec, and the one place in this window where a shadow is
        // allowed. See `.tc-tab` in `style.css`.
        let count_whats_in_it = gtk::Label::new(None);
        count_whats_in_it.add_css_class("tc-tab-count");
        let count_permissions = gtk::Label::new(None);
        count_permissions.add_css_class("tc-tab-count");
        let tab_track = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(space::XXS)
            .halign(gtk::Align::Center)
            .margin_top(space::M)
            .build();
        tab_track.add_css_class("tc-tab-track");
        let mut tab_buttons: Vec<gtk::ToggleButton> = Vec::with_capacity(TABS.len());
        for tab in &TABS {
            let button = gtk::ToggleButton::new();
            button.add_css_class("tc-tab");
            let inner = gtk::Box::new(gtk::Orientation::Horizontal, space::XXS);
            let icon = gtk::Image::from_icon_name(tab.icon);
            icon.set_pixel_size(11);
            inner.append(&icon);
            inner.append(&gtk::Label::new(Some(tab.label)));
            match tab.name {
                "whats-in-it" => inner.append(&count_whats_in_it),
                "permissions" => inner.append(&count_permissions),
                _ => {}
            }
            button.set_child(Some(&inner));
            // One selection, not four independent toggles.
            if let Some(first) = tab_buttons.first() {
                button.set_group(Some(first));
            }
            button.set_active(tab.name == "search");
            let stack_for_tab = stack.clone();
            let name = tab.name;
            button.connect_toggled(move |button| {
                if button.is_active() {
                    stack_for_tab.set_visible_child_name(name);
                }
            });
            tab_track.append(&button);
            tab_buttons.push(button);
        }

        // What the acknowledgement checkbox used to make a contributor
        // tick, said as a statement instead. It sits where the gate did --
        // last thing above the buttons -- because that is where somebody is
        // standing when they reach for `Contribute`.
        let gate_statement = gtk::Label::builder()
            .label(copy::GATE_STATEMENT)
            .xalign(0.0)
            .wrap(true)
            .build();
        gate_statement.add_css_class("tc-caveat");
        gate_statement.add_css_class("tc-tertiary");

        // The daemon's answer about this session, in the shared crate's
        // words. Empty and hidden until `sync_contribute` fills it, which
        // is also the one place the button's state is decided -- so the
        // sentence and the button cannot disagree about why.
        let eligibility_note = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .build();
        eligibility_note.add_css_class("tc-caveat");

        // The concession, on the footer rather than on a tab, so it is on
        // screen at the moment of the decision whichever tab is open. See
        // `copy::RESIDUAL_RISK`.
        let residual_risk = style::caveat(copy::RESIDUAL_RISK);

        // The verdict question: entirely optional, and it never gates
        // `Contribute` -- a contributor who does not answer is
        // `TaskSuccess::Unknown`, a valid outcome the daemon expects to
        // see. Reuses the tab strip's segmented-control styling
        // (`.tc-tab-track` / `.tc-tab`) rather than a new one, so this
        // stays the same brand rather than borrowing the GNOME accent.
        let verdict_question = style::caveat(copy::VERDICT_QUESTION);

        let verdict_track = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(space::XXS)
            .halign(gtk::Align::Start)
            .build();
        verdict_track.add_css_class("tc-tab-track");

        let mut verdict_buttons: Vec<gtk::ToggleButton> = Vec::with_capacity(3);
        for label in [
            copy::VERDICT_WORKED,
            copy::VERDICT_PARTLY,
            copy::VERDICT_FAILED,
        ] {
            let button = gtk::ToggleButton::with_label(label);
            button.add_css_class("tc-tab");
            if let Some(first) = verdict_buttons.first() {
                button.set_group(Some(first));
            }
            verdict_track.append(&button);
            verdict_buttons.push(button);
        }

        // Load-bearing, not decoration -- see `copy::VERDICT_CAPTION`: this
        // is where the shown-bytes guarantee's one exemption is disclosed.
        let verdict_caption = gtk::Label::builder()
            .label(copy::VERDICT_CAPTION)
            .xalign(0.0)
            .wrap(true)
            .build();
        verdict_caption.add_css_class("tc-caveat");
        verdict_caption.add_css_class("tc-tertiary");

        // The correction control. Shown only under `Partly` and `Failed`:
        // you cannot correct a run you have just called successful, and the
        // gate is a guard as much as it is semantics -- it halves the
        // surface for correction-shaped credit farming and puts the field
        // only where a correction means something.
        //
        // Optional throughout. `Contribute` is never gated on it; see
        // `sync_contribute`, which does not read it.
        let correction_question = style::caveat(copy::CORRECTION_QUESTION);

        let correction_view = gtk::TextView::builder()
            .wrap_mode(gtk::WrapMode::WordChar)
            .accepts_tab(false)
            .top_margin(space::XS)
            .bottom_margin(space::XS)
            .left_margin(space::XS)
            .right_margin(space::XS)
            .build();
        correction_view.set_tooltip_text(Some(copy::CORRECTION_PLACEHOLDER));
        let correction_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .min_content_height(72)
            .max_content_height(160)
            .child(&correction_view)
            .build();
        correction_scroll.add_css_class("tc-field");

        // The disclosure, in full and never abbreviated for layout -- see
        // `copy::CORRECTION_CAPTION`. Until the published policy page
        // carves the correction out of its "redacted locally, re-applied
        // on the server" promise, this label is the only place a
        // contributor is told their own words are stored as typed.
        let correction_caption = gtk::Label::builder()
            .label(copy::CORRECTION_CAPTION)
            .xalign(0.0)
            .wrap(true)
            .build();
        correction_caption.add_css_class("tc-caveat");
        correction_caption.add_css_class("tc-tertiary");

        let correction_group = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::XS)
            .build();
        correction_group.append(&correction_question);
        correction_group.append(&correction_scroll);
        correction_group.append(&correction_caption);
        correction_group.set_visible(false);

        let skip = gtk::Button::with_label(copy::NOT_THIS_ONE);
        skip.add_css_class("tc-quiet");
        skip.set_tooltip_text(Some(copy::NOT_THIS_ONE_TOOLTIP));
        let close = gtk::Button::with_label(copy::CLOSE);
        close.add_css_class("tc-quiet");
        let contribute = gtk::Button::with_label(copy::CONTRIBUTE);
        // `.suggested-action` fills with `accent_bg_color` and labels with
        // `accent_fg_color`, which `style` sets to the measured pair. This
        // is the one irreversible control in the product; a label nobody
        // can read on it is not a consent action. See `ui::style`.
        contribute.add_css_class("suggested-action");
        contribute.add_css_class("tc-primary");
        contribute.set_sensitive(false);
        // Deliberately no accelerator and no default-widget binding: the
        // one irreversible action in the product is reachable by pointing
        // at it and nothing else.
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        let actions = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(space::S)
            .build();
        actions.append(&skip);
        actions.append(&spacer);
        actions.append(&close);
        actions.append(&contribute);

        // A rule above the footer, so the statement and the actions sit on a
        // footer rather than floating under whichever tab happens to be
        // open.
        let footer_rule = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        footer_rule.add_css_class("tc-rule");
        footer_rule.set_height_request(1);
        let footer = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(space::S)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::L)
            .margin_end(space::L)
            .build();
        footer.append(&residual_risk);
        footer.append(&gate_statement);
        footer.append(&eligibility_note);
        let immutable_note = gtk::Label::builder()
            .label(
                trace_commons_contributor::witness_copy::witness_copy()
                    .review
                    .immutable,
            )
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .build();
        footer.append(&immutable_note);
        footer.append(&verdict_question);
        footer.append(&verdict_track);
        footer.append(&verdict_caption);
        footer.append(&correction_group);
        let witness_button = gtk::Button::with_label(
            trace_commons_contributor::witness_copy::witness_copy()
                .review
                .action,
        );
        witness_button.set_visible(false);
        footer.append(&witness_button);
        let admission_button = gtk::Button::with_label(
            trace_commons_contributor::witness_copy::witness_copy()
                .admission
                .heading,
        );
        admission_button.set_visible(false);
        let admission_message = gtk::Label::builder().wrap(true).xalign(0.0).build();
        footer.append(&admission_button);
        footer.append(&admission_message);
        footer.append(&actions);

        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.add_css_class("tc-root");
        content.append(&header);
        content.append(&sheet_header);
        content.append(&tab_track);
        content.append(&stack);
        content.append(&footer_rule);
        content.append(&footer);
        window.set_content(Some(&content));

        let sheet = Rc::new(Sheet {
            app: Rc::clone(app),
            witness_button: witness_button.clone(),
            immutable_note,
            admission_button: admission_button.clone(),
            admission_message,
            admission_required: Cell::new(false),
            admission_supported: Cell::new(false),
            admission_busy: Cell::new(false),
            witness_requested: Cell::new(false),
            witness_busy: Cell::new(false),
            witness_supported: Cell::new(false),
            window: window.clone(),
            title,
            pending,
            index: RefCell::new(index),
            identity_project,
            identity_agent,
            identity_when,
            manifest_slot,
            count_whats_in_it,
            count_permissions,
            search_entry: search_entry.clone(),
            search_results,
            search_summary,
            recent_row,
            whats_in_it,
            removed_summary,
            transcript: Rc::clone(&transcript),
            copy_all: copy_all.clone(),
            permissions,
            pinned: Cell::new(false),
            contribute: contribute.clone(),
            eligibility_note: eligibility_note.clone(),
            body: RefCell::new(None),
            verdict_buttons: verdict_buttons.clone(),
            verdict: RefCell::new(None),
            correction_group: correction_group.clone(),
            correction_view: correction_view.clone(),
        });

        let admission_sheet = Rc::clone(&sheet);
        admission_button.connect_clicked(move |_| admission_sheet.confirm_admission());
        let admission_sheet = Rc::clone(&sheet);
        app.call("get_settings", serde_json::json!({}), move |_, result| {
            admission_sheet
                .admission_required
                .set(result.as_ref().is_ok_and(admission_required_by_settings));
            admission_sheet.sync_witness();
        });
        let witness_sheet = Rc::clone(&sheet);
        witness_button.connect_clicked(move |_| witness_sheet.confirm_witness());
        let witness_sheet = Rc::clone(&sheet);
        app.call("hello", serde_json::json!({}), move |_, result| {
            witness_sheet.admission_supported.set(
                result
                    .as_ref()
                    .ok()
                    .and_then(|v| v.get("methods"))
                    .and_then(|v| v.as_array())
                    .is_some_and(|methods| {
                        methods
                            .iter()
                            .any(|v| v.as_str() == Some("prepare_admission_session"))
                    }),
            );
            let supported = result
                .ok()
                .and_then(|value| value.get("methods").cloned())
                .and_then(|value| value.as_array().cloned())
                .is_some_and(|methods| {
                    methods
                        .iter()
                        .any(|method| method.as_str() == Some("witness_preview_request"))
                });
            witness_sheet.witness_supported.set(supported);
            witness_sheet.sync_witness();
        });

        for (button, name) in verdict_buttons.iter().zip(["worked", "partly", "failed"]) {
            let s = Rc::clone(&sheet);
            button.connect_toggled(move |button| {
                // Written as a total match on `is_active()`, not an `if`:
                // GTK 4 grouped `ToggleButton`s do not universally behave as
                // strict radios, and a click that clears the group (leaving
                // nothing visibly selected) must also clear `verdict` --
                // otherwise the approval would carry a verdict the
                // contributor just visibly withdrew.
                let mut v = s.verdict.borrow_mut();
                if button.is_active() {
                    *v = Some(name);
                } else if *v == Some(name) {
                    *v = None;
                }
                let shown = matches!(*v, Some("partly") | Some("failed"));
                drop(v);
                s.set_correction_visible(shown);
            });
        }

        let s = Rc::clone(&sheet);
        search_entry.connect_search_changed(move |entry| {
            s.run_search(&entry.text(), false);
        });
        let s = Rc::clone(&sheet);
        search_entry.connect_activate(move |entry| {
            s.remember_search(&entry.text());
            s.run_search(&entry.text(), true);
        });
        let s = Rc::clone(&sheet);
        search_button.connect_clicked(move |_| {
            let term = s.search_entry.text();
            s.remember_search(&term);
            s.run_search(&term, true);
        });
        let s = Rc::clone(&sheet);
        skip.connect_clicked(move |_| s.dismiss_current());
        let s = Rc::clone(&sheet);
        contribute.connect_clicked(move |_| s.approve_current());
        let window_for_close = window.clone();
        close.connect_clicked(move |_| window_for_close.close());
        // Selection is per chunk now -- a chunk that is not laid out has
        // nothing to select -- so whole-body selection is traded for
        // whole-body copying. Copying is a string copy rather than a
        // layout, so it stays bounded work at any size.
        let s = Rc::clone(&sheet);
        copy_all.connect_clicked(move |button| {
            if let Some(text) = s.transcript.whole_text() {
                button.clipboard().set_text(&text);
            }
        });

        // Keep the tab strip's own selection in step with the stack,
        // however the stack was moved -- the strip, a programmatic open, or
        // a future keyboard path.
        let buttons = tab_buttons.clone();
        stack.connect_visible_child_name_notify(move |stack| {
            let Some(name) = stack.visible_child_name() else {
                return;
            };
            let name = name.as_str();
            for (button, tab) in buttons.iter().zip(TABS.iter()) {
                if tab.name == name {
                    button.set_active(true);
                }
            }
        });

        sheet.load();
        window.present();
        search_entry.grab_focus();
        if let Some(term) = term {
            search_entry.set_text(&term);
        }
        if let Some(tab) = tab {
            stack.set_visible_child_name(&tab);
        }
    }

    fn current(&self) -> Option<&crate::model::QueueEntry> {
        self.pending.get(*self.index.borrow())
    }

    /// The entry now showing, resolved against the LIVE queue by id.
    ///
    /// **`self.pending` is a copy, taken when the sheet opened.** That is
    /// right for everything the sheet displays -- a transcript must not
    /// rearrange itself under somebody reading it -- and wrong for exactly
    /// one thing: whether this session may still be sent.
    ///
    /// A submit-time failure writes its reason back into the row (Decision 1
    /// of the eligibility design), so a row CAN be downgraded to
    /// `ineligible_permanent` while a sheet sits open on it. Nothing undoes
    /// the gate in that case; the gate goes on reading a copy that stopped
    /// being true, and offers `Contribute` for a session the server will
    /// refuse. Recomputing faithfully from a stale snapshot recomputes the
    /// same wrong answer forever.
    ///
    /// Only the gate and its sentence read this. What an approval actually
    /// covers still goes through the pinned entry -- the same id either way
    /// -- so nothing a contributor started moves under them mid-read.
    ///
    /// It reads the queue rather than assuming the worst: an entry that has
    /// become eligible arms the control, the same as one that stopped being
    /// eligible disarms it.
    ///
    /// Falls back to the held copy when the id is not in the live queue at
    /// all. That is not staleness -- there is no newer answer to read -- and
    /// inventing an ineligibility from an absence would disarm a control on
    /// no evidence.
    fn current_live(&self) -> Option<crate::model::QueueEntry> {
        let held = self.current()?;
        let live = self
            .app
            .entries
            .borrow()
            .iter()
            .find(|e| e.entry_id == held.entry_id)
            .cloned();
        Some(live.unwrap_or_else(|| held.clone()))
    }

    /// Fetch the preview for the entry now showing.
    ///
    /// Deliberately re-previewed rather than read from the row cache: a
    /// preview pins the entry to the exact envelope it describes, and the
    /// approval that may follow covers those bytes. Approving against a
    /// summary fetched minutes ago would be approving something the daemon
    /// is no longer holding.
    fn sync_witness(&self) {
        self.admission_button.set_visible(admission_control_visible(
            self.admission_required.get(),
            self.admission_supported.get(),
            self.pinned.get(),
        ));
        self.admission_button
            .set_sensitive(!self.admission_busy.get() && !self.witness_busy.get());
        let configured = super::settings::witness_read(&self.app.worker.dir).state
            == trace_commons_contributor::witness::status::WitnessTrustState::Pinned;
        self.immutable_note
            .set_visible(configured || self.witness_requested.get());
        self.witness_button
            .set_visible(configured && self.witness_supported.get() && !self.pinned.get());
        self.witness_button
            .set_sensitive(!self.witness_busy.get() && !self.admission_busy.get());
        for button in &self.verdict_buttons {
            button.set_sensitive(!configured && !self.witness_requested.get());
        }
        self.correction_view
            .set_editable(!configured && !self.witness_requested.get());
    }

    fn confirm_admission(self: &Rc<Self>) {
        if !self.admission_required.get()
            || !self.admission_supported.get()
            || self.admission_busy.get()
            || self.witness_busy.get()
        {
            return;
        }
        let copy = trace_commons_contributor::witness_copy::witness_copy().admission;
        let backend = gtk::Entry::builder().placeholder_text(copy.backend).build();
        let dialog = adw::MessageDialog::builder()
            .transient_for(&self.window)
            .modal(true)
            .heading(copy.heading)
            .body(copy.disclosure)
            .extra_child(&backend)
            .build();
        dialog.add_responses(&[("cancel", copy.cancel), ("prepare", copy.confirm)]);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        dialog.set_response_enabled("prepare", false);
        backend.connect_changed({
            let dialog = dialog.clone();
            move |entry| dialog.set_response_enabled("prepare", !entry.text().trim().is_empty())
        });
        let sheet = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "prepare" || sheet.admission_busy.replace(true) { return; }
            let Some(entry) = sheet.pending.get(*sheet.index.borrow()) else { sheet.admission_busy.set(false); return; };
            sheet.admission_message.set_label(trace_commons_contributor::witness_copy::witness_copy().admission.working); sheet.sync_witness();
            let result_sheet = sheet.clone();
            let prepared_entry = entry.entry_id.clone();
            sheet.app.call("prepare_admission_session", serde_json::json!({"entry_id":entry.entry_id,"backend":backend.text().trim(),"confirmed":true}), move |_, result| {
                let (ready, text) = admission_outcome(&result);
                result_sheet.admission_busy.set(false);
                if result_sheet.current().is_none_or(|entry| entry.entry_id != prepared_entry) { result_sheet.sync_witness(); return; }
                if ready { result_sheet.admission_message.remove_css_class("tc-refused"); }
                else { result_sheet.admission_message.add_css_class("tc-refused"); }
                result_sheet.admission_message.set_label(&text);
                result_sheet.sync_witness();
            });
        });
        dialog.present();
    }

    fn confirm_witness(self: &Rc<Self>) {
        if !self.witness_supported.get() || self.witness_busy.get() {
            return;
        }
        let copy = trace_commons_contributor::witness_copy::witness_copy().review;
        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(copy.heading),
            Some(copy.disclosure),
        );
        dialog.add_responses(&[("cancel", copy.cancel), ("review", copy.confirm)]);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let sheet = Rc::clone(self);
        dialog.connect_response(None, move |dialog, response| {
            dialog.close();
            if response != "review" || sheet.witness_busy.replace(true) {
                return;
            }
            let Some(entry) = sheet.current() else {
                sheet.witness_busy.set(false);
                return;
            };
            sheet.witness_requested.set(true);
            sheet.pinned.set(false);
            sheet.sync_contribute();
            sheet.sync_witness();
            let copy = trace_commons_contributor::witness_copy::witness_copy().review;
            sheet.search_summary.set_text(copy.working);
            sheet.transcript.show_sentence(copy.working);
            let result_sheet = Rc::clone(&sheet);
            sheet.app.call(
                "witness_preview_request",
                serde_json::json!({
                    "entry_id": entry.entry_id, "raw_session_confirmed": true
                }),
                move |_, result| {
                    result_sheet.witness_busy.set(false);
                    match result {
                        Ok(value)
                            if value.get("status").and_then(serde_json::Value::as_str)
                                == Some("ready") =>
                        {
                            result_sheet.load()
                        }
                        Ok(_) => result_sheet.fill_failure("witness-review-incomplete"),
                        Err(label) => result_sheet.fill_failure(&label),
                    }
                    result_sheet.sync_witness();
                },
            );
        });
        dialog.present();
    }

    fn load(self: &Rc<Self>) {
        self.admission_message.set_label("");
        let Some(entry) = self.current() else {
            self.window.close();
            return;
        };
        self.title.set_title(&format!(
            "{} \u{2014} {}",
            copy::SHEET_TITLE_PREFIX,
            entry.project_label
        ));
        self.title.set_subtitle("");
        self.identity_project.set_text(&entry.project_label);
        self.identity_agent.set_text(&format!(
            "{} \u{2014} {} of {}",
            entry.agent_label(),
            *self.index.borrow() + 1,
            self.pending.len()
        ));
        self.identity_when
            .set_text(&human_when(entry.discovered_at));
        // A new entry is a new decision, and nothing about the previous
        // one may carry into it: the pin is dropped here and only set again
        // by a preview that actually came back for THIS entry. The verdict
        // selection is dropped the same way -- a verdict answered for the
        // last entry must never attach to this one.
        self.pinned.set(false);
        self.sync_contribute();
        self.sync_witness();
        for button in &self.verdict_buttons {
            button.set_active(false);
        }
        *self.verdict.borrow_mut() = None;
        self.set_correction_visible(false);
        self.count_whats_in_it.set_text("");
        self.count_permissions.set_text("");
        self.search_summary.set_text("");
        self.clear_results();
        self.set_manifest(None);
        self.copy_all.set_sensitive(false);
        self.transcript
            .show_sentence("Working out exactly what would be sent…");

        let sheet = Rc::clone(self);
        let entry_id = entry.entry_id.clone();
        let requested = entry_id.clone();
        self.app.preview(&requested, move |app, result| {
            match result {
                Ok((summary, body)) => {
                    app.previews
                        .borrow_mut()
                        .insert(entry_id.clone(), summary.clone());
                    sheet.fill(&summary, body);
                    super::queue::render(app);
                }
                Err(label) => sheet.fill_failure(&label),
            }
            sheet.render_recent();
        });
    }

    /// Rebuild the strip in the sheet header from the same function the
    /// queue row uses, so the four fields are identical in both places.
    ///
    /// It sits inside the header card, where the inset surface reads
    /// against the card's face. On the ground it would not: `surface-2` and
    /// `bg` are within a hair of each other and the strip would disappear.
    fn set_manifest(&self, summary: Option<&PreviewSummary>) {
        while let Some(child) = self.manifest_slot.first_child() {
            self.manifest_slot.remove(&child);
        }
        self.manifest_slot
            .append(&super::queue::manifest_for(summary));
    }

    /// Arm `Contribute` only against a real, pinned preview.
    ///
    /// This used to AND two more conditions -- transcript tab shown,
    /// acknowledgement ticked -- and the module doc records why they went.
    /// What remains is not friction: an unenrolled or failed preview has no
    /// envelope for an approval to bind to, so the button must stay off.
    ///
    /// Still one function, called from every place the pin can change, so
    /// no path sets the button sensitive on its own.
    ///
    /// The second condition is this surface's: a row the daemon says cannot
    /// be sent must not be sendable from the sheet either. Gating the card's
    /// `Submit` and leaving `Contribute` armed one click deeper would move
    /// the defect rather than remove it -- the contributor still presses,
    /// and the server still refuses. An entry with no eligibility field
    /// answers `true` and nothing changes for it.
    fn sync_contribute(&self) {
        // The LIVE row, not the copy this sheet opened with -- see
        // `current_live`. A gate computed once from a snapshot recomputes
        // the same stale answer for as long as the sheet stays open.
        let view = self
            .current_live()
            .as_ref()
            .and_then(crate::eligibility::view);
        let sendable =
            view.is_none_or(|view| view.control == crate::copy::ContributionControl::Contribute);
        self.contribute.set_sensitive(self.pinned.get() && sendable);

        // The sentence beside the control it explains. Drawn only where it
        // says something: an entry with no eligibility field has no
        // sentence, and an eligible one has nothing to explain.
        let note = view.filter(|_| !sendable);
        self.eligibility_note.set_visible(note.is_some());
        if let Some(view) = note {
            let text = if view.reason_line.is_empty() {
                view.state_line.to_string()
            } else {
                // Two sentences the shared crate authored, joined by a
                // space. This shell adds no words of its own to either.
                format!("{} {}", view.state_line, view.reason_line)
            };
            self.eligibility_note.set_label(&text);
            // The whole class set is REPLACED rather than the previous tone
            // removed by name. A hand-written list of tones to strip is a
            // second enumeration of `Tone`, and the arm it gets wrong is the
            // one added after it was written: a tone this code has never
            // heard of would be left stacked on top of the last one. Setting
            // the set is exhaustive by construction.
            self.eligibility_note.set_css_classes(&[
                "tc-caveat",
                super::private_inference::indicator_tone(view.tone).css(),
            ]);
        }
    }

    /// The removed-summary panel: one row per redaction family, and -- only
    /// when there is one -- what scrubbing found and left in.
    ///
    /// The caveat sits under both. A panel that enumerates categories makes
    /// the app look more thorough than it is, which is exactly when that
    /// sentence earns its place.
    fn fill_removed_summary(&self, summary: &PreviewSummary) {
        while let Some(child) = self.removed_summary.first_child() {
            self.removed_summary.remove(&child);
        }
        let (removed, still_present) =
            crate::redaction_summary::rows(&summary.redactions, &summary.redactions_distinct);

        let panel = style::card(gtk::Orientation::Vertical, space::S);
        panel.append(&style::section(copy::REDACTION_PANEL_REMOVED));
        if removed.is_empty() {
            style::append_meta(&panel, copy::NOTHING_MATCHED);
        }
        for row in &removed {
            panel.append(&summary_row(row, Tone::Neutral));
        }

        if !still_present.is_empty() {
            panel.append(&style::section(copy::REDACTION_PANEL_STILL_PRESENT));
            for row in &still_present {
                panel.append(&summary_row(row, Tone::Attention));
            }
        }

        style::append_caveat(
            &panel,
            copy::residual_risk_line(crate::redaction_labels::removed_total(&summary.redactions)),
        );

        self.removed_summary.append(&panel);
    }

    fn fill(self: &Rc<Self>, summary: &PreviewSummary, body: Option<String>) {
        self.witness_requested
            .set(summary.envelope_digest.starts_with("witness-sha256:"));
        self.witness_button.set_visible(false);
        self.set_manifest(Some(summary));
        // Approving is only allowed against a real, pinned preview. An
        // unenrolled build carries a placeholder identity and is not
        // bindable to an approval, so the button stays off and the sheet
        // says why.
        self.pinned.set(summary.enrolled);
        self.sync_contribute();
        // The two counts on the tab strip, read off the pinned preview.
        self.count_whats_in_it
            .set_text(&summary.event_count.to_string());
        self.count_permissions
            .set_text(&summary.consent_scopes.len().to_string());

        *self.body.borrow_mut() = body.clone();
        match &body {
            Some(text) => {
                // The full body can be many megabytes. Laying all of it out
                // in one `TextBuffer` and tagging redactions across the
                // whole thing is the bug this exists to fix; the pane cuts
                // it into chunks and keeps only the ones near the viewport.
                // See `crate::transcript_paging`.
                self.transcript.show_body(text.clone());
                self.copy_all.set_sensitive(true);
            }
            None => {
                self.copy_all.set_sensitive(false);
                self.transcript.show_sentence(copy::BODY_NOT_AVAILABLE_HERE);
            }
        }

        self.fill_removed_summary(summary);

        // "What's in it", from what the contract actually reports. Files
        // touched, tools invoked and the model are not on this response --
        // see the report's contract notes.
        while let Some(child) = self.whats_in_it.first_child() {
            self.whats_in_it.remove(&child);
        }
        // The strip above already carries turn count and the personal-info
        // labels, so this tab does not restate them. What it adds is what
        // the strip cannot hold: the on-disk comparison, the category
        // breakdown behind the count, and the concession in full.
        let detail = style::card(gtk::Orientation::Vertical, space::M);
        for (heading, value) in [
            (
                "Would send",
                format!(
                    "{} (the session file on disk is {})",
                    human_bytes(summary.would_send_bytes),
                    human_bytes(summary.raw_session_bytes)
                ),
            ),
            ("Scrubbing found", summary.scrubbed_line()),
        ] {
            detail.append(&super::titled_paragraph(heading, &value));
        }
        // The concession used to be restated here as a "Residual risk"
        // field. It now lives on the sheet's footer instead, which is the
        // same sentence in a strictly better place: the footer is on screen
        // on every tab, so it cannot be the one thing a person happened not
        // to be looking at when they decided. See `copy::RESIDUAL_RISK`.
        if let Some(summary) = &summary.token_distribution_summary {
            let label = gtk::Label::builder()
                .label(summary)
                .wrap(true)
                .xalign(0.0)
                .build();
            detail.append(&label);
        }
        self.whats_in_it.append(&detail);

        if !summary.enrolled {
            let unenrolled = style::card(gtk::Orientation::Vertical, space::S);
            let badge = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            badge.append(&style::tag("Not connected yet", Tone::Held));
            badge.set_halign(gtk::Align::Start);
            unenrolled.append(&badge);
            style::append_body(&unenrolled, copy::UNENROLLED_PREVIEW);
            self.whats_in_it.append(&unenrolled);
        }

        // Permissions, restated at the moment of consent rather than only
        // at onboarding.
        while let Some(child) = self.permissions.first_child() {
            self.permissions.remove(&child);
        }
        style::append_body(&self.permissions, copy::PERMISSIONS_INTRO);
        let sheet = Rc::clone(self);
        let scopes = summary.consent_scopes.clone();
        self.app.call(
            "consent_options",
            serde_json::json!({}),
            move |_, result| {
                let described: Vec<crate::model::ConsentScope> = result
                    .ok()
                    .and_then(|v| serde_json::from_value(v.get("scopes").cloned()?).ok())
                    .unwrap_or_default();
                for name in &scopes {
                    let description = described
                        .iter()
                        .find(|s| &s.name == name)
                        .map(|s| s.description.clone())
                        .unwrap_or_default();
                    sheet
                        .permissions
                        .append(&super::titled_paragraph(name, &description));
                }
                style::append_caveat(&sheet.permissions, copy::PERMISSIONS_REQUESTED_NOTE);
            },
        );

        if !self.search_entry.text().is_empty() {
            self.run_search(&self.search_entry.text(), false);
        }
    }

    fn fill_failure(self: &Rc<Self>, label: &str) {
        self.pinned.set(false);
        self.sync_contribute();
        self.sync_witness();
        let sentence = if self.witness_requested.get() {
            // The same function the daemon selects with for the other two
            // shells. GTK reaches it directly because it is Rust and has no
            // `view` to read -- two mappings would drift, which is what
            // `witness_refusal_line`'s own doc says it is shared to avoid.
            //
            // Before this the label was discarded here, so a reviewer that
            // declined a receipt and a reviewer that was simply down were the
            // same sentence.
            trace_commons_contributor::witness_copy::witness_refusal_line(Some(label))
        } else {
            match label {
                "preview-failed" | "unavailable" => {
                    concat!(
                        copy::app_name!(),
                        " can't work out what would be sent right now, so there is nothing to \
                     decide on yet. Nothing has been sent."
                    )
                }
                "unknown-entry-id" | "session-file-vanished" => {
                    "This session is no longer waiting. Nothing was sent."
                }
                _ => "Something went wrong working out what would be sent. Nothing has been sent.",
            }
        };
        self.copy_all.set_sensitive(false);
        self.transcript.show_sentence(sentence);
        self.search_summary.set_text(sentence);
    }

    fn set_summary_tone(&self, tone: Tone) {
        for other in [
            Tone::Neutral,
            Tone::Clear,
            Tone::Attention,
            Tone::Held,
            Tone::Refused,
        ] {
            self.search_summary.remove_css_class(other.css());
        }
        self.search_summary.add_css_class(tone.css());
    }

    fn clear_results(&self) {
        while let Some(child) = self.search_results.first_child() {
            self.search_results.remove(&child);
        }
    }

    /// Search the redacted body.
    ///
    /// The answer a contributor wants is usually "0 matches", and getting it
    /// in one keystroke is the point. When this deployment cannot serve the
    /// body, the sheet says so rather than reporting a reassuring zero it
    /// has not earned.
    fn run_search(self: &Rc<Self>, needle: &str, remember: bool) {
        self.clear_results();
        let needle = needle.trim();
        if needle.is_empty() {
            self.search_summary.set_text("");
            return;
        }
        let body = self.body.borrow();
        let Some(body) = body.as_deref() else {
            self.search_summary.set_text(copy::BODY_NOT_AVAILABLE_HERE);
            return;
        };
        if remember {
            // no-op: remembering happens in `remember_search`, kept separate
            // so a keystroke-by-keystroke search does not fill the list.
        }

        let hits = search_hits(body, needle);
        // What the redacted body says, on its own, before the daemon answers
        // about the original. It is replaced in place by
        // `apply_original_count` when that answer lands, and it is what
        // stands if the answer never does.
        //
        // Which is why the zero-hit case is drawn NEUTRAL rather than clear.
        // Zero matches in the redacted body cannot tell "never here" from
        // "removed", and it certainly cannot tell either from "the daemon
        // has not answered yet" -- and this module's own doc says the one
        // direction it must not fail in is reporting "not in this session"
        // about a value that is in it. Printing the good-standing tick here
        // did exactly that, synchronously, before anything was checked.
        // `apply_original_count` is the only thing allowed to print a
        // verdict.
        self.request_original_count(needle, hits.len() as u32);
        // A hit is not a failure -- it is something to weigh -- so it gets
        // gold, not coral. Every state carries a glyph and words as well as
        // a colour.
        if hits.is_empty() {
            self.set_summary_tone(Tone::Neutral);
            self.search_summary.set_text(&format!(
                "{}  {}",
                Tone::Neutral.glyph(),
                copy::SEARCH_CHECKING_ORIGINAL
            ));
            // A clean answer is still worth one caution, and the caution is
            // the gold one: a literal search finds the spelling it was
            // given and no other. Glyph, words and colour, so it survives
            // greyscale.
            let card = style::card(gtk::Orientation::Vertical, space::S);
            card.add_css_class("tc-flagged");
            let heading = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            heading.append(&style::tag(copy::NOTHING_MATCHED, Tone::Attention));
            heading.set_halign(gtk::Align::Start);
            let caution = style::body(copy::NOTHING_MATCHED_BODY);
            card.append(&heading);
            card.append(&caution);
            self.search_results.append(&card);
            return;
        }
        self.set_summary_tone(Tone::Attention);
        self.search_summary.set_text(&format!(
            "{}  {} {}",
            Tone::Attention.glyph(),
            hits.len(),
            if hits.len() == 1 { "match" } else { "matches" }
        ));
        for (start, end) in hits.iter().take(50) {
            let excerpt = context_around(body, *start, *end);
            let label = gtk::Label::builder()
                .xalign(0.0)
                .wrap(true)
                .selectable(true)
                .build();
            label.set_markup(&excerpt.markup());
            label.add_css_class("tc-mono");
            // A recess in the tab rather than a card of its own: an excerpt
            // is a quotation of the transcript, not a second document.
            let row = gtk::Box::new(gtk::Orientation::Vertical, 0);
            row.add_css_class("tc-code");
            row.append(&label);
            self.search_results.append(&row);
        }
        if hits.len() > 50 {
            let more = gtk::Label::builder()
                .label(format!("…and {} more", hits.len() - 50))
                .xalign(0.0)
                .build();
            more.add_css_class("tc-meta");
            self.search_results.append(&more);
        }
    }

    /// Ask the daemon how many times this needle was in the PRE-redaction
    /// session, and say which of the four cases this is once it answers.
    ///
    /// Asynchronous, because the daemon reads the raw session file to
    /// answer. Until it does, the summary says what the redacted body says
    /// on its own -- an honest partial answer rather than a blank.
    ///
    /// The reply is dropped unless the sheet is still showing the SAME ENTRY
    /// and the search box still holds the needle it was asked about. Typing
    /// produces one call per keystroke and the replies can land out of
    /// order, and a stale count printed against a newer question would be a
    /// wrong answer on the screen whose whole job is to be right about this.
    ///
    /// The entry half is not redundant with the needle half. `fill` re-runs
    /// the search when the sheet advances to the next session, so advancing
    /// with the box unchanged asks the same needle of a different entry --
    /// and needle-only matching would let entry A's count paint over entry
    /// B's, which is the case a contributor stepping through a queue hits
    /// every time.
    fn request_original_count(self: &Rc<Self>, needle: &str, remaining: u32) {
        let Some(entry) = self.current() else {
            return;
        };
        let entry_id = entry.entry_id.clone();
        let sheet = Rc::clone(self);
        let asked = needle.to_string();
        let asked_of = entry_id.clone();
        self.app
            .search_original(&entry_id, &asked.clone(), move |_, original| {
                let still_here = sheet
                    .current()
                    .is_some_and(|entry| entry.entry_id == asked_of);
                if !still_here || sheet.search_entry.text().trim() != asked {
                    return;
                }
                sheet.apply_original_count(remaining, original);
            });
    }

    /// Replace the summary with the sentence that tells "never here" apart
    /// from "removed". See `crate::original_search`.
    fn apply_original_count(&self, remaining: u32, original: Option<u32>) {
        let outcome = crate::original_search::classify(remaining, original);
        // Three tones, not two. An `Unknown` used to draw in the clear tone,
        // putting the good-standing tick beside the sentence that says the
        // check did not run. See `original_search::Emphasis`.
        let tone = match crate::original_search::emphasis(&outcome) {
            crate::original_search::Emphasis::Attention => Tone::Attention,
            crate::original_search::Emphasis::Clear => Tone::Clear,
            crate::original_search::Emphasis::Unchecked => Tone::Neutral,
        };
        self.set_summary_tone(tone);
        let glyph = tone.glyph();
        self.search_summary.set_text(&format!(
            "{glyph}  {}",
            crate::original_search::sentence(&outcome)
        ));
    }

    fn remember_search(self: &Rc<Self>, needle: &str) {
        let needle = needle.trim().to_string();
        if needle.is_empty() {
            return;
        }
        let mut recent = self.app.recent_searches.borrow_mut();
        recent.retain(|r| r != &needle);
        recent.insert(0, needle);
        recent.truncate(6);
        drop(recent);
        self.render_recent();
    }

    /// Recent searches, so the second trace is one click rather than one
    /// retyping of a client's name.
    fn render_recent(self: &Rc<Self>) {
        while let Some(child) = self.recent_row.first_child() {
            self.recent_row.remove(&child);
        }
        for term in self.app.recent_searches.borrow().iter() {
            let button = gtk::Button::with_label(term);
            button.add_css_class("tc-chip");
            let sheet = Rc::clone(self);
            let term = term.clone();
            button.connect_clicked(move |_| {
                sheet.search_entry.set_text(&term);
                sheet.run_search(&term, false);
            });
            self.recent_row.append(&button);
        }
        // "Recent:" with nothing after it is a label for an empty set, so
        // the whole row goes when there is nothing to recall.
        if let Some(row) = self.recent_row.parent() {
            row.set_visible(self.recent_row.first_child().is_some());
        }
    }

    fn dismiss_current(self: &Rc<Self>) {
        let Some(entry) = self.current() else { return };
        let entry_id = entry.entry_id.clone();
        let sheet = Rc::clone(self);
        self.app.call(
            "dismiss",
            serde_json::json!({ "entry_id": entry_id }),
            move |app, _| {
                app.refresh();
                sheet.advance();
            },
        );
    }

    /// Approve exactly the bytes this sheet described, render the toast
    /// `crate::toast` builds from what came back, and offer a real undo
    /// when the response earns one.
    ///
    /// The undo itself is the queue's, not the sheet's: recovery lives on
    /// the screen a contributor lands on after deciding, not behind a sheet
    /// that has already closed or moved on to the next session. See
    /// `App::offer_undo`.
    ///
    /// `App::render_submit_response` decides whether Undo is offered --
    /// through `ApproveResult::offers_undo`, which is the fix for the
    /// defect this used to carry: a decode failure used to fall back to
    /// `approved: 1` and call `offer_undo` unconditionally, so any `Ok`
    /// response looked sent. The fallback here is `ApproveResult::default()`
    /// (`approved: 0`), which renders "Nothing sent" and offers no undo --
    /// fail-closed, the same rule a genuinely skipped entry gets.
    fn approve_current(self: &Rc<Self>) {
        let Some(entry) = self.current() else { return };
        let entry_id = entry.entry_id.clone();
        let project_label = entry.project_label.clone();
        // Checked again HERE, against the live queue, and not only when the
        // button was drawn.
        //
        // Nothing tells this sheet the queue changed -- it holds no
        // subscription -- so `sync_contribute` runs only at the moments
        // listed beside it. Between two of them a row can be downgraded
        // under an armed button, and the press is what would send it. The
        // gate at draw time decides what is OFFERED; this decides what is
        // SENT, and only the second one is load-bearing.
        //
        // Repaints on the way out, so a contributor who presses a button
        // that has stopped being valid sees it disarm and reads why, rather
        // than pressing something that silently does nothing.
        if !self
            .current_live()
            .as_ref()
            .is_none_or(crate::eligibility::offers_send)
        {
            self.sync_contribute();
            return;
        }
        self.contribute.set_sensitive(false);
        let sheet = Rc::clone(self);
        // No selection is a valid, expected answer -- `approve_params`
        // omits `outcome` entirely rather than sending `null` or `""`, both
        // of which the daemon refuses. See `ApproveTarget` in `ui::queue`.
        //
        // The correction goes the same way: omitted entirely when the box
        // is empty or was never shown, so an unanswered sheet sends exactly
        // the call it sent before this control existed.
        let correction = self.correction_text();
        let params = super::queue::approve_params(
            super::queue::ApproveTarget::Entry(entry_id.clone()),
            *self.verdict.borrow(),
            correction.as_deref(),
        );
        self.app.call("approve", params, move |app, result| {
            match result {
                Ok(value) => {
                    let approve: ApproveResult = serde_json::from_value(value).unwrap_or_default();
                    // The one refusal the contributor caused and can fix.
                    // It gets its own dialog rather than a line in the
                    // submit toast, and the sheet stays on this entry with
                    // the text still in the box, because the next thing
                    // they have to do is edit it. Advancing would take the
                    // correction away from them along with the chance to
                    // act on the advice.
                    if approve.was_refused_for_a_correction_credential() {
                        // Through the one function, never straight at the
                        // widget: re-arming here directly would put the
                        // button back on a session eligibility says cannot
                        // be sent.
                        sheet.sync_contribute();
                        sheet.show_correction_credential_refusal();
                        app.refresh();
                        return;
                    }
                    app.render_submit_response(&approve, vec![entry_id.clone()], &project_label);
                }
                // A top-level refusal, which for this call means the
                // parameters themselves were rejected -- an oversized or
                // ill-formed correction among them. The label is fixed by
                // contract and is not echoed.
                Err(_) => app.toast(copy::SUBMIT_FAILED),
            }
            app.refresh();
            sheet.advance();
        });
    }

    /// The credential refusal, as its own dialog.
    ///
    /// A dialog rather than a toast because it is the one submit failure
    /// that asks the contributor to do two things -- edit the text, and
    /// rotate what they typed -- and a toast that disappears on a timer is
    /// not where either instruction belongs. Parented to the sheet, which
    /// is the window still holding the correction.
    ///
    /// Neither string is derived from the response: the daemon sends a
    /// fixed label and this shows fixed copy, so no correction text and no
    /// detected value can reach the screen a second time or a log at all.
    fn show_correction_credential_refusal(self: &Rc<Self>) {
        let dialog = adw::MessageDialog::new(
            Some(&self.window),
            Some(copy::CORRECTION_CREDENTIAL_HEADLINE),
            Some(copy::CORRECTION_CREDENTIAL_BODY),
        );
        dialog.add_responses(&[("close", copy::CLOSE)]);
        dialog.set_close_response("close");
        dialog.connect_response(None, |dialog, _| dialog.close());
        dialog.present();
    }

    /// Show or hide the correction control, and empty it on the way out.
    ///
    /// Emptying matters: a contributor who wrote a correction under
    /// `Failed` and then changed their answer to `Worked` has withdrawn it,
    /// and text left in a hidden box would ride along on the next approval
    /// they made without ever being on screen again.
    fn set_correction_visible(&self, visible: bool) {
        if !visible {
            self.correction_view.buffer().set_text("");
        }
        self.correction_group.set_visible(visible);
    }

    /// What is in the correction box, or `None` when the control is hidden
    /// or holds nothing but whitespace.
    ///
    /// The visibility check is deliberate rather than redundant. The box is
    /// emptied when it is hidden, so this would answer `None` anyway; the
    /// check states the rule -- a hidden control contributes nothing -- so
    /// it survives a future change that stops emptying on hide.
    fn correction_text(&self) -> Option<String> {
        if !self.correction_group.is_visible() {
            return None;
        }
        let buffer = self.correction_view.buffer();
        let text = buffer
            .text(&buffer.start_iter(), &buffer.end_iter(), false)
            .to_string();
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    /// `Contribute` advances to the next entry in the sheet, so three
    /// sessions is three deliberate clicks in one flow. There is no
    /// select-all, and there never will be one here.
    fn advance(self: &Rc<Self>) {
        let next = *self.index.borrow() + 1;
        if next >= self.pending.len() {
            self.window.close();
            return;
        }
        *self.index.borrow_mut() = next;
        self.load();
    }
}

/// Show where scrubbing fired, rather than leaving holes.
///
/// The pipeline replaces removed values with visible markers
/// (`<PRIVATE_SECRET_1>`, `[REDACTED]`), so they are already in the text;
/// this makes them legible as chips instead of noise, which is what lets a
/// contributor see *where* redaction happened rather than only being told
/// how often.
///
/// The wash is a gold in the brand's "weigh this" role rather than the
/// GNOME palette yellow this used to hard-code. That value also set a
/// background and no foreground, so under a dark theme it put the theme's
/// near-white text on a bright yellow field -- the marks that most need
/// reading were the least readable ones on the screen. Both halves are
/// stated here, per scheme, and both measure well clear of 4.5:1:
/// `#202426` on `#f3e3c0` is 12.34:1, `#F0EBDD` on `#4A3C18` is 9.04:1.
///
/// A text tag cannot reference a CSS named colour, so these two pairs are
/// the one place outside `style` that names a colour. They must be kept in
/// step with `tc_redaction_bg` / `tc_redaction_fg`.
///
/// The spec draws the marker as a chip with a 3px radius and 4px of side
/// padding. A `GtkTextTag` has neither -- a text buffer can set a run's
/// colours and weight and nothing about its box -- so what lands is the
/// same wash and weight with square ends. The property that matters is
/// carried either way: the marker reads as a legible chip rather than as a
/// hole. See `.tc-redaction` in `style.css` for the full treatment, which
/// applies where a marker is drawn as a widget rather than as buffer text.
fn highlight_redactions(buffer: &gtk::TextBuffer, text: &str) {
    let dark = adw::StyleManager::default().is_dark();
    let (background, foreground) = if dark {
        ("#4A3C18", "#F0EBDD")
    } else {
        ("#f3e3c0", "#202426")
    };
    let tag = buffer
        .create_tag(
            None,
            &[
                ("weight", &700i32),
                ("background", &background),
                ("foreground", &foreground),
            ],
        )
        .expect("creating a text tag");
    // One forward pass, carrying the character offset with it. The version
    // this replaced re-counted the characters before every marker
    // (`text[..start].chars().count()`), which is quadratic in the buffer:
    // measured at 0.77 ms over 64 KB, 166 ms over 1 MB and 2.92 s over
    // 4 MB. `text` is one chunk here, so the pass is bounded either way,
    // but there is no reason to leave the quadratic in.
    let mut byte = 0usize;
    let mut chars = 0i32;
    for span in transcript_paging::marker_spans(text) {
        chars += text[byte..span.start].chars().count() as i32;
        let width = text[span.clone()].chars().count() as i32;
        let a = buffer.iter_at_offset(chars);
        let b = buffer.iter_at_offset(chars + width);
        buffer.apply_tag(&tag, &a, &b);
        chars += width;
        byte = span.end;
    }
}

/// The transcript tab's body: a column of one slot per chunk, of which only
/// the slots near the viewport hold text.
///
/// This is the GTK half of `crate::transcript_paging`. The model there
/// decides *which* chunks are resident and asserts the ceiling; this decides
/// what a resident chunk and an absent one look like on screen.
///
/// A slot that is not resident is an empty `GtkBox` with a height request,
/// so it still holds its place in the scroll: without that the scrollbar
/// would describe the window rather than the body. The height is estimated
/// from the chunk's bytes and newlines until the chunk has been laid out
/// once, and is the measured height afterwards, so revisiting a chunk does
/// not move the text around it.
struct TranscriptPane {
    scroller: gtk::ScrolledWindow,
    column: gtk::Box,
    state: RefCell<PaneState>,
    /// Set while `sync` is mutating widgets. Adding or removing a chunk
    /// changes the adjustment, which re-enters this handler; without the
    /// guard that is an unbounded recursion into a `RefCell` already
    /// borrowed.
    syncing: Cell<bool>,
}

#[derive(Default)]
struct PaneState {
    document: Option<TranscriptDocument>,
    /// One per chunk, in order, and the children of `column`.
    slots: Vec<gtk::Box>,
    /// What each slot stands at while it is not resident, in pixels.
    heights: Vec<i32>,
    resident: ResidentChunks<gtk::TextView>,
    /// Characters across the pane at the current width, for the row
    /// estimate. Zero until the pane has a width.
    columns: usize,
}

/// Advance of one character at the transcript's 11 px monospace, in pixels.
/// Measured through Pango on this crate's own font description: 6.630 px.
/// Only the row *estimate* depends on it, and that estimate is replaced by
/// the measured height as soon as a chunk has been laid out once.
const TRANSCRIPT_ADVANCE_PX: f64 = 6.63;

/// Height of one display row: a 13 px line box at 11 px monospace, plus the
/// 2+2 px the view sets above and below a line (and the 4 px it carries
/// across a wrap, which comes to the same 17 px either way).
const TRANSCRIPT_ROW_PX: i32 = 17;

impl TranscriptPane {
    fn new() -> Rc<Self> {
        let column = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(0)
            .build();
        column.add_css_class("tc-transcript");
        let scroller = gtk::ScrolledWindow::builder()
            // The chunk views wrap at the pane's width, so the pane must
            // have one: an automatic horizontal policy would let the column
            // be as wide as its widest line instead.
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&column)
            .build();

        let pane = Rc::new(Self {
            scroller: scroller.clone(),
            column,
            state: RefCell::new(PaneState::default()),
            syncing: Cell::new(false),
        });

        // Both signals matter: `value-changed` is the scroll itself, and
        // `changed` is a resize or a height that settled after a chunk was
        // laid out.
        // Weak, not strong: the pane owns the scroller, the scroller owns
        // the adjustment, and a strong handle in the handler would close
        // that loop and keep the document -- which is the whole body --
        // alive for the life of the process.
        let adjustment = scroller.vadjustment();
        let p = Rc::downgrade(&pane);
        adjustment.connect_value_changed(move |_| {
            if let Some(pane) = p.upgrade() {
                pane.sync();
            }
        });
        let p = Rc::downgrade(&pane);
        adjustment.connect_changed(move |_| {
            if let Some(pane) = p.upgrade() {
                pane.sync();
            }
        });
        pane
    }

    /// Replaces whatever the pane is showing with a sentence -- no body
    /// available, a failure, or the wait before a preview arrives.
    fn show_sentence(&self, sentence: &str) {
        self.reset();
        let label = gtk::Label::builder()
            .label(sentence)
            .xalign(0.0)
            .wrap(true)
            .margin_top(space::M)
            .margin_bottom(space::M)
            .margin_start(space::M)
            .margin_end(space::M)
            .build();
        label.add_css_class("tc-body");
        self.column.append(&label);
    }

    /// Shows a body: cut it into chunks, give every chunk a slot, and lay
    /// out the ones at the top.
    fn show_body(self: &Rc<Self>, text: String) {
        self.reset();
        let document = TranscriptDocument::new(text);
        let columns = self.columns();
        let mut slots = Vec::with_capacity(document.chunk_count());
        let mut heights = Vec::with_capacity(document.chunk_count());
        for chunk in document.chunks() {
            let height = (chunk.rows(columns) as i32).saturating_mul(TRANSCRIPT_ROW_PX);
            let slot = gtk::Box::new(gtk::Orientation::Vertical, 0);
            slot.set_size_request(-1, height);
            self.column.append(&slot);
            slots.push(slot);
            heights.push(height);
        }
        {
            let mut state = self.state.borrow_mut();
            state.document = Some(document);
            state.slots = slots;
            state.heights = heights;
            state.columns = columns;
        }
        self.scroller.vadjustment().set_value(0.0);
        self.sync();
    }

    /// Drops every slot and everything laid out in one.
    fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.resident.clear(|_, _| {});
        state.document = None;
        state.slots.clear();
        state.heights.clear();
        drop(state);
        while let Some(child) = self.column.first_child() {
            self.column.remove(&child);
        }
    }

    /// The whole body, for "Copy everything".
    fn whole_text(&self) -> Option<String> {
        self.state
            .borrow()
            .document
            .as_ref()
            .map(|d| d.whole_text().to_string())
    }

    fn columns(&self) -> usize {
        let width = self.scroller.width();
        if width <= 0 {
            // No allocation yet. 100 columns is the shape of the pane the
            // sheet opens at; the estimate is replaced by a measurement as
            // soon as the chunk is laid out.
            return 100;
        }
        ((width as f64 / TRANSCRIPT_ADVANCE_PX).floor() as usize).max(1)
    }

    /// Brings the resident set in line with where the viewport is.
    fn sync(self: &Rc<Self>) {
        if self.syncing.get() {
            return;
        }
        self.syncing.set(true);
        self.sync_inner();
        self.syncing.set(false);
    }

    fn sync_inner(&self) {
        let adjustment = self.scroller.vadjustment();
        let top = adjustment.value();
        let bottom = top + adjustment.page_size().max(1.0);
        let columns = self.columns();

        let mut state = self.state.borrow_mut();
        let PaneState {
            document,
            slots,
            heights,
            resident,
            columns: known_columns,
        } = &mut *state;
        let Some(document) = document.as_ref() else {
            return;
        };
        if document.chunk_count() == 0 {
            return;
        }

        // A resize changes how many rows a chunk takes, so the stand-ins
        // for chunks that have never been laid out have to be re-estimated.
        // A slot that has been laid out keeps its measured height.
        if columns != *known_columns {
            *known_columns = columns;
            for (i, chunk) in document.chunks().iter().enumerate() {
                if resident.contains(i) {
                    continue;
                }
                let height = (chunk.rows(columns) as i32).saturating_mul(TRANSCRIPT_ROW_PX);
                heights[i] = height;
                slots[i].set_size_request(-1, height);
            }
        }

        // Which chunks the viewport is over, from where the slots actually
        // are rather than from a model of where they ought to be. A slot
        // that is laid out has a real height, and it replaces the estimate
        // it was standing at, so letting the chunk go later does not move
        // everything below it.
        let mut standing = Vec::with_capacity(slots.len());
        for (i, slot) in slots.iter().enumerate() {
            let allocated = slot.height();
            if allocated > 0 && resident.contains(i) {
                heights[i] = allocated;
            }
            standing.push(if allocated > 0 {
                allocated as f64
            } else {
                heights[i] as f64
            });
        }
        let visible = transcript_paging::visible_range(&standing, top, bottom);

        resident.update(
            document,
            visible,
            transcript_paging::RETAINED_LIMIT_BYTES,
            |index| {
                let view = chunk_view(document.text_of(index));
                slots[index].set_size_request(-1, -1);
                slots[index].append(&view);
                view
            },
            |index, view| {
                // Freeze the slot at the height the chunk actually took, so
                // letting it go does not move everything below it.
                let measured = slots[index].height();
                if measured > 0 {
                    heights[index] = measured;
                }
                slots[index].remove(&view);
                slots[index].set_size_request(-1, heights[index]);
            },
        );
    }
}

/// One row of the removed-summary panel: what kind of thing, how much of it,
/// what that kind IS, and which sub-labels it folded in.
///
/// Never a matched value. The row names a KIND -- the value is gone by
/// construction, and a sub-label is a schema-shaped identifier the redactor
/// minted, not contributor text.
fn summary_row(row: &crate::redaction_summary::Row, tone: Tone) -> gtk::Box {
    let container = gtk::Box::new(gtk::Orientation::Vertical, space::XXS);

    let head = gtk::Box::new(gtk::Orientation::Horizontal, space::S);
    if tone == Tone::Attention {
        head.append(&style::tag(tone.glyph(), tone));
    }
    let name = gtk::Label::builder()
        .label(&row.display)
        .xalign(0.0)
        .hexpand(true)
        .wrap(true)
        .build();
    name.add_css_class("tc-card-title");
    head.append(&name);
    let counts = gtk::Label::new(Some(&copy::redaction_row_counts(
        row.occurrences,
        row.distinct,
    )));
    counts.add_css_class("tc-meta");
    counts.set_valign(gtk::Align::Center);
    head.append(&counts);
    container.append(&head);

    style::append_meta(&container, row.description);

    if !row.detail.is_empty() {
        let detail = gtk::Label::builder()
            .label(row.detail.join(", "))
            .xalign(0.0)
            .wrap(true)
            .build();
        detail.add_css_class("tc-meta");
        detail.add_css_class("tc-tertiary");
        container.append(&detail);
    }

    container
}

/// One chunk, laid out: a text view over that chunk's bytes with its
/// redaction markers chipped.
///
/// The tab is flat monospaced text, deliberately not chat bubbles: what is
/// on it is the literal bytes an approval covers, and anything that dressed
/// them up as a conversation would be showing a rendering of the payload
/// rather than the payload.
///
/// The spec sets the transcript at 11px / 1.7. GTK 4 CSS has no
/// line-height, so the leading is set here in pixels instead: an 11px
/// monospaced line lands around 15px on its own metrics, and 1.7 asks for
/// about 19. `pixels_inside_wrap` carries the same leading across a wrapped
/// line, which is most of them -- a transcript is one very long paragraph
/// per turn.
fn chunk_view(text: &str) -> gtk::TextView {
    let view = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(gtk::WrapMode::WordChar)
        .monospace(true)
        .vexpand(false)
        .build();
    view.add_css_class("tc-transcript");
    view.set_pixels_above_lines(2);
    view.set_pixels_below_lines(2);
    view.set_pixels_inside_wrap(4);
    let buffer = view.buffer();
    buffer.set_text(text);
    highlight_redactions(&buffer, text);
    label_placeholders(&view, text);
    view
}

/// Name each redaction mark, on hover.
///
/// `highlight_redactions` makes a mark legible; this says WHAT was taken out
/// there, which is the half a `GtkTextTag` cannot carry. Both walk the same
/// spans -- `transcript_paging::marker_spans`, which the chunker also uses
/// -- so there is no second marker pass, and no set of marks one of them
/// knows about and the other does not.
///
/// Three forms, three amounts of information, and none of them padded out
/// with a guess: a numbered placeholder names its category and, on a repeat
/// of the same ordinal, says it is the same original value; a labelled
/// `[REDACTED:...]` names its category only; a bare `[REDACTED]` says just
/// that something was removed. See `crate::placeholders`.
///
/// The ranges are converted to CHARACTER offsets here, because that is the
/// unit a `GtkTextIter` counts in while the spans are bytes. Done once per
/// chunk rather than per motion event, which would re-walk the chunk on
/// every pixel of a hover.
fn label_placeholders(view: &gtk::TextView, text: &str) {
    let mut marks: Vec<(i32, i32, String)> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u32)> = std::collections::HashSet::new();
    let mut byte = 0usize;
    let mut chars = 0i32;
    for found in crate::placeholders::scan(text) {
        chars += text[byte..found.start].chars().count() as i32;
        let width = text[found.start..found.end].chars().count() as i32;
        let name = match (&found.label, found.ordinal) {
            (Some(label), Some(ordinal)) => {
                let kind = crate::placeholders::display(label);
                // Only a numbered placeholder supports this claim: the
                // redactor mints one token per DISTINCT value and reuses it
                // wherever that value recurs.
                if seen.insert((label.clone(), ordinal)) {
                    copy::redaction_mark_tooltip(&kind)
                } else {
                    copy::redaction_mark_repeat(&kind)
                }
            }
            (Some(label), None) => {
                copy::redaction_mark_tooltip(&crate::placeholders::display(label))
            }
            (None, _) => copy::REDACTION_MARK_UNNAMED.to_string(),
        };
        marks.push((chars, chars + width, name));
        chars += width;
        byte = found.end;
    }
    if marks.is_empty() {
        return;
    }
    view.set_has_tooltip(true);
    view.connect_query_tooltip(move |view, x, y, keyboard, tooltip| {
        // A keyboard tooltip has no pointer position to resolve, and this
        // mark is a property of a place rather than of the widget.
        if keyboard {
            return false;
        }
        let (bx, by) = view.window_to_buffer_coords(gtk::TextWindowType::Widget, x, y);
        let Some(iter) = view.iter_at_location(bx, by) else {
            return false;
        };
        let offset = iter.offset();
        match marks
            .iter()
            .find(|(start, end, _)| offset >= *start && offset < *end)
        {
            Some((_, _, name)) => {
                tooltip.set_text(Some(name));
                true
            }
            None => false,
        }
    });
}

/// A readable window around a search hit, and where inside it the hit is.
///
/// The range is kept rather than re-found, because re-finding it in the
/// rendered snippet would have to reproduce the case folding the search
/// used and would mark the wrong run the first time the two disagreed.
struct Excerpt {
    text: String,
    hit: std::ops::Range<usize>,
}

impl Excerpt {
    /// The excerpt as Pango markup, with the matched run washed in the
    /// brand's "weigh this" gold.
    ///
    /// Pango cannot reference a CSS named colour any more than a text tag
    /// can, so the hue and its alpha are written out per scheme. They are
    /// `tc_gold_highlight`'s own two components -- `rgba(185,130,31,.28)`
    /// light, `rgba(220,170,67,.32)` dark -- and must be kept in step with
    /// it. Only the background is set: the foreground stays the label's own
    /// ink, which is what keeps the excerpt readable at both ends of the
    /// scheme.
    fn markup(&self) -> String {
        let dark = adw::StyleManager::default().is_dark();
        let (hue, alpha) = if dark {
            ("#DCAA43", "32%")
        } else {
            ("#B9821F", "28%")
        };
        format!(
            "{}<span background=\"{hue}\" bgalpha=\"{alpha}\">{}</span>{}",
            glib::markup_escape_text(&self.text[..self.hit.start]),
            glib::markup_escape_text(&self.text[self.hit.clone()]),
            glib::markup_escape_text(&self.text[self.hit.end..]),
        )
    }
}

/// A readable window around a search hit. Character-safe: slicing a UTF-8
/// body on a byte offset would panic on a multi-byte boundary, and traces
/// contain plenty of those.
///
/// Newlines are replaced rather than stripped so that the returned range
/// still indexes the returned string: a snippet whose highlight had drifted
/// by the number of line breaks in it would mark the wrong words, which on
/// this screen is worse than marking none.
/// Every case-insensitive hit for `needle` in `body`, as `(start, end)` byte
/// ranges into `body` ITSELF.
///
/// The obvious implementation -- `body.to_lowercase().match_indices(needle)`
/// -- is wrong, because case folding is not byte-length preserving. U+0130 is
/// two bytes and folds to three; U+212A is three and folds to one. Every
/// offset after such a character is off by the difference, so slicing `body`
/// with it marks the wrong run ("eedle" rather than "needle" after a single
/// U+0130) and can land mid-codepoint and panic.
///
/// So the fold is built alongside a map from each folded byte back to the
/// body byte it came from. The map carries one entry per folded byte plus a
/// terminator, so both ends of a hit translate, and every value it holds is a
/// char boundary in `body` because it only ever records `char_indices`.
fn search_hits(body: &str, needle: &str) -> Vec<(usize, usize)> {
    let mut folded = String::with_capacity(body.len());
    let mut map: Vec<usize> = Vec::with_capacity(body.len() + 1);
    for (offset, ch) in body.char_indices() {
        for lowered in ch.to_lowercase() {
            folded.push(lowered);
            map.resize(folded.len(), offset);
        }
    }
    map.push(body.len());

    let pin = needle.to_lowercase();
    if pin.is_empty() {
        return Vec::new();
    }
    folded
        .match_indices(&pin)
        .map(|(i, m)| (map[i], map[i + m.len()]))
        .collect()
}

/// `byte_start` and `byte_end` are offsets into `body` itself, not into a
/// case-folded copy of it -- see `search_hits`. Both must be char boundaries;
/// the caller gets them from that map, which only ever records boundaries.
fn context_around(body: &str, byte_start: usize, byte_end: usize) -> Excerpt {
    let start = body[..byte_start]
        .char_indices()
        .rev()
        .take(60)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(byte_start);
    let after = byte_end.min(body.len());
    let end = body[after..]
        .char_indices()
        .take(60)
        .last()
        .map(|(i, _)| after + i)
        .unwrap_or(body.len());
    let head = body[start..byte_start].replace('\n', " ");
    let head = head.trim_start();
    let hit = body[byte_start..after].replace('\n', " ");
    let tail = body[after..end.min(body.len())].replace('\n', " ");
    let tail = tail.trim_end();
    let lead = "\u{2026}";
    let hit_start = lead.len() + head.len();
    Excerpt {
        text: format!("{lead}{head}{hit}{tail}\u{2026}"),
        hit: hit_start..hit_start + hit.len(),
    }
}

/// Whether this contributor's enrolment admits evidence-bearing
/// contribution, read out of a `get_settings` reply.
///
/// `admission_evidence_required` is the daemon's own answer, and it is not a
/// preference: it is true for a contributor who signed up through NEAR and
/// false for one who came in on an invite. Anything but an explicit `true` is
/// a no -- the daemon answers null when it could not read the config, and an
/// older daemon does not answer at all.
fn admission_required_by_settings(settings: &serde_json::Value) -> bool {
    settings
        .get("admission_evidence_required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Whether the preparation control belongs on the sheet at all.
///
/// Withheld rather than shown refused, which is what macOS does: it omits
/// `AdmissionPreparationView` outright for a contributor whose enrolment
/// cannot use it. A disabled button with nothing beside it to say why is
/// worse than no button.
fn admission_control_visible(required: bool, supported: bool, pinned: bool) -> bool {
    // `required` is the enrolment, `supported` the daemon advertising the
    // method, `pinned` this sheet having already committed the bytes -- after
    // which there is nothing left to prepare.
    required && supported && !pinned
}

/// The sentence for a refused preparation.
///
/// This shell reaches a refusal as a bare label string -- `Backend::call`
/// turns `error.message` into the `Err` side, and the daemon's `view` object
/// does not survive that -- so it maps the label itself rather than reading
/// `view.message` the way the macOS shell does. Same function, same words:
/// a second mapping here would drift from the one the daemon uses.
///
/// The label is a fixed string by IPC contract, which is what makes forwarding
/// it safe; it is used to *choose* a sentence and is never displayed.
/// What the sheet should say about one preparation attempt, and whether it
/// succeeded.
///
/// The whole decision, so the widget callback has nothing left to get wrong.
/// It previously chose the refusal sentence inline, which meant the choice
/// could only be checked by running GTK -- and it was choosing one fixed
/// sentence for every cause.
///
/// This shell reaches a refusal as a bare label string: `Backend::call` turns
/// `error.message` into the `Err` side and the daemon's `view` object does not
/// survive that, so the label is mapped here rather than read from
/// `view.message` as the macOS shell does. Same function, same words -- a
/// second mapping would drift from the daemon's.
///
/// The label is a fixed string by IPC contract, which is what makes using it
/// safe. It selects a sentence and is never shown.
fn admission_outcome(result: &Result<serde_json::Value, String>) -> (bool, String) {
    let copy = trace_commons_contributor::witness_copy::witness_copy().admission;
    if result.as_ref().ok().is_some_and(admission_ready) {
        return (true, copy.ready.to_string());
    }
    let line = trace_commons_contributor::witness_copy::admission_refusal_line(
        result.as_ref().err().map(String::as_str),
    );
    (false, format!("{} {}", copy.refused_glyph, line))
}

fn admission_ready(value: &serde_json::Value) -> bool {
    value
        .get("view")
        .and_then(|view| view.get("ready"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

#[cfg(test)]
mod tests {
    /// The control that prepares an evidence-bearing session is offered on
    /// the strength of `admission_evidence_required` -- a consequence of how
    /// the contributor enrolled, not a preference anyone sets. A contributor
    /// who came in on an invite cannot use it, and must not be shown it: the
    /// only thing pressing it could do is refuse them. This is the condition
    /// macOS reads at `PreviewSheet.swift`, and the daemon's own answer at
    /// `add_admission_setting`.
    ///
    /// Both directions, because a test that only proves the control appears
    /// for an eligible contributor says nothing about the bug.
    #[test]
    fn admission_preparation_is_offered_only_where_the_enrolment_allows_it() {
        assert!(super::admission_required_by_settings(
            &serde_json::json!({"admission_evidence_required": true})
        ));
        assert!(!super::admission_required_by_settings(
            &serde_json::json!({"admission_evidence_required": false})
        ));

        // `add_admission_setting` answers null when it could not read the
        // config, and an older daemon does not answer at all. Neither is a
        // yes.
        for value in [
            serde_json::json!({"admission_evidence_required": serde_json::Value::Null}),
            serde_json::json!({}),
            serde_json::json!({"admission_evidence_required": "true"}),
            serde_json::json!({"admission_evidence_required": 1}),
        ] {
            assert!(
                !super::admission_required_by_settings(&value),
                "an unreadable answer was read as eligibility: {value}"
            );
        }
    }

    /// The three conditions the sheet actually multiplies together, held
    /// apart so each one can be shown to matter on its own. `supported` is
    /// the daemon advertising the method; `pinned` is this sheet having
    /// already committed the bytes, after which there is nothing left to
    /// prepare.
    #[test]
    fn every_condition_on_the_admission_control_can_withhold_it() {
        assert!(super::admission_control_visible(true, true, false));
        assert!(!super::admission_control_visible(false, true, false));
        assert!(!super::admission_control_visible(true, false, false));
        assert!(!super::admission_control_visible(true, true, true));
    }

    /// This shell renders the refusal it chooses, so choosing wrongly here is
    /// invisible everywhere else: the daemon can classify perfectly and Linux
    /// still shows one sentence. That was the state before this change.
    #[test]
    fn a_refusal_says_what_the_daemon_classified_rather_than_one_sentence() {
        let generic = trace_commons_contributor::witness_copy::witness_copy()
            .admission
            .failed;
        let refusal = |label: &str| {
            let (ready, text) =
                super::admission_outcome(&Err::<serde_json::Value, String>(label.to_string()));
            assert!(!ready, "{label} is a refusal");
            text
        };

        assert!(
            refusal("admission_setup_unavailable").ends_with(generic),
            "an unclassified failure still says the generic sentence"
        );

        let mut seen = Vec::new();
        for label in [
            "admission_setup_consent_required",
            "admission_setup_proxy_missing",
            "admission_setup_source_unsupported",
            "admission_receipt_endpoint_required",
        ] {
            let line = refusal(label);
            assert_ne!(line, generic, "{label} is rendered as the generic sentence");
            seen.push(line);
        }
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "two causes were given the same words");
    }

    #[test]
    fn admission_preparation_requires_fresh_explicit_success() {
        let future = chrono::Utc::now().timestamp() + 600;
        assert!(super::admission_ready(
            &serde_json::json!({"status":"ready_for_next_inference","expires_at":future,"view":{"ready":true}})
        ));
        for value in [
            serde_json::json!({}),
            serde_json::json!({"status":"ready"}),
            serde_json::json!({"status":"ready_for_next_inference","expires_at":1}),
        ] {
            assert!(!super::admission_ready(&value));
        }
    }
    use super::context_around;

    #[test]
    fn context_never_splits_a_multibyte_character() {
        let body = "prefix ünïcödé haystack needle tail ünïcödé more";
        let start = body.find("needle").unwrap();
        let excerpt = context_around(body, start, start + "needle".len());
        assert!(excerpt.text.contains("needle"));
    }

    /// Case folding is not byte-length preserving, so a hit offset taken
    /// from a lowercased copy of the body does not address the body. U+0130
    /// is two bytes and folds to three, U+212A is three and folds to one, so
    /// every offset after one of them is wrong by the difference -- which
    /// marks the wrong run, and can land mid-codepoint and panic.
    ///
    /// This drives the real `search_hits`, so a regression in the mapping
    /// fails here rather than in a contributor's window.
    #[test]
    fn a_hit_after_a_case_folding_character_still_marks_the_matched_term() {
        for (body, needle) in [
            ("\u{130}xx the client is Acme Corp here", "acme corp"),
            ("\u{212A}elvin asked about Acme Corp today", "ACME CORP"),
            ("\u{130}\u{130}\u{130} Acme Corp", "Acme Corp"),
            ("\u{130} Acme Corp and Acme Corp again", "acme corp"),
            ("no folding oddity, Acme Corp", "acme corp"),
        ] {
            let hits = super::search_hits(body, needle);
            assert!(!hits.is_empty(), "no hit in {body:?}");
            for (start, end) in hits {
                assert_eq!(&body[start..end], "Acme Corp", "body {body:?}");
                let excerpt = context_around(body, start, end);
                assert_eq!(
                    &excerpt.text[excerpt.hit.clone()],
                    "Acme Corp",
                    "body {body:?} needle {needle:?}"
                );
            }
        }
    }

    /// An empty needle would otherwise report a hit at every byte boundary.
    #[test]
    fn an_empty_needle_matches_nothing() {
        assert!(super::search_hits("Acme Corp", "").is_empty());
    }

    /// The highlight has to land on the matched term itself. A range that
    /// drifted -- by the ellipsis, by a trimmed space, by a replaced
    /// newline -- would gild the wrong words on the one screen where the
    /// marked words are the answer.
    #[test]
    fn the_marked_range_is_exactly_the_matched_term() {
        for body in [
            "the client is Acme Corp -- their invoice template still uses the legacy footer",
            "prefix ünïcödé Acme Corp ünïcödé suffix",
            "a line\nbreak before Acme Corp and\nanother after it",
            "Acme Corp at the very start",
            "trailing hit is Acme Corp",
        ] {
            let start = body.find("Acme Corp").unwrap();
            let excerpt = context_around(body, start, start + "Acme Corp".len());
            assert_eq!(&excerpt.text[excerpt.hit.clone()], "Acme Corp", "{body}");
        }
    }
}
