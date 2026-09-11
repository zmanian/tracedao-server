//! The words, in one place.
//!
//! The shared design specifies copy rather than suggesting it, so it lives
//! here as constants instead of being scattered through widget
//! construction: a sentence that must not drift is easier to keep from
//! drifting when there is exactly one of it.
//!
//! Four rules bind everything below.
//!
//! * **Credit is a record, never a currency.** No currency symbol, no fiat
//!   estimate, no projection, no date, no gamification.
//! * **Quarantine is held, never rejected**, and never carries a turnaround
//!   time.
//! * **Never name the mechanism.** "Privacy filter", "claim", "ingest",
//!   "canary" are internal words.
//! * **Always state the data consequence.** "Nothing was sent unscanned",
//!   "your queue is safe", "nothing has been lost".

/// The app's name, re-exported from its one definition.
///
/// This used to be a literal here, and `routing_copy` had its own, and the
/// Swift views had more. Pointing at `trace_commons_contributor::brand`
/// makes this file a reader of the name rather than a second author of it.
///
/// Re-exporting the constant alone would not have finished the job: most of
/// the sentences below do not merely *equal* the name, they wrap it in
/// prose, and a `const` cannot be pasted into another `const`'s middle. So
/// every one of them is built with [`app_name!`] inside `concat!`, which is
/// why the macro exists. The name appears as a literal nowhere in this file
/// except through that macro; what is left is prose in comments, which no
/// contributor reads.
pub use trace_commons_contributor::{app_name, brand::APP_NAME};

// --- Queue -------------------------------------------------------------

/// The concession, in full. Shown once per decision, in the preview sheet,
/// where a person is reading rather than scanning.
pub const RESIDUAL_RISK: &str =
    "Scrubbing is pattern-based. It misses things it hasn't seen before.";

/// The same concession on a queue row, said in terms of what scrubbing
/// actually did to *this* session.
///
/// The constant above used to be printed verbatim on every card. Repeated
/// down a column, identical each time, it stops being read -- which is how
/// a warning becomes wallpaper, and the warning it becomes is the one this
/// product most needs someone to take seriously. Splitting it across
/// several places only makes several pieces of wallpaper.
///
/// So the row carries a line that changes with the count. "Scrubbing
/// matched nothing" and "scrubbing removed 4 things" are different
/// sentences describing different situations, and a person reads the second
/// one because it is not the one they read on the card above. The zero case
/// is also the one worth weighing -- a session that obviously touched a
/// `.env` and reports nothing removed is a signal -- so it is the case that
/// carries the attention tone and, on the card, the gold rule.
///
/// The full sentence is never dropped: it is restated in the preview sheet
/// under "Residual risk", which is the screen a person is on when they
/// actually decide.
pub fn residual_risk_line(total_redactions: u32) -> String {
    match total_redactions {
        0 => "Scrubbing matched nothing here. That is not the same as there being nothing to \
              find -- it only recognises patterns it has seen before. Search this session for \
              anything you are worried about."
            .to_string(),
        1 => "Scrubbing removed 1 thing it recognised. It works from patterns, so it misses \
              what it hasn't seen before."
            .to_string(),
        n => format!(
            "Scrubbing removed {n} things it recognised. It works from patterns, so it misses \
             what it hasn't seen before."
        ),
    }
}
/// What one card actually covers, when the answer is more than the
/// conversation itself.
///
/// A Claude Code conversation is not one file: each delegated subagent's
/// turns are written beside the session, and one probed machine had 114 of
/// them under a single conversation. The card offers all of it as one
/// decision, so its extent belongs in the description -- see
/// `docs/contributor-daemon-ipc-v1_1.md`, which asks a client to say how
/// many delegated transcripts an entry covers and **requires** it to
/// surface a non-zero dropped count.
///
/// The second sentence is the one that has to be exactly right. A dropped
/// transcript is a normal consequence of a very large conversation, not an
/// error, and it is never the conversation itself -- the parent file is
/// always kept, and only delegated transcripts, largest first, are left out
/// to bring the group under the byte budget. So the line states what was
/// left out, why, and what that does not mean, in that order, and it does
/// it without a word that reads as a failure.
///
/// Returns `None` when there is nothing to say: an entry covering no
/// delegated transcripts and dropping none renders no row at all rather
/// than a line of zeroes.
pub fn subagent_line(subagent_count: u32, subagents_dropped: u32) -> Option<String> {
    let trimmed = "left out to keep this session within its size limit; the conversation itself \
                   is complete.";
    match (subagent_count, subagents_dropped) {
        (0, 0) => None,
        (n, 0) => Some(format!("Includes {n} {}.", transcripts(n))),
        (0, 1) => Some(format!("1 delegated subagent transcript was {trimmed}")),
        (0, d) => Some(format!("{d} delegated subagent transcripts were {trimmed}")),
        (n, 1) => Some(format!(
            "Includes {n} {}. The largest was {trimmed}",
            transcripts(n)
        )),
        (n, d) => Some(format!(
            "Includes {n} {}. The {d} largest were {trimmed}",
            transcripts(n)
        )),
    }
}

fn transcripts(n: u32) -> &'static str {
    if n == 1 {
        "delegated subagent transcript"
    } else {
        "delegated subagent transcripts"
    }
}

pub const LOOK_INSIDE: &str = "Look inside";
pub const NOT_THIS_ONE: &str = "Not this one";
/// Says "for good" because it is. A dismissal is a decision about the
/// conversation, not about the size it happened to be when the card was
/// drawn, and there is no un-dismiss -- so the tooltip has to say so before
/// the click, not leave the contributor to infer it from a card that never
/// comes back. The second sentence is the reassurance that keeps the first
/// from reading like an opt-out of the whole project.
pub const NOT_THIS_ONE_TOOLTIP: &str = "Skips this session for good, even if you keep working in \
     it. This project will keep being offered.";

/// The one-click send on a queue row. See
/// `docs/superpowers/specs/2026-08-20-one-click-submit-design.md`: the click
/// builds, pins, and approves, then raises the toast that says what
/// happened -- see [`crate::toast`].
///
/// The tooltip says "approves", never "sends": nothing leaves the machine
/// at click time, only at the watcher's next sweep -- [`UNDO_BODY`] states
/// that for the undo bar, and a toast that once said "Sent." while still
/// offering Undo was the same contradiction this tooltip must not repeat.
pub const SUBMIT: &str = "Submit";
pub const SUBMIT_TOOLTIP: &str = "Approves this session now. Scrubbing runs first; the watcher \
     sends it on its next sweep, and you can undo before then.";

/// The same gesture at the project level, on the group's header rather than
/// on a row. Calls `approve` with a `project_id` rather than an `entry_id`
/// -- the daemon selects that project's pending entries, this shell never
/// enumerates them itself.
pub const SUBMIT_ALL: &str = "Submit all";
pub const SUBMIT_ALL_TOOLTIP: &str = "Approves every waiting session from this project now. \
     Scrubbing runs first; the watcher sends them on its next sweep, and you can undo before \
     then.";

/// Stops a project being offered again and clears whatever it has waiting.
/// Sits beside [`SUBMIT_ALL`] on the same group header but must never carry
/// its primary-action styling -- the two buttons take a contributor's queue
/// in opposite directions.
pub const IGNORE_PROJECT: &str = "Ignore project";
///
/// Word for word what macOS and Windows put on the same button. Three
/// shells drift, and a tooltip nobody tests drifts first: this one is
/// `ProjectIgnoreCopy.tooltip` there.
pub const IGNORE_PROJECT_TOOLTIP: &str = "Stops this project being offered and clears what it has waiting. \
     Anything already submitted is unaffected, and you can undo this in Settings.";

pub fn ignore_project_title(project: &str) -> String {
    format!("Ignore {project}?")
}

/// The removal clause is dropped when nothing is waiting.
///
/// No group renders that way today: all three shells build their groups
/// from the pending list alone, so a group that renders has at least one
/// waiting session in it. The branch is kept because this function is
/// handed a number and must be right about whatever number it is handed --
/// "removes 0 waiting traces" would be both wrong and alarming -- not
/// because a caller is known to produce zero.
pub fn ignore_project_body(pending: usize) -> String {
    let tail = "Nothing already submitted is affected. You can undo this in Settings.";
    if pending == 0 {
        return format!("Stops this project being offered. {tail}");
    }
    let noun = if pending == 1 { "trace" } else { "traces" };
    format!("This removes {pending} waiting {noun} and stops this project being offered. {tail}")
}

/// What is said afterwards when the daemon removed a different number than
/// the confirmation named.
///
/// The dialog has to state a count before the call is made, so it states
/// the one this shell can see. The queue is live: a poll between the render
/// and the click adds waiting sessions, an approval elsewhere removes one,
/// and the daemon acts on what is there when it gets the message. `purged`
/// is that number and it is the authority; the promise was an estimate.
///
/// `None` when the two agree, which is the ordinary case -- a line that
/// appears every time to say nothing happened is noise, and noise is how a
/// line that matters gets skipped.
pub fn ignore_project_reconciled(project: &str, promised: usize, purged: u64) -> Option<String> {
    if purged == promised as u64 {
        return None;
    }
    let clause = if purged == 1 {
        "1 waiting trace was removed".to_string()
    } else {
        format!("{purged} waiting traces were removed")
    };
    Some(format!(
        "Ignored {project}. The queue changed while you were deciding: {clause}, not {promised}."
    ))
}

/// The four things a search can find, in the words the sheet says them.
///
/// The search scans the REDACTED body, so a value that was removed returns
/// zero matches -- indistinguishable, on that count alone, from a value that
/// was never in the session. The daemon's `search_original` counts the same
/// needle in the pre-redaction text, and these four sentences are what tell
/// the two apart. See [`crate::original_search`].
pub fn search_absent() -> String {
    "0 matches \u{2014} not in this session".to_string()
}

pub fn search_all_removed(total: u32) -> String {
    format!("{total} matches \u{2014} all {total} were removed")
}

pub fn search_some_remain(remaining: u32, total: u32) -> String {
    format!("{total} matches \u{2014} {remaining} would still be sent")
}

/// The arm where the app does not know, and must not round that off to a
/// clean answer. Saying "not in this session" because a call failed would be
/// the most dangerous wrong sentence this tab can print.
/// What the summary says between the local scan finding nothing and the
/// daemon answering about the original.
///
/// Zero matches in the redacted body is not yet an answer to "was it ever
/// here", so this sentence deliberately claims nothing. The reassuring one
/// is `search_absent`, and only `apply_original_count` may print it.
pub const SEARCH_CHECKING_ORIGINAL: &str = "0 matches here. Checking the original session…";

pub fn search_unknown() -> String {
    "0 matches in what would be sent \u{2014} couldn't check the original".to_string()
}

/// What each redaction family IS, in words -- the panel's actual value to a
/// reader who has never seen these labels.
///
/// Deliberately not exhaustive. The vocabulary is generated and open, which
/// is why `redaction_summary::describe` falls back rather than panicking.
pub const REDACTION_CATEGORY_LOCAL_PATH: &str = "File paths from this machine.";
pub const REDACTION_CATEGORY_SECRET: &str =
    "API keys, tokens, private keys, and high-entropy strings found next to credential words.";
pub const REDACTION_CATEGORY_PRIVACY_FILTER: &str =
    "Names, emails, and other personal details found in prose.";
pub const REDACTION_CATEGORY_SENSITIVE_FIELD: &str =
    "Fields whose name marks them sensitive, like password or authorization.";
pub const REDACTION_CATEGORY_TOOL_SENSITIVE_FIELD: &str =
    "Tool-call arguments whose name marks them sensitive.";
pub const REDACTION_CATEGORY_RESIDUAL: &str = "Found, and still in what would be sent. Either a credential inside a correction \
     you wrote, which is kept on purpose, or a field scrubbing does not reach.";

/// The neutral description for a family this build has no words for. It must
/// still appear: dropping an unrecognised category would understate what
/// happened.
pub const REDACTION_CATEGORY_UNKNOWN: &str =
    "Removed by a pattern this version has no description for.";

/// The two headings over the summary panel. The second is a sentence rather
/// than a noun because it is the one a contributor must not skim past.
pub const REDACTION_PANEL_REMOVED: &str = "Removed";
pub const REDACTION_PANEL_STILL_PRESENT: &str = "Found, and still in what would be sent";

/// One panel row's figures: how many times a family fired, and over how many
/// distinct values. The distinct half is omitted when it repeats the first,
/// for the same reason [`crate::redaction_labels::line`] omits it.
pub fn redaction_row_counts(occurrences: u32, distinct: u32) -> String {
    if distinct > 0 && distinct < occurrences {
        format!("{occurrences} ({distinct} distinct)")
    } else {
        format!("{occurrences}")
    }
}

/// What a redaction mark in the transcript is, named on hover.
///
/// The marks themselves are not new -- the transcript has washed them in
/// gold since the pane was written. What is new is the NAME, which a
/// `GtkTextTag` cannot carry: a tag colours a run and has no label of its
/// own, so the name arrives as the tooltip over the mark.
///
/// Three sentences because the scrubber leaves three marker forms carrying
/// three different amounts of information, and none of them may be padded
/// out with a guess. See `crate::placeholders`.
pub fn redaction_mark_tooltip(kind: &str) -> String {
    format!("Removed: {kind}")
}

/// A repeat of a value already marked earlier in this transcript.
///
/// Only a numbered placeholder supports this claim: the redactor mints one
/// token per DISTINCT value and reuses it, so the same label and ordinal
/// twice is the same original string twice. Never said of a mark whose
/// marker carries no ordinal.
pub fn redaction_mark_repeat(kind: &str) -> String {
    format!("Removed: {kind} -- the same value as an earlier mark")
}

/// A mark whose marker names no category -- a bare `[REDACTED]`, which is
/// the form plain secrets land in. It says what it can and stops. Guessing
/// a category here would put a word on screen the scrubber never said.
pub const REDACTION_MARK_UNNAMED: &str = "Removed";

/// The back control at the head of a folder's sessions.
pub const ALL_FOLDERS: &str = "All folders";

/// A history folder row's right-hand figure. No byte total: a submitted
/// trace's size is not a thing the account keeps, and inventing one would be
/// worse than saying nothing.
pub fn history_folder_summary(submissions: usize) -> String {
    let unit = if submissions == 1 {
        "submission"
    } else {
        "submissions"
    };
    format!("{submissions} {unit}")
}

/// A folder row's right-hand figures: how much is waiting, and how big.
pub fn folder_summary(sessions: usize, bytes: u64) -> String {
    let unit = if sessions == 1 { "session" } else { "sessions" };
    format!(
        "{sessions} {unit}  \u{00b7}  {}",
        crate::model::human_bytes(bytes)
    )
}

/// Shown instead of the toast's own sentence when `approve` itself refused
/// the call -- an unrecognised `entry_id` or `project_id`, or any other
/// transport failure. This is not a skip: nothing about the request was
/// honoured, so none of the four toast clauses apply, and presenting it as
/// one would claim the daemon looked at entries it never touched.
pub const SUBMIT_FAILED: &str = "That couldn't be approved just now. Nothing has been approved.";

pub const QUEUE_EMPTY_TITLE: &str = "Nothing waiting";
pub const QUEUE_EMPTY_BODY: &str = "When a session finishes and goes quiet, it shows up here. \
     Nothing is sent unless you say so.";
pub const CHECKING: &str = "Checking what would be sent…";

/// The manifest strip's "Would send" field when the daemon's admission
/// control refused to preview a session at all -- see
/// `docs/superpowers/specs/2026-08-20-preview-scheduler-design.md`. Never
/// paired with a would-send figure of any kind: the preview card is a
/// consent surface, and a plausible-looking estimate for bytes that were
/// never built is worse than none.
pub const TOO_LARGE_TO_PREVIEW: &str = "too large to preview";

/// What the "Removed by pattern" field says instead of a count when
/// nothing was parsed at all.
pub const NOT_PREVIEWED: &str = "not previewed";

/// The caption under a too-large card, naming the one real number involved
/// -- `raw_session_bytes`, a `stat` of the file, never an estimate of what
/// would be sent.
pub fn too_large_caption(raw_session_bytes: u64) -> String {
    format!(
        "{} on disk -- too large to build a preview for automatically. \
         It can still be approved and sent; nothing here decides that.",
        crate::model::human_bytes(raw_session_bytes)
    )
}

/// The row's opening-prompt line for a too-large card, standing in for the
/// redacted opening prompt a preview never ran to produce.
pub const TOO_LARGE_OPENING_LINE: &str = "(too large to preview automatically)";

/// The standing concession, under the column rather than on every card.
/// Distinct on purpose from [`residual_risk_line`], which says what
/// scrubbing did to *one* session: this one says what scrubbing *is*.
pub const STANDING_DISCLAIMER: &str = "Scrubbing is local and pattern-based. It is good and it is \
     not perfect -- which is why you look before anything is sent.";

/// The manifest pair labels, §5.1 item 6. "Removed by pattern" names the
/// mechanism's *limit* in the label itself, which is the point: it is what
/// pattern matching found, not what was in there.
pub const WOULD_SEND: &str = "Would send";
pub const REMOVED_BY_PATTERN: &str = "Removed by pattern";

/// §6.2's attention chip, in both places it is earned: a session where
/// scrubbing removed nothing, and a search that found nothing. Neither is a
/// reassurance, which is why they share a wording that concedes rather than
/// one that congratulates.
pub const NOTHING_MATCHED: &str = "nothing matched";

/// What the chip does now that it is a control.
pub const NOTHING_MATCHED_TOOLTIP: &str = "Search this session for a value you are worried about";

/// A secret scrubbing FOUND and did not remove.
///
/// `residual_secret_at:*` counts a detection that survived redaction --
/// either a credential inside a correction the contributor wrote, which is
/// preserved on purpose, or a field the typed traversal does not reach. It
/// arrives in the same map as every genuine removal and used to render as
/// one, which is the opposite of the truth on the screen where somebody
/// decides whether to send the session.
///
/// The sites are schema-shaped identifiers (`events.3.correction`), never a
/// filesystem path and never transcript text.
///
/// Never names a number of secrets. The count is of detection SITES, and
/// one site can hold more than one value, so "3 secrets" would understate
/// what survived. The plural says "found in N places" instead, which is
/// what the number actually counts; the singular drops it entirely.
pub fn residual_secret_line(count: u32, sites: &[String]) -> String {
    let head = if count == 1 {
        "A secret found here is still in what would be sent".to_string()
    } else {
        format!("Secrets found in {count} places are still in what would be sent")
    };
    if sites.is_empty() {
        return head;
    }
    format!("{head} ({})", sites.join(", "))
}

/// The eyebrow over the count of things that did go out this week.
pub const CONTRIBUTED: &str = "Contributed";

/// The week band's heading.
pub const THIS_WEEK: &str = "This week";

pub fn waiting_heading(waiting: usize) -> String {
    match waiting {
        1 => "1 session waiting for your decision".to_string(),
        n => format!("{n} sessions waiting for your decision"),
    }
}

pub fn no_longer_waiting(count: u64) -> String {
    format!("Sessions no longer waiting ({count})")
}

/// The bound on what [`no_longer_waiting`] can account for, stated rather
/// than left to be assumed.
///
/// `queue_outcome_counts` counts entries that reached the queue. It cannot
/// explain a session the watcher discarded before an entry existed -- an
/// ineligible verdict, or a project set to be ignored -- and a contributor
/// who read this list as complete would come away believing sessions had
/// been accounted for that were never counted at all.
pub const NOT_OFFERED_BOUND: &str = "This covers sessions that reached the queue. Sessions that were never queued at all are not \
     counted here.";

// --- Preview -----------------------------------------------------------

/// The tab, which names a place. [`SEARCH_SUBMIT`] is the button, which
/// names an action; they are the same word today and are not the same
/// string, because only one of them is a verb.
pub const TAB_SEARCH: &str = "Search";
pub const TAB_WHATS_IN_IT: &str = "What's in it";
pub const TAB_WOULD_BE_SENT: &str = "Exactly what would be sent";
pub const TAB_PERMISSIONS: &str = "Permissions";
pub const SEARCH_PROMPT: &str = "Search this trace for anything you need to be sure isn't in it.";
pub const CONTRIBUTE: &str = "Contribute";

/// Shown where the transcript would be when the shell is attached to a
/// daemon it does not host. The contract serves the full redacted body
/// in-process only; saying so plainly beats an empty box.
pub const BODY_NOT_AVAILABLE_HERE: &str = concat!(
    "The full text can only be shown by the copy of ",
    app_name!(),
    " that is doing the watching. \
     A background watcher is running separately on this machine, so this window can show what \
     would be sent and what was scrubbed, but not the text itself. \
     `trace-commons-contributor daemon preview` shows the same summary from a terminal."
);

pub const PERMISSIONS_INTRO: &str =
    "If you contribute this session, it will carry these permissions:";
pub const PERMISSIONS_REQUESTED_NOTE: &str = concat!(
    "These are the permissions this device requests. ",
    app_name!(),
    " can narrow them, never widen them."
);
pub const UNENROLLED_PREVIEW: &str = "This is an illustration. This device isn't connected yet, so this was built without your \
     identity and nothing here can be contributed.";

/// The sheet's title, before the project label the call site appends.
pub const SHEET_TITLE_PREFIX: &str = "Look inside";

/// §6.2's locked chip, and the sentence beside it. Both say the same thing
/// the whole sheet exists to say: this is a rehearsal.
pub const NOTHING_SENT_YET: &str = "nothing sent yet";
pub const NOTHING_SENT_REASSURANCE: &str = "Nothing has been sent. This is what would be.";

/// The search button. See [`TAB_SEARCH`].
pub const SEARCH_SUBMIT: &str = "Search";
pub const RECENT_LABEL: &str = "Recent:";

/// What an empty search result says. A search that found nothing is not
/// evidence that nothing is there, and this is where that is said rather
/// than implied.
pub const NOTHING_MATCHED_BODY: &str = "A search only finds what is written the way you typed it. \
     If it matters, try the other spellings you would worry about -- a hostname, an internal \
     code name, an address.";

/// The button that puts the whole redacted body on the clipboard.
///
/// The transcript is laid out a chunk at a time, so a selection cannot span
/// the body the way it could when the tab was one clamped text view. This is
/// the replacement, and it is a better trade than it sounds: copying is a
/// string copy rather than a layout, so it is bounded work at any size.
pub const TRANSCRIPT_COPY_ALL: &str = "Copy everything";

/// The example is a `local_path` placeholder for a reason: `local_path` and
/// `private_email` are the only two labels that mint a numbered
/// `<PRIVATE_..._n>` token. `<PRIVATE_SECRET_1>`, which this line used to
/// show, is a shape the scrubber never produces -- a secret is replaced with
/// a bare `[REDACTED]`. Naming an impossible token taught the wrong thing on
/// the one screen that must be right about this.
///
/// The second sentence is not decoration. A mark shows where the rewriter
/// reached a typed field; the detector scans every leaf and the rewriter
/// does not reach all of them, so an unmarked stretch is not a clean one.
pub const TRANSCRIPT_CAPTION: &str = "These are the exact bytes an approval covers. Marks like \
     <PRIVATE_LOCAL_PATH_1> and [REDACTED] show where scrubbing fired. A stretch with no mark \
     is not a stretch with nothing in it -- scrubbing only rewrites the fields it reaches.";

// --- The consent surface ------------------------------------------------
//
// The sentence printed above `Contribute`, and the two tooltips beside it.
//
// The words are NOT here. They live in
// `trace_commons_contributor::consent_copy`, because the macOS and Windows
// shells print the same claim and reach it across the C ABI, and a claim
// about what leaves this machine kept in three places is three claims that
// have not diverged yet.
//
// `GATE_READY_HELP`, `GATE_NOT_PINNED_HELP` and `gate_help` are re-exported
// and not rendered: this shell puts no tooltip on `Contribute`. That is
// deliberate rather than an oversight -- they are here so that a screen
// which later grows one reaches for the shared sentence instead of writing
// a fourth.
//
// COPY-MIGRATED-BEGIN
//
// Everything between this marker and COPY-MIGRATED-END is swept by
// `a_migrated_region_of_copy_rs_holds_no_words_of_its_own`, which reads this
// file. The region may hold `pub use` and nothing else: a literal left
// beside a re-export is the word this shell would render while the other
// two render the shared one.
pub use trace_commons_contributor::consent_copy::{
    GATE_NOT_PINNED_HELP, GATE_READY_HELP, GATE_STATEMENT, gate_help,
};
// COPY-MIGRATED-END

/// The verdict control's question. Answering it is optional and never
/// gates `Contribute` -- see [`VERDICT_CAPTION`] for the disclosure that
/// makes the exemption explicit.
pub const VERDICT_QUESTION: &str = "Did this session do what you asked?";
pub const VERDICT_WORKED: &str = "Worked";
pub const VERDICT_PARTLY: &str = "Partly";
pub const VERDICT_FAILED: &str = "Failed";

/// Load-bearing, not decoration: the spec exempts the outcome fields from
/// the "the preview above is exactly what would be sent" guarantee, and
/// this sentence is where that exemption is disclosed to the contributor.
/// Do not drop or soften it.
pub const VERDICT_CAPTION: &str =
    "Optional. This is recorded as the trace outcome; the preview above does not show it.";

/// The correction field's prompt. Shown only under `Partly` and `Failed`:
/// a run the contributor has just called successful has nothing to correct,
/// and the field appearing there would invite text written for no reason.
pub const CORRECTION_QUESTION: &str = "What did it get wrong?";

/// The placeholder inside the box. It says the field is optional in the one
/// place a contributor is already looking, so the caption below can spend
/// all of its words on the thing that actually matters.
pub const CORRECTION_PLACEHOLDER: &str = "Optional";

/// **The disclosure, and the most load-bearing sentence in this file.**
///
/// Everything else a contributor writes or captures is scrubbed on this
/// machine and scrubbed again on the server. A correction is the one
/// exception: redaction would destroy the thing it exists to carry -- "it
/// edited /Users/x/proj/config.toml instead of the staging one" is useless
/// once the path is a placeholder -- so it is stored exactly as typed, with
/// only credential detection standing between it and the corpus.
///
/// The published policy page at <https://tracecommons.ai/legal/> promises
/// local redaction and a server-side re-application of it, and does not yet
/// carve this out. Until that clause is published, this sentence is the
/// ONLY disclosure a contributor gets that their own words are stored
/// verbatim. Do not shorten it for layout; change the layout.
///
/// One line, one escaped literal, for the same reason `GATE_STATEMENT` is:
/// the macOS and Windows shells are pinned against this exact text, and a
/// line break in any of the three would defeat the pin.
pub const CORRECTION_CAPTION: &str = "Stored exactly as you write it. Unlike the rest of the trace, a correction is not scrubbed here or on the server -- so leave out anything you would not want in the corpus: someone else's personal information, employer-confidential material, or anything you are not free to share.";

/// The credential refusal, headline and body.
///
/// Its own message rather than a line in the generic failure toast, because
/// it is the only submit failure the contributor caused and the only one
/// they can fix -- and because the second half is advice they will not get
/// anywhere else. A credential that has been typed into a box has been
/// typed; removing it from the text does not un-type it, so the sentence
/// says to rotate it.
///
/// Neither string quotes the correction, and neither names what matched.
pub const CORRECTION_CREDENTIAL_HEADLINE: &str =
    "Nothing was sent. Your correction looks like it contains a credential.";
pub const CORRECTION_CREDENTIAL_BODY: &str = "A correction is stored as you write it, so this one was refused rather than masked. Take the credential out and submit again -- and rotate it, because it has already been typed here.";

/// The bulk verdict menu beside `Submit all`. The plain button stays a
/// one-click unanswered submit; this is the opt-in path for answering
/// once for the whole group.
pub const SUBMIT_ALL_AS: &str = "Submit all as...";
pub const SUBMIT_ALL_AS_TOOLTIP: &str = "Record the same outcome for every session in this group.";

pub const CLOSE: &str = "Close";

// --- Approving ---------------------------------------------------------

pub const SENDING: &str = "Sending…";
pub const UNDO: &str = "Undo";

pub fn undo_headline(project_label: &str) -> String {
    format!("Approved {project_label}. Still on this machine.")
}

/// Explains automatic sending and when approval can still be undone.
pub const UNDO_BODY: &str =
    "Approved sessions will send automatically. You can undo until uploading starts.";

/// Closes the notice without changing the approval.
pub const LET_IT_SEND: &str = "Dismiss";

// --- Credit ------------------------------------------------------------

pub const CREDIT_HEADING: &str = "About credit";
/// §5.3's eyebrow over the credit card. [`CREDIT_HEADING`] reads "About
/// credit", which titles a paragraph rather than labelling a figure; the
/// section rule beneath it wants the shorter word.
pub const CREDIT_SECTION: &str = "Credit";
pub const CREDIT_BODY: &str = "Contributions earn credit points, scored on how novel and \
     information-rich a trace is. Today credit is a record, not a currency: there is no payout, \
     no token, no exchange rate, and no date. The intent is that credit eventually settles to \
     something real, and if it does it will settle from this record. Contribute because you want \
     the commons to exist.";
pub const NOT_SYNCED_YET: &str = "Not synced yet";

// --- History -----------------------------------------------------------

pub const HISTORY_IN_THE_COMMONS: &str = "In the commons";
pub const HISTORY_WAITING_TO_BE_SCORED: &str = "Waiting to be scored";

/// §5.3's section heading over the record rows.
pub const EVERYTHING_CONTRIBUTED: &str = "Everything you've contributed";

/// §5.3's chip on a withdrawn record. The record stays on the list and
/// reads as withdrawn (§7.3); it is never dropped and never re-labelled as
/// something that failed.
pub const WITHDRAWN_BY_YOU: &str = "Withdrawn by you";

/// §5.3's row-level explanation on a held record, used only when the server
/// sent no explanation of its own. It says the same three things
/// [`QUARANTINE_BODY`] says -- automated, not rejected, not shared -- at row
/// length rather than at section length.
pub const HELD_ROW_BODY: &str = "Automated checks saw something that might be personal and \
     couldn't decide on their own. It has not been rejected, and it has not been shared with \
     anyone but the agent that inspects it.";
pub const QUARANTINE_HEADING: &str = "Held for privacy review";
pub const QUARANTINE_BODY: &str = "An agent inspects these before they enter the commons. It \
     happens when automated checks see something that might be personal or sensitive and can't \
     decide on its own.\n\nThese have not been rejected, and they have not been shared with \
     anyone but the agent that inspects them. They are sitting still.\n\nTypical wait: we don't \
     have a reliable number yet.";

// --- Withdrawal --------------------------------------------------------
//
// Withdrawal is the one place in this product where a plausible-sounding
// phrase becomes a false promise about erasure, so the three confirmation
// bodies are NOT this shell's to write. They are fixed in
// `docs/contributor-daemon-ipc-v1_1.md`'s "Canonical confirmation copy"
// table, reproduced here word for word, and the tests at the foot of this
// file fail if they are paraphrased, shortened, or "tightened".
//
// Five rules come with them, and each is honoured somewhere below:
//
// 1. Never a generic "withdrawn" -- [`withdraw_result_sentence`] always
//    names what the tier that actually applied did.
// 2. Never claim more erasure than the tier achieved -- which is why
//    [`withdraw_confirmation`] shows an `accepted` trace BOTH commons
//    bodies rather than picking the gentler one.
// 3. Withdrawal does not reverse settled credit -- [`WITHDRAW_CREDIT_NOTE`],
//    and nothing here implies otherwise.
// 4. `not_found` must not disclose which -- [`WITHDRAW_NOT_FOUND`].
// 5. Bulk withdrawal spans tiers -- [`WITHDRAW_NO_BULK`] says why this
//    shell does not offer it.
//
// ## Why the confirmation cannot simply state the tier
//
// The server computes `distribution_reach` *during* the withdrawal, from
// live export membership. It arrives in the response, and the confirmation
// has to be shown before that response exists. All this machine holds is
// the record's `status`, so the confirmation is keyed on that instead --
// see [`WithdrawStage`].

/// `distribution_reach` as the server spells it. Wire strings rather than a
/// typed enum: the shell only ever looks a tier up to find its sentence,
/// and an unrecognised one is reported as unrecognised (see
/// [`withdraw_result_sentence`]) rather than failing to parse.
pub const REACH_NOT_DISTRIBUTED: &str = "not_distributed";
pub const REACH_COMMONS_NOT_DISTRIBUTED: &str = "commons_not_distributed";
pub const REACH_COMMONS_DISTRIBUTED: &str = "commons_distributed";

/// Canonical copy for `not_distributed`, verbatim.
pub const WITHDRAW_BODY_NOT_DISTRIBUTED: &str = "This trace never entered the commons. Withdrawing deletes it. Nothing was distributed and \
     nothing needs recalling.";

/// Canonical copy for `commons_not_distributed`, verbatim.
pub const WITHDRAW_BODY_COMMONS_NOT_DISTRIBUTED: &str = "This trace is in the commons but has not been included in any published export or benchmark \
     yet. Withdrawing deletes it and excludes it from everything published from here on.";

/// Canonical copy for `commons_distributed`, verbatim. The clause from "but
/// copies" onward is the one sentence in this feature that must never be
/// softened, shortened, or quietly dropped.
pub const WITHDRAW_BODY_COMMONS_DISTRIBUTED: &str = "This trace has already been included in a published export or benchmark. Withdrawing \
     deletes our copy and excludes it from everything published from here on, but copies that \
     have already been distributed cannot be recalled. Withdrawing does not undo that.";

/// Credit is not clawed back, and this says only that -- nothing about how
/// much, when it settles, or what it is worth.
pub const WITHDRAW_CREDIT_NOTE: &str = "Credit already recorded stays.";

/// The canonical body for a tier, or `None` for a tier this build has never
/// heard of.
pub fn withdraw_canonical_body(reach: &str) -> Option<&'static str> {
    match reach {
        REACH_NOT_DISTRIBUTED => Some(WITHDRAW_BODY_NOT_DISTRIBUTED),
        REACH_COMMONS_NOT_DISTRIBUTED => Some(WITHDRAW_BODY_COMMONS_NOT_DISTRIBUTED),
        REACH_COMMONS_DISTRIBUTED => Some(WITHDRAW_BODY_COMMONS_DISTRIBUTED),
        _ => None,
    }
}

/// What this machine can honestly say about how far a trace got, read off
/// the history record's `status`. Not the server's tier: this is the weaker
/// thing the client knows before it asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawStage {
    /// `submitted` or `quarantined`. `not_distributed`, exactly -- that is
    /// the server's own rule.
    NotInTheCommons,
    /// `accepted`. One of the two commons tiers, and not knowable which.
    InTheCommons,
    /// Any other status this build does not recognise. Treated as the worst
    /// case, because the furthest reach cannot be ruled out.
    Unknown,
}

impl WithdrawStage {
    pub fn of_status(status: &str) -> Self {
        match status {
            "submitted" | "quarantined" => Self::NotInTheCommons,
            "accepted" => Self::InTheCommons,
            _ => Self::Unknown,
        }
    }
}

/// The confirmation as parts rather than one blob, so the dialog can weight
/// the body carrying the cannot-be-recalled clause and leave the rest as
/// ordinary body copy.
pub struct WithdrawConfirmation {
    pub question: &'static str,
    /// Present only where the tier is ambiguous: says so, in this shell's
    /// own words, before the canonical bodies it cannot choose between.
    pub ambiguity: Option<&'static str>,
    /// Canonical bodies that may apply, in order. One when the tier is
    /// known, two when it is not.
    pub bodies: &'static [&'static str],
    /// Index into `bodies` of the one carrying the cannot-be-recalled
    /// clause, so the dialog can weight it. `None` when none does.
    pub gravest: Option<usize>,
    pub credit: &'static str,
    /// "Withdraw" where the outcome is unambiguous, "Withdraw anyway" where
    /// the contributor is being asked to accept a limit.
    pub confirm_label: &'static str,
}

pub const WITHDRAW_QUESTION: &str = "Withdraw this trace?";
pub const WITHDRAW: &str = "Withdraw";
pub const WITHDRAW_ANYWAY: &str = "Withdraw anyway";
pub const WITHDRAW_CANCEL: &str = "Keep it";

pub fn withdraw_confirmation(stage: WithdrawStage) -> WithdrawConfirmation {
    match stage {
        WithdrawStage::NotInTheCommons => WithdrawConfirmation {
            question: WITHDRAW_QUESTION,
            ambiguity: None,
            bodies: &[WITHDRAW_BODY_NOT_DISTRIBUTED],
            gravest: None,
            credit: WITHDRAW_CREDIT_NOTE,
            confirm_label: WITHDRAW,
        },
        WithdrawStage::InTheCommons => WithdrawConfirmation {
            question: WITHDRAW_QUESTION,
            ambiguity: Some(
                "This trace is in the commons. Whether it has already gone into a published \
                 export or benchmark is decided on the server, and this window cannot tell from \
                 here which of these two applies:",
            ),
            bodies: &[
                WITHDRAW_BODY_COMMONS_NOT_DISTRIBUTED,
                WITHDRAW_BODY_COMMONS_DISTRIBUTED,
            ],
            gravest: Some(1),
            credit: WITHDRAW_CREDIT_NOTE,
            confirm_label: WITHDRAW_ANYWAY,
        },
        WithdrawStage::Unknown => WithdrawConfirmation {
            question: WITHDRAW_QUESTION,
            ambiguity: Some(
                "This session may already have been distributed. Withdrawal cannot recall distributed copies.",
            ),
            bodies: &[WITHDRAW_BODY_COMMONS_DISTRIBUTED],
            gravest: Some(0),
            credit: WITHDRAW_CREDIT_NOTE,
            confirm_label: WITHDRAW_ANYWAY,
        },
    }
}

/// What actually happened, from the tier the server applied. Never a
/// generic "withdrawn": the canonical body for the tier that applied is
/// what says which of the three outcomes this was.
pub fn withdraw_result_sentence(reach: Option<&str>) -> String {
    match reach.and_then(withdraw_canonical_body) {
        Some(body) => format!("Withdrawn. {body}"),
        // The daemon sent a tier this build does not know. The withdrawal
        // happened; what cannot be stated is how far the trace had
        // travelled -- so the furthest tier is not ruled out.
        None => "Withdrawn, but the server did not report which of the three tiers applied, so \
                 this window cannot tell you whether it had already been included in a published \
                 export or benchmark. If it had, copies that have already been distributed \
                 cannot be recalled."
            .to_string(),
    }
}

/// Withdrawal is authenticated by an account session, which this build has
/// no way to obtain. Leads with the fact that nothing happened: a
/// contributor must not walk away from a failed withdrawal believing their
/// trace was taken back.
pub const WITHDRAW_ACCOUNT_SESSION_REQUIRED: &str = concat!(
    "Nothing was withdrawn and nothing was deleted. Withdrawal is an account-level act, so it \
     is authenticated by your ",
    app_name!(),
    " account rather than by this device -- that is what lets you withdraw a trace after \
     losing the machine that sent it. This build has no account sign-in yet, so it cannot \
     make the request."
);

/// The daemon's label for "the server has no record of this submission for
/// this account".
///
/// The server answers identically whether the submission belongs to someone
/// else or does not exist at all, so that accounts cannot be enumerated,
/// and this window must not undo that by guessing out loud. So this sentence
/// says neither.
pub const WITHDRAW_NOT_FOUND: &str = "Nothing was withdrawn and nothing was deleted. There is no trace with that id under your \
     account.";

/// The daemon labels that mean not-found. Unreachable today --
/// `daemon/withdraw.rs` collapses every failure into `withdraw-failed` --
/// and handled anyway, because the day that label is passed through is not
/// the day to be inventing this sentence.
pub const WITHDRAW_NOT_FOUND_LABELS: [&str; 3] = ["not-found", "not_found", "submission-not-found"];

/// Any other failure. Same first clause, for the same reason.
///
/// The label is the daemon's fixed, content-free error message, which by
/// contract is never a path, a token, or a response body -- so printing it
/// cannot leak one, and leaving it out would make two different failures
/// indistinguishable to whoever is asked to help.
pub fn withdraw_failure_sentence(label: &str) -> String {
    if label == "account-session-required" {
        return WITHDRAW_ACCOUNT_SESSION_REQUIRED.to_string();
    }
    if WITHDRAW_NOT_FOUND_LABELS.contains(&label) {
        return WITHDRAW_NOT_FOUND.to_string();
    }
    format!(
        "Nothing was withdrawn and nothing was deleted. The request did not go through \
         ({label}). You can try again."
    )
}

/// Why the held group has no "withdraw all of these" button, even though
/// the shared design draws one.
///
/// Rule 6 permits bulk only if the confirmation can say the selected traces
/// may fall into different tiers and that some may already have been
/// distributed. There is a second problem on top of that one, and it is the
/// reason bulk is left out rather than worded around: `withdraw_bulk`
/// reports only `withdrawn` and `failed` counts, so afterwards there is no
/// per-trace tier to report and rule 1 cannot be honoured at all.
pub const WITHDRAW_NO_BULK: &str = "Withdraw sessions individually to see the result for each one.";

/// The row-level progress label while a withdrawal is in flight. Present
/// tense, because nothing has happened yet.
pub const WITHDRAWING: &str = "Withdrawing…";

// --- Checking for updates -----------------------------------------------

/// The History button behind `refresh_history`.
pub const CHECK_FOR_UPDATES: &str = "Check for updates";

/// What `refresh_history` actually achieved, said accurately.
///
/// The daemon answers `requested: true` and nothing else: the background
/// poller owns the network call, and this only asks it to run sooner. So
/// this sentence says the ask landed, never that anything was fetched --
/// "Updated" would be a claim about a round trip that has not happened yet.
pub const CHECK_FOR_UPDATES_ASKED: &str =
    "Asked for an update. New results appear here as they arrive.";

// --- Community ---------------------------------------------------------
//
// §5.5's panel in History and §5.6's block in Settings are the two public
// surfaces. They share their words as well as their stylesheet: the link
// out of both is the same link.

pub const COMMUNITY_HEADING: &str = "Community";

/// The way out to the public page, from either surface. The arrow is part
/// of the wording, not decoration: it is what says the destination is not
/// in this window.
pub const VIEW_PUBLIC_PROFILE: &str = "View public profile \u{2197}";

/// §7.3: analytics that are withheld are stated in words, never as an empty
/// chart.
pub const COMMUNITY_ANALYTICS_WITHHELD: &str = "Corpus analytics are withheld. The server \
     publishes the roster on consent, but will not publish aggregates without an approved noise \
     mechanism -- so nothing is charted here either.";

/// The footnote below the panel, in native type: the section is a
/// consequence of one setting, and says which one.
pub const COMMUNITY_FOOTNOTE: &str = "Shown only while \"List my handle publicly\" is on. Turn it \
     off in Settings and this section disappears with it.";

// --- Settings: connection ------------------------------------------------

pub const CONNECTION_HEADING: &str = "Connection";
pub const CONNECTED: &str = "Connected";
pub const NOT_CONNECTED: &str = "Not connected";
// The two session-source rows are NOT constants here. They were, as a
// set/default pair each, and the "default" half was printed for `off` as
// well as for `unset` -- so a contributor who said they do not use Claude
// Code was told its sessions were being read from the usual place. Three
// modes need three sentences, and the other two shells print them too, so
// the words live in `trace_commons_contributor::source_copy` and this
// shell re-exports the one definition.
pub use trace_commons_contributor::source_copy::{SourceTool, source_check_line};
pub const CHECK_SCAN_SET: &str = "Extra privacy scan configured";
pub const CHECK_SCAN_UNSET: &str = "No extra privacy scan";

// --- Settings: how it behaves --------------------------------------------
//
// The three timing knobs `set_settings` accepts, as a title and a unit
// each. Every one of them is a promise the daemon keeps -- how long a
// session must be quiet, how long an approval is held, how often a
// contributor may be interrupted -- so each label says what the number does
// to the contributor rather than naming the setting.

pub const KNOB_QUIESCENCE_TITLE: &str = "Quiet time before a session counts as finished";
pub const KNOB_QUIESCENCE_UNIT: &str = "minutes";
pub const KNOB_HOLD_TITLE: &str = "How long you can take something back";
pub const KNOB_HOLD_UNIT: &str = "seconds after you approve";

/// A hold of zero is not a smaller undo window, it is no undo window at
/// all, and the row says so rather than showing a bare `0`.
pub const KNOB_HOLD_ZERO: &str = "No undo window. Approving sends on the next pass.";
pub const KNOB_DIGEST_TITLE: &str = "How often you can be interrupted";
pub const KNOB_DIGEST_UNIT: &str = "hours between notifications, at most";

/// Where a change made here lands, said once under the three of them.
///
/// On Linux the watcher is usually a separate process, so "this window" is
/// the wrong mental model for what was just changed -- and a contributor
/// who thought these were window preferences would be surprised by them
/// still holding after the window closed.
pub const KNOBS_NOTE: &str = "These govern the background watcher, not this window, and take \
     effect as soon as they are changed. The same values are readable and settable from the \
     command line.";

// --- Settings: daily upload budget ----------------------------------------
//
// A separate section from the three timing knobs above on purpose: those
// govern *when* the daemon interrupts or waits, and these bound how much it
// is willing to send in a day -- the cap that exists to stop a runaway
// client, not a convenience setting. Kept as its own card so lowering it
// (a contributor's own throttle) and raising it (unsticking a budget that
// was already spent) read as one topic, distinct from the pacing knobs.

pub const BUDGET_HEADING: &str = "Daily upload budget";
pub const KNOB_MAX_UPLOADS_TITLE: &str = "Uploads allowed per day";
pub const KNOB_MAX_UPLOADS_UNIT: &str = "uploads/day";
pub const KNOB_MAX_BYTES_TITLE: &str = "Data allowed per day";
pub const KNOB_MAX_BYTES_UNIT: &str = "MB/day";

/// Under both budget knobs. Says why they cannot be turned off entirely and
/// what turning them down really means, since a cap of zero is refused
/// rather than silently accepted as "stop uploading" -- see `KNOB_NOT_CHANGED`
/// for what a contributor sees if they try.
pub const BUDGET_NOTE: &str = "These bound how much can be sent in a day, not whether anything \
     can. Lowering either is a throttle you control; there is no way to raise them past a fixed \
     ceiling, because the whole point of a daily budget is that nothing on this machine can \
     spend past it. Changes take effect immediately, with nothing queued waiting for a restart.";

/// A refused write. States the data consequence -- nothing changed -- since
/// a knob that silently snapped back would otherwise look like a value that
/// had been accepted.
pub const KNOB_NOT_CHANGED: &str = "That couldn't be changed just now. Nothing was changed.";

// --- Settings: the public profile, §5.6 ----------------------------------

pub const PUBLIC_HEADING: &str = "Your public profile";
pub const LIST_HANDLE_PUBLICLY: &str = "List my handle publicly";
pub const PUBLIC_FOOTNOTE: &str = "Attribution only -- being listed grants no data use at all. \
     Leaving the roster removes you from future snapshots.";
/// The date is the daemon's, formatted at the call site; only the sentence
/// around it lives here.
pub fn on_roster_since(date: &str) -> String {
    format!("On the roster since {date}")
}
pub const HANDLE_LABEL: &str = "Handle";
pub const BIO_LABEL: &str = "Bio -- 280 bytes, plaintext, no HTML";
pub const SAVE_PROFILE: &str = "Save profile";
pub const LEAVE_ROSTER: &str = "Leave the roster";

// --- The go-public dialog, §5.7 ------------------------------------------

pub const GO_PUBLIC_TITLE: &str = "Go public?";
pub const GO_PUBLIC_HEADLINE: &str = "Put your handle on the public roster?";
pub const PUBLISHED_HEADING: &str = "What gets published";
pub const PUBLISHED_BODY: &str = "Your handle -- real handles only, no pseudonyms. Aggregate \
     counts: accepted, novelty credit, accept rate. The date you went public. Your bio, if you \
     write one.";
pub const NEVER_HEADING: &str = "What never does";
pub const NEVER_BODY: &str = "Your traces or anything in them. Per-trace data of any kind. \
     Anything about sessions you didn't send.";
pub const GO_PUBLIC_ACKNOWLEDGEMENT: &str = "I understand my handle and aggregate counts become \
     public. Leaving the roster removes me from future snapshots.";
pub const GO_PUBLIC_CONFIRM: &str = "Go public";
pub const GO_PUBLIC_FOOTNOTE: &str = "Nothing is pre-checked, and Go public stays off until the \
     acknowledgement is on. This changes attribution only -- it grants no data use.";
/// The handle field inside the dialog. The panel's `HANDLE_LABEL` names
/// the same thing, so the same constant would do -- except that here the
/// field is empty and has to say what to put in it, and "Handle" over an
/// empty box does not.
pub const GO_PUBLIC_HANDLE_LABEL: &str = "The handle to publish";
/// The optional bio, said as optional. `BIO_LABEL` carries the budget and
/// the format; what it cannot carry is that leaving this empty is a
/// complete answer rather than an unfinished form.
pub const GO_PUBLIC_BIO_LABEL: &str = "Bio, if you want one -- 280 bytes, plaintext, no HTML";

// --- What claiming and leaving actually did, §5.6 ------------------------
//
// Every sentence below states what is true of the *public* surface first,
// because that is the thing the contributor just changed and the thing
// they cannot inspect from this window. What this device managed to write
// down about it is a second, lesser fact and is worded as one.

/// A claim the server accepted.
pub const PROFILE_PUBLISHED: &str =
    "You're on the roster. Your handle and aggregate counts are public now.";

/// A claim the server accepted and this device then failed to write down.
///
/// This is what `handle_persisted: false` means, and it is emphatically
/// not a failed claim: the server has taken the handle, so the profile is
/// public whatever happened on this machine afterwards. Telling a
/// contributor their handle did not go up when it did is the one error
/// this surface must never make -- it is a false statement about a public,
/// outward-facing act, and they would walk away believing they are
/// unlisted. So the sentence leads with the publication, and describes the
/// local loss for exactly what it is: this window will misreport the state
/// until the next successful save, and nothing public changes either way.
pub const PROFILE_PUBLISHED_NOT_CACHED: &str = "You're on the roster -- your handle and aggregate counts are public now. This device \
     couldn't keep its own copy of the profile, so this window will show you as unlisted again \
     until you save it once more. That doesn't change anything about what is public.";

/// A withdrawal the server accepted.
pub const PROFILE_LEFT_ROSTER: &str = "You've left the roster. Your handle isn't published any \
     more, and future snapshots won't include you.";

/// A withdrawal the server accepted and this device then failed to write
/// down. The mirror of `PROFILE_PUBLISHED_NOT_CACHED`, and stated for the
/// same reason: the row is gone from the server regardless, so the
/// withdrawal is not in doubt -- only what this window will show next.
pub const PROFILE_LEFT_ROSTER_NOT_CACHED: &str = "You've left the roster -- your handle isn't published any more, and future snapshots won't \
     include you. This device couldn't clear its own copy of the profile, so this window may show \
     the old handle again until it can.";

/// A claim the server or the daemon refused, from the daemon's fixed
/// label.
///
/// Every branch says that nothing was published, because in every one of
/// them nothing was: the refusal happens before or instead of the `PUT`.
/// The rules themselves are not re-implemented here -- the daemon and the
/// server share one copy of them in `community_handle`, and a second copy
/// in this window is how a handle this shell accepts becomes a handle the
/// server refuses. These sentences only translate the verdict.
pub fn profile_failure_sentence(label: &str) -> String {
    let reason = match label {
        "handle-required" => "There's no handle in the box yet.",
        "handle-too-short" => "That handle is too short -- it needs at least 3 characters.",
        "handle-too-long" => "That handle is too long -- 32 characters at most.",
        "handle-invalid-character" => {
            "A handle can only use letters, numbers, hyphens and underscores."
        }
        "handle-invalid-boundary" => "A handle has to start and end with a letter or a number.",
        "handle-consecutive-separators" => {
            "A handle can't have two hyphens or underscores in a row."
        }
        "handle-reserved" => "That handle is reserved and can't be claimed.",
        "bio-too-long" => "That bio is over the 280-byte budget.",
        "bio-invalid-character" => "That bio has a character the roster doesn't take.",
        // Not reachable from this window -- it always sends a bio key, null
        // or a string -- and handled anyway, so a contract change surfaces
        // as a sentence rather than as the fallback below.
        "bio-required-or-null" | "bio-invalid" => "The bio wasn't sent in a form the roster takes.",
        "not-logged-in" => concat!("This device isn't connected to ", app_name!(), "."),
        // The underlying failure is never forwarded by the daemon -- it can
        // carry a server response body or a URL -- so there is nothing more
        // specific to say than that it did not go through.
        "profile-update-failed" | "profile-withdraw-failed" | "daemon-not-running" => {
            "The request didn't go through."
        }
        _ => "The request didn't go through.",
    };
    format!("{reason} Nothing was published and nothing changed. You can try again.")
}

/// The same, for a withdrawal: "nothing was published" is the wrong second
/// clause when what failed was an attempt to *un*-publish, and a
/// contributor who read it could conclude they had been taken off the
/// roster when they are still on it.
pub fn roster_leave_failure_sentence(label: &str) -> String {
    let reason = match label {
        "not-logged-in" => concat!("This device isn't connected to ", app_name!(), "."),
        _ => "The request didn't go through.",
    };
    format!(
        "{reason} You're still on the roster and your handle is still published. You can try \
             again."
    )
}

// --- Declining -----------------------------------------------------------

/// The one way this product declines to do something now: "Not now", never
/// "Cancel" and never "No". It is one constant rather than one per dialog
/// because the word is a stance, not a label -- nothing here is ever
/// refused, only not done yet, and three copies of the sentence are three
/// chances for one of them to stop saying that. Used by the arming dialog
/// (§5.1), the go-public dialog (§5.7) and the desktop notification.
pub const NOT_NOW: &str = "Not now";

// --- The arming offer --------------------------------------------------

/// The evidence, stated before the question, so a contributor who reads only
/// the first line still learns why they are being asked.
pub fn arming_offer_evidence(project_label: &str, count: u32) -> String {
    let times = if count == 1 {
        "once".to_string()
    } else {
        format!("{count} times")
    };
    format!("You've contributed from {project_label} {times}.")
}

pub fn arming_offer_question(project_label: &str) -> String {
    format!("Contribute from {project_label} automatically?")
}

pub const ARMING_OFFER_CONFIRM: &str = "Turn on automatic contributing";
/// "Not now" rather than "No": the daemon silences the offer for thirty days
/// rather than forever, and the button must not promise otherwise.
pub const ARMING_OFFER_DECLINE: &str = "Not now";

// --- Arming ------------------------------------------------------------

pub fn arming_heading(project_label: &str) -> String {
    format!("Contribute from {project_label} automatically?")
}
pub const ARMING_BODY: &str = "Every future session in this project will be scrubbed and \
     contributed without asking you. You won't review them first.\n\nA session is sent a day \
     after you last work on it, so there is time to change your mind.\n\nYou can turn this off \
     at any time.";
pub const ARMING_CONFIRM: &str = "Turn on automatic contributing";

// --- Quitting ----------------------------------------------------------

/// The Linux wording, and it is the *second* of the two the shared spec
/// gives. It is true only where a separate daemon keeps running after the
/// window closes; where this application is itself the watcher, the first
/// wording applies. Which one is shown is decided at runtime by which of
/// those two this process actually is -- getting it wrong is a lie about
/// whether the machine is still watching. See `QUIT_HOSTING_BODY`.
pub const QUIT_ATTACHED_BODY: &str = "The background watcher keeps running and will keep queuing \
     sessions. Nothing will be sent while nobody's approving.";
pub const QUIT_ATTACHED_CONFIRM: &str = "Quit";
pub const QUIT_ATTACHED_ALSO_STOP: &str = "Quit and stop watching";

pub const QUIT_HOSTING_BODY: &str = concat!(
    "Quitting stops ",
    app_name!(),
    " watching for finished sessions. Nothing is queued or sent until you open it again. \
     Anything already waiting stays waiting."
);
pub const QUIT_HOSTING_CANCEL: &str = "Cancel";
pub const QUIT_HOSTING_CONFIRM: &str = "Quit";

// --- Notifications -----------------------------------------------------

pub const NOTIFY_REVIEW: &str = "Review";
pub const NOTIFY_NOTHING_SENT: &str = "Nothing is sent until you review them.";

// --- Background portal ---------------------------------------------------

/// Shown to the desktop's own permission dialog, not to a widget in this
/// window -- `org.freedesktop.portal.Background`'s `reason` option is
/// rendered by the portal implementation itself (GNOME Shell, Plasma, ...).
pub const PORTAL_BACKGROUND_REASON: &str = concat!(
    app_name!(),
    " reviews new sessions and uploads only what you approve."
);

// --- Autostart -----------------------------------------------------------

pub const AUTOSTART_HEADING: &str = "Starting automatically";
/// Shown when the systemd user unit is doing the job. The service name is
/// not a filesystem path, so naming it here does not violate the no-paths
/// rule.
pub const AUTOSTART_SYSTEMD_BODY: &str = concat!(
    "A background service you installed already starts ",
    app_name!(),
    " at login. Manage it with systemctl --user, not from here, so this window and that \
     service never disagree about whether it's running."
);
pub const AUTOSTART_XDG_LABEL: &str = concat!("Start ", app_name!(), " when you log in");
pub const AUTOSTART_XDG_BODY: &str =
    "No background service is installed, so this switch is the other way to do it.";

// --- Background portal probe ----------------------------------------------

/// Shown while `portal::spawn_request`'s classification is still in
/// flight. Replaced by `portal_status_line` once it lands.
pub const PORTAL_STATUS_CHECKING: &str = "Checking whether this desktop can list background apps…";

/// The background-registration row, chosen from both of the two things
/// that actually decide it: whether this desktop has a `Background` portal
/// backend at all (`state`), and whether the systemd user unit -- not this
/// window, and not the portal -- is what really keeps Trace Commons running
/// (`systemd_unit_installed`, from `autostart::detect`).
///
/// The portal is not what keeps the process alive on any desktop; systemd
/// is, with `loginctl enable-linger` needed to survive logout, and no
/// portal can do that on any desktop either. The portal's only job here is
/// being listed in GNOME's or Plasma's own "Background Apps" UI and not
/// being treated as a rogue process. So a desktop with no such backend
/// (XFCE, Cinnamon, MATE, Budgie, Sway, and other wlroots compositors) is
/// not a degraded product when the systemd unit is doing the real work --
/// and it is a real, nameable gap when nothing is.
pub fn portal_status_line(
    state: crate::portal::BackendState,
    systemd_unit_installed: bool,
) -> &'static str {
    use crate::portal::BackendState::{Absent, Present, Unknown};
    match (state, systemd_unit_installed) {
        (Present, true) => {
            concat!(
                "This desktop can list ",
                app_name!(),
                " as a background app. The systemd service you installed is what actually \
                 keeps it running."
            )
        }
        (Present, false) => {
            concat!(
                "This desktop can list ",
                app_name!(),
                " as a background app. That listing alone doesn't keep it running past login \
                 -- the switch above does."
            )
        }
        (Absent, true) => {
            concat!(
                "This desktop has no background-app list to register with. Nothing is wrong: \
                 the systemd service you installed is what keeps ",
                app_name!(),
                " running here, the same as it would anywhere else."
            )
        }
        (Absent, false) => {
            concat!(
                "This desktop has no background-app list to register with, and no systemd \
                 service is installed either, so ",
                app_name!(),
                " only runs while this window is open. Turn on the switch above, or install \
                 the service, to change that."
            )
        }
        (Unknown, true) => {
            concat!(
                "Couldn't tell whether this desktop can list background apps. Either way, the \
                 systemd service you installed is what keeps ",
                app_name!(),
                " running."
            )
        }
        (Unknown, false) => {
            concat!(
                "Couldn't tell whether this desktop can list background apps. No systemd \
                 service is installed, so right now ",
                app_name!(),
                " only runs while this window is open."
            )
        }
    }
}

// --- Flatpak session-root access (for onboarding, not yet built) ---------

/// The Linux design spec's exact wording for why a confined build asks for
/// two specific folders rather than the whole home directory. Onboarding
/// does not exist yet (see the report), so nothing renders this today; it
/// is pinned here so the string is ready and cannot drift from the spec
/// when onboarding is built.
pub const FLATPAK_SESSION_ROOTS_EXPLANATION: &str = concat!(
    app_name!(),
    " needs to read your Claude Code and Codex session files. It asks for access to those \
     folders only."
);

// --- Health ------------------------------------------------------------

/// The sentence to render for a `status.health.last_error_label`.
///
/// The daemon picks exactly one label by its own precedence order; a client
/// must not reconstruct that order or choose a different label to show. So
/// this is a lookup, not a decision.
pub fn health_sentence(label: &str) -> &'static str {
    match label {
        "opencode-export-version-unsupported" => {
            trace_commons_contributor::source_copy::OPENCODE_VERSION_DETAIL
        }
        "not-logged-in" => {
            "Not connected. Sessions are being queued, but nothing can be sent until you \
             reconnect. Nothing has been lost."
        }
        "pii-filter-unavailable" => {
            "The extra privacy scan isn't reachable. Your traces are waiting rather than going \
             out unscanned. Retrying automatically."
        }
        "privacy-filter-canary-failed" => {
            "The privacy scan failed its own self-test, so nothing is being sent through it. \
             This is deliberate -- a scan we can't verify doesn't get used."
        }
        "near-ai-notice-not-acknowledged" => {
            "One thing to confirm. You chose the extra privacy scan, which sends message text to \
             NEAR AI. Confirm you're OK with that and contributions resume."
        }
        "claim-mint-failed" | "ingest-unreachable" => {
            concat!(
                "Can't reach ",
                app_name!(),
                " right now. Your queue is safe; it'll retry on its own."
            )
        }
        // The banner for this condition is built by `daily_cap_sentence`,
        // which can say how many traces are waiting and exactly when the
        // limit resets. This line is the fallback for a daemon that
        // reported the label without the budget object -- so it must not
        // promise a time it does not have.
        "daily-cap-reached" => {
            "Today's upload limit is used up. Approved traces are waiting; nothing has been lost, \
             and they go out when the limit resets."
        }
        "queue-full" => {
            concat!(
                app_name!(),
                " has stopped queuing new sessions -- 500 are already waiting. Review or clear \
                 some to start again."
            )
        }
        // An unrecognized label is still a real condition. Say the true
        // thing that holds for every blocking label rather than inventing a
        // mechanism name for it.
        _ => "Something is holding contributions up. Your queue is safe; nothing has been lost.",
    }
}

/// The banner sentence for a spent daily budget.
///
/// Said separately from `health_sentence` because the daemon reports the
/// budget separately from the health label: `daily-cap-reached` is last in
/// the precedence order, so on the machine this was written for the slot
/// was occupied by `queue-full` and the real reason nothing was uploading
/// never reached a screen at all.
///
/// Everything in it is something the daemon actually knows. The reset time
/// is `status.daily_budget.resets_at`, rendered in local time; when it is
/// absent the sentence stops rather than guessing at "tomorrow". It is not
/// phrased as an error, because nothing has gone wrong and nothing has been
/// lost.
pub fn daily_cap_sentence(
    blocked_entries: u32,
    resets_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    let waiting = match blocked_entries {
        0 => "Approved traces are waiting".to_string(),
        1 => "1 approved trace is waiting".to_string(),
        n => format!("{n} approved traces are waiting"),
    };
    match resets_at {
        Some(t) => format!(
            "Today's upload limit is used up. {waiting}. Nothing has been lost -- they go out \
             when the limit resets at {}.",
            t.with_timezone(&chrono::Local).format("%H:%M")
        ),
        None => format!(
            "Today's upload limit is used up. {waiting}. Nothing has been lost -- they go out \
             when the limit resets."
        ),
    }
}

/// Whether a health label deserves an action button, and what it says.
pub fn health_action(label: &str) -> Option<&'static str> {
    match label {
        "not-logged-in" => Some("Reconnect"),
        "near-ai-notice-not-acknowledged" => Some("Review and confirm"),
        _ => None,
    }
}

/// Plain-language renderings of `reason_label`, for entries that are on the
/// queue but are not decisions owed.
pub fn reason_sentence(label: &str) -> &'static str {
    trace_commons_contributor::private_inference_copy::queue_outcome_line(label)
}

// --- Updating ------------------------------------------------------------
//
// The one platform this app is forbidden to update itself on, so a flatpak
// portal does the work and this window only ever narrates it -- see
// `update.rs`. Nothing below names the portal, D-Bus, or a monitor; every
// sentence says what happens to the machine and the queue instead.

/// The offer, with the commit a person is being moved to.
///
/// The commit is named because "an update is available" with nothing else
/// is unfalsifiable -- there is no way for a contributor to check they got
/// what they were shown. Twelve characters of an ostree commit is enough to
/// compare against `flatpak info ai.tracecommons.Contributor` and short
/// enough to read.
pub fn update_offer_line(short_commit: &str) -> String {
    format!(
        concat!(
            "A newer ",
            app_name!(),
            " is available ({}). Installing it replaces this app; your queue and everything \
             already waiting in it are untouched."
        ),
        short_commit
    )
}

/// The banner's button while an update is merely offered.
pub const UPDATE_AVAILABLE_ACTION: &str = "Install";

/// Kept as a constant so the banner body and the dialog body cannot drift
/// apart, since the dialog is the second time a person reads the same fact.
pub const UPDATE_AVAILABLE_BODY: &str = concat!("A newer ", app_name!(), " is available.");

/// The confirmation, which is where the actual decision is made.
pub const UPDATE_CONFIRM_HEADING: &str = "Install the newer version?";
pub const UPDATE_CONFIRM_BODY: &str = "Flatpak installs it. This app does not change while it is open -- you keep running this \
     version until you quit and reopen. Nothing in your queue is sent, removed or re-scanned.";
pub const UPDATE_CONFIRM_ACCEPT: &str = "Install";
pub const UPDATE_CONFIRM_CANCEL: &str = "Not now";

/// Progress. One sentence, because a progress bar carries the rest.
pub fn update_installing_line(percent: u32) -> String {
    format!("Installing the update -- {percent}% done. You can keep using this window.")
}

/// Installed but not yet running.
pub const UPDATE_READY_BODY: &str = concat!(
    "The update is installed. Quit and reopen ",
    app_name!(),
    " to start using it. Your queue stays exactly where it is."
);
pub const UPDATE_READY_ACTION: &str = "Quit now";

/// Refused or failed. States the data consequence, names no mechanism, and
/// does not ask anyone to retry -- the portal re-checks on its own.
pub const UPDATE_FAILED_BODY: &str = "The update did not install. This copy is unchanged and nothing in your queue was affected. \
     It will be offered again.";

/// Built from source, so nothing here manages it. Honest about the fact
/// that this app is not checking anything in that case -- there is no
/// version check pending, only one that will never happen on this build.
pub const UPDATE_UNMANAGED_BODY: &str = "This copy was built from source, so updates are not managed here and nothing is being \
     checked. Rebuild from the repository to move to a newer version.";

/// Under flatpak, but nothing answered.
pub const UPDATE_UNAVAILABLE_BODY: &str = "Updates cannot be offered here: this desktop's Flatpak service did not answer. Use your \
     software centre, or run flatpak update, to move to a newer version.";

// --- Onboarding --------------------------------------------------------
//
// Six screens, one decision each. Every string below is verbatim from
// `docs/superpowers/specs/2026-08-08-contributor-shell-shared-design.md`,
// "## Onboarding" -- that document specifies the copy for every shell, so
// this is transcription, not authorship. If a sentence here reads oddly,
// change it there first.

pub const ONBOARD_WELCOME_TITLE: &str = APP_NAME;
pub const ONBOARD_WELCOME_BODY_1: &str = concat!(
    "Coding agents get better when there are real transcripts to learn from. Almost all of \
     that data is locked inside companies. ",
    app_name!(),
    " is a shared pool that isn't."
);
/// The bold half of screen 1. Split from the paragraph around it because it
/// is the promise the whole product is judged against.
pub const ONBOARD_WELCOME_DECIDES: &str =
    "You decide what gets contributed. Nothing is sent unless you say so.";
pub const ONBOARD_WELCOME_BODY_2: &str = trace_commons_contributor::onboarding_copy::WELCOME_BODY;
/// "Good and it is not perfect" is load-bearing: a developer knows automatic
/// redaction is imperfect, and conceding it first is what makes the rest
/// credible. Do not soften it into "thorough" or drop the second clause.
pub const ONBOARD_WELCOME_SCRUB: &str = "Before anything leaves this machine it is scrubbed locally for secrets, keys, and tokens. \
     That scrubbing is good and it is not perfect — which is why you get to look first.";
pub const ONBOARD_GET_STARTED: &str = "Get started";

/// The second button the shared spec gives screen 1 and the shell never had.
pub const ONBOARD_WHAT_REMOVED: &str = "What gets removed?";
pub const ONBOARD_WHAT_REMOVED_HEADING: &str = "What gets removed";
/// The list is generated from `trace_commons_protocol::secret_leak_pattern_names`,
/// so this sentence introduces it without claiming to enumerate it.
pub const ONBOARD_WHAT_REMOVED_INTRO: &str =
    "Before a trace leaves this machine, these are found and replaced:";

/// A named detector, in words. `slug` is a name from the protocol's table.
///
/// The LIST is generated; only the prettification is a lookup, and an
/// unrecognised slug still renders -- de-slugged rather than dropped -- so a
/// detector added upstream can never silently vanish from a screen that tells
/// a contributor what is scrubbed. `every_detector_has_a_human_label` fails
/// the build if one arrives without a label, so the fallback is a safety net
/// and not the plan.
pub fn scrub_detector_label(slug: &str) -> String {
    match slug {
        "openai_api_key" => "OpenAI API keys".to_string(),
        "github_token" => "GitHub tokens".to_string(),
        "aws_access_key" => "AWS access keys".to_string(),
        // The regex behind this one covers Stripe, GitLab and Slack prefixes.
        // Naming them beats "provider tokens", which tells a contributor
        // nothing about whether their own provider is covered.
        "provider_token" => "Stripe, GitLab and Slack tokens".to_string(),
        // Named separately from `provider_token` for the same reason that
        // entry names its providers: a Cursor user reading this list has to
        // be able to see their own key in it.
        "cursor_api_key" => "Cursor API keys".to_string(),
        "jwt" => "JSON Web Tokens".to_string(),
        "npm_token" => "npm tokens".to_string(),
        "google_api_key" => "Google API keys".to_string(),
        "pem_header_orphan" => "Private keys in PEM blocks".to_string(),
        other => other.replace('_', " "),
    }
}

pub const ONBOARD_CONNECT_TITLE: &str = "Connect";
pub const ONBOARD_CONNECT_PROMPT: &str =
    "Paste the invite link someone sent you, or click it from your email.";
pub const ONBOARD_CONNECT_PLACEHOLDER: &str = "https://…/onboard#…";
pub const ONBOARD_CONNECT_BUTTON: &str = "Connect";
/// One sentence for the entire invite path -- an invite this app cannot
/// parse and one the daemon refused both land here.
///
/// `enroll` answers `enroll-failed` and never echoes the underlying HTTP
/// condition (see "### `enroll`" in `docs/contributor-daemon-ipc-v1_1.md`),
/// so showing anything more specific would either invent detail the daemon
/// withheld or leak the detail it deliberately withheld.
pub const ONBOARD_CONNECT_FAILED: &str =
    "This invite link is no longer valid. Ask whoever sent it for a new one.";

pub const ONBOARD_CONSENT_TITLE: &str = "How may your traces be used?";
pub const ONBOARD_CONSENT_SUBTITLE: &str =
    "You can change this later. It applies to traces you send from now on.";
pub const ONBOARD_CONSENT_ALWAYS: &str = "Always included";
pub const ONBOARD_CONSENT_OPTIONAL: &str = "Optional — each one lets your traces do more";
pub const ONBOARD_CONSENT_CREDIT: &str = "Credit";
pub const ONBOARD_ALWAYS_ON_TAG: &str = "always on";

pub const ONBOARD_SCAN_TITLE: &str = "Extra scrub before sending? (optional)";
pub const ONBOARD_SCAN_LOCAL_ALWAYS: &str = "Local scrubbing removes secrets, keys, tokens and credentials by pattern before anything \
     leaves this machine. It runs either way.";
pub const ONBOARD_SCAN_OFFER: &str = "You can additionally send the message text of each trace — not tool output, not file \
     contents — through a second scanner run by NEAR AI, a third party, to catch personal \
     information the patterns miss: names, addresses, that kind of thing.";
/// Both halves of the disclosure. The cost (text really does leave the
/// machine to a third party) and the reassurance (an unreachable scanner
/// holds traces rather than sending them unscanned). Cutting either half
/// makes the screen dishonest in one direction, so they live in one string.
pub const ONBOARD_SCAN_DISCLOSURE: &str = concat!(
    "This means your message text is transmitted to NEAR AI before it reaches ",
    app_name!(),
    ". If that scanner is unreachable, nothing is sent at all — traces wait rather than \
     going out unscanned."
);
pub const ONBOARD_SCAN_LOCAL_ONLY: &str = "Local scrubbing only";
pub const ONBOARD_SCAN_WITH_NEAR: &str = "Local scrubbing + NEAR AI scan";

pub const ONBOARD_WATCH_TITLE: &str = "What to watch";

// ---------------------------------------------------------------------------
// NOT YET IN THE SHARED SPEC. The five strings below are new product copy, not
// transcription: `### 5. What to watch` specifies the screen's BEHAVIOUR (all
// projects at ask-first, `Ignore` offered and `auto_upload` withheld) and
// gives it no words at all. The screen therefore shipped as a bare title over
// an unlabelled list, which says neither what the list is nor what `Ignore`
// does -- on the one screen that decides which of a contributor's repositories
// are eligible to leave the machine.
//
// They must land in `docs/superpowers/specs/2026-08-08-contributor-shell-shared-design.md`
// before macOS and Windows transcribe them, or the three shells will describe
// the same decision differently. Flagged for approval rather than quietly
// adopted.
// ---------------------------------------------------------------------------

/// The subtitle screen 5 never had. States the default first, because the
/// default is what happens to a contributor who reads nothing and clicks
/// Continue -- which is most of them.
pub const ONBOARD_WATCH_SUBTITLE: &str = "Every project starts at ask-first: you see each session before anything is sent. Ignore a \
     project to leave it out entirely.";

/// The eyebrow over the list. `style::section` uppercases it.
pub const ONBOARD_WATCH_SECTION: &str = "Projects";

/// The per-row state, in the vocabulary `settings.rs` already uses for the
/// same mode -- its dropdown reads "Ask me first". Two screens that set the
/// same field must not name it two ways.
pub const ONBOARD_WATCH_ASK_FIRST: &str = "Ask me first";

/// The state after `Ignore`. Echoes the button that produced it rather than
/// introducing a third name for the mode.
pub const ONBOARD_WATCH_IGNORED: &str = "Ignored";

/// Shown when `list_projects` returns nothing. This was the state of the
/// screen on EVERY machine until the `local_path` deserialisation bug was
/// fixed, and it rendered as a title above nothing at all.
pub const ONBOARD_WATCH_EMPTY: &str =
    "No projects yet. Sessions you run later will appear here, and in Settings.";

/// The human name for `policy::UNKNOWN_PROJECT_KEY`. The wire carries the
/// slug `unknown-project` as this row's `project_label`, because
/// `project_label_for` deliberately returns the constant rather than risk
/// deriving a name from a path. A slug is the right answer on the socket and
/// the wrong one on a screen.
pub const ONBOARD_WATCH_UNKNOWN_LABEL: &str = "Sessions with no project";

/// The note the shared spec asks for: "sessions with no resolvable project
/// get a permanent plain-English note that they can never be armed."
///
/// Stated as a consequence rather than a fault. The daemon buckets these
/// because a cwd with no usable final segment has no label but itself, and
/// `project_label` reaches `daemon-audit.jsonl`, OS notification text and
/// `HistoryRecord` -- so naming them would have written a full local path
/// into all three. Not being armable is the protective half of that, not a
/// degradation, and the wording should not read as an error a contributor
/// might try to fix.
///
/// It replaces the state line rather than adding a third: "you'll always be
/// asked" already says what `Ask me first` says.
pub const ONBOARD_WATCH_UNKNOWN_NOTE: &str = concat!(
    app_name!(),
    " can't tell which folder these ran in, so they can never be contributed automatically. \
     You'll always be asked."
);

/// The per-project control on screen 5. `Ignore` is offered here and
/// `auto_upload` is not, per the shared spec: excluding a repository is a
/// live thought at this moment and never returns, whereas arming automation
/// before a single preview has been seen asks for trust not yet earned.
pub const ONBOARD_IGNORE: &str = "Ignore";

/// Shown when `set_project_mode` refuses. The same sentence the settings
/// screen uses for the same refusal, so the two places that change a
/// project's mode cannot describe the same failure differently.
pub const PROJECT_MODE_FAILED: &str =
    "That couldn't be changed just now. Nothing else changed either.";
pub const ONBOARD_CONTINUE: &str = "Continue";

pub const ONBOARD_DONE_TITLE: &str = "You're set up. Nothing has been sent.";
pub const ONBOARD_DONE_BODY: &str = trace_commons_contributor::onboarding_copy::DONE_BODY;
pub const ONBOARD_DONE_BUTTON: &str = "Finish";

// The roots screen. It runs BEFORE the daemon starts, so it is not one of
// the six onboarding screens above -- those are all daemon-backed, which is
// exactly why the roots refusal used to be a dead end.

pub const ROOTS_TITLE: &str = "Which folders may this app watch?";
pub const ROOTS_BODY: &str = concat!(
    app_name!(),
    " reads coding-session transcripts. It will not guess where they are, and it will not \
     watch anything until you say so."
);
/// Says the consequence, per the copy rules. Without this sentence "skip it"
/// reads as safe, and it is the opposite of safe: an unanswered source is
/// the one that falls back to the real location.
///
/// Says "each" rather than naming how many rows there are: the screen has
/// grown as adapters were added, and a count here would need updating every
/// time another one is.
pub const ROOTS_BOTH: &str = "Answer for each. Leaving one blank is not the same as skipping it -- an unanswered folder \
     falls back to the standard location, which is probably your real work.";
pub const ROOTS_CLAUDE: &str = "Claude Code sessions";
pub const ROOTS_CODEX: &str = "Codex sessions";
pub const ROOTS_GEMINI: &str = "Gemini CLI sessions";
pub const ROOTS_CLINE: &str = "Cline sessions";
/// Shown when a store arrives that this build has no name for -- a newer
/// contributor library discovering a source this shell predates. Deliberately
/// not one of the named titles: a row must never claim to be a product it is
/// not, and the path beside it still says exactly what would be read.
pub const ROOTS_UNKNOWN_SOURCE: &str = "Other agent sessions";
pub const ROOTS_WATCH: &str = "Watch this folder";
pub const ROOTS_OFF: &str = "I don't use this";
pub const ROOTS_CHOOSE: &str = "Choose a different folder...";
pub const ROOTS_CONTINUE: &str = "Continue";
pub const ROOTS_FAILED: &str = "That couldn't be saved just now. Nothing is being watched.";
/// Shown against a path that is not on this machine. Not an error: naming a
/// folder that does not exist yet is allowed, and saying so is more use than
/// refusing it.
pub const ROOTS_ABSENT: &str = "Not on this machine";
pub const ROOTS_EMPTY: &str = "No sessions yet";
/// Said when an environment variable moved the store, so a path that is not
/// the usual one does not read as a mistake.
pub const ROOTS_RELOCATED: &str = "Set by an environment variable";

/// The evidence line under a discovered folder.
///
/// A count and a recency, because that is what makes this a consent prompt
/// rather than a text field: "946 sessions, most recent 2 hours ago" tells a
/// contributor what they are agreeing to.
pub fn roots_evidence(session_count: u64, recent: Option<&str>) -> String {
    let sessions = if session_count == 1 {
        "1 session".to_string()
    } else {
        format!("{session_count} sessions")
    };
    match recent {
        Some(when) => format!("{sessions}, most recent {when}"),
        None => sessions,
    }
}

/// A coarse "how long ago", in the vocabulary the rest of the app uses.
pub fn roots_ago(seconds: i64) -> String {
    match seconds {
        s if s < 90 => "just now".to_string(),
        s if s < 5400 => format!("{} minutes ago", (s + 30) / 60),
        s if s < 172_800 => format!("{} hours ago", (s + 1800) / 3600),
        s => format!("{} days ago", (s + 43200) / 86400),
    }
}

/// The short bold label for a consent scope.
///
/// `consent_options` carries the wire name and the description but no
/// human title, so every shell maps them. The fallback matters as much as
/// the table: an operator who adds a scope this build has never heard of
/// still gets a readable row rather than a blank one, and the description
/// beside it comes from the daemon regardless.
pub fn scope_title(wire_name: &str) -> String {
    match wire_name {
        "debugging_evaluation" => "Finding bugs and measuring agents".to_string(),
        "benchmark_only" | "benchmark_creation" => "Turn my traces into test cases".to_string(),
        "ranking_training" | "reward_model_training" => {
            "Train models that judge agent output".to_string()
        }
        "model_training" => "Train coding models directly".to_string(),
        "public_attribution" => "List my handle publicly as a contributor".to_string(),
        other => other.replace('_', " "),
    }
}

// --- The submit toast --------------------------------------------------
//
// One-click submit sends without a preview, so this sentence is the only
// account a contributor gets of what happened. It is specified rather than
// suggested, in
// `docs/superpowers/specs/2026-08-20-one-click-submit-design.md` under "The
// toast: normative copy", and transcribed here: the macOS shell holds the
// identical strings in `macos/Sources/TCShellCore/SubmitToast.swift` and the
// Windows shell in `windows/src/TraceCommons.Interop/SubmitToast.cs`. All
// three assert the spec's four worked examples, because a sentence reworded
// in one client is precisely the drift that section exists to prevent.
//
// The vocabulary is `residual_risk_line`'s on purpose: the toast is the same
// fact said in fewer words, not a second way of saying it.
//
// `crate::toast` assembles these into the finished line.

/// Clause 1: what happened.
///
/// Corrected 2026-08-20: this used to say "Sent", and that was false. At
/// toast time nothing has left the machine -- the approval is recorded and
/// the watcher sends it on its next sweep (`copy.rs:192`). A toast reading
/// "Sent." while still offering Undo contradicted itself.
pub fn submit_approved_clause(approved: u64) -> String {
    match approved {
        0 => "Nothing approved.".to_string(),
        1 => "Approved.".to_string(),
        n => format!("Approved {n}."),
    }
}

/// Clause 2: what scrubbing did.
///
/// Always present, including when it did nothing. A count of zero is a fact
/// the contributor is owed, not an absence to omit -- and it is the case
/// worth weighing, which is why it is never silently dropped.
///
/// The count is the sum of the response's `redactions` map. Categories are
/// deliberately not named here; the preview sheet is where a contributor
/// sees which detector fired.
pub fn submit_scrub_clause(total_redactions: u64) -> String {
    match total_redactions {
        0 => "Scrubbing matched nothing.".to_string(),
        1 => "1 redaction applied.".to_string(),
        n => format!("{n} redactions applied."),
    }
}

/// The human label for each wire reason an entry can be skipped for, in the
/// spec table's order -- which is also the order they are listed in when
/// several apply.
///
/// The wire spellings are the daemon's and belong to the protocol; the
/// human halves belong to the contributor. Nothing here ever shows the
/// left-hand column, and nothing here shows an entry id: an id in a toast
/// is noise a contributor cannot act on.
pub const SUBMIT_SKIP_REASONS: [(&str, &str); 7] = [
    ("not-enrolled", "not connected to a commons"),
    ("not-pending", "already decided"),
    ("not-pinned", "could not be prepared"),
    ("envelope-too-large", "too large to send"),
    ("session-file-vanished", "the session file is gone"),
    ("preview-failed", "could not be read"),
    // Listed so a toast can never render this one as "could not be
    // prepared", which would be a false account of a refusal the
    // contributor caused and can fix. The sheet says the rest -- see
    // `CORRECTION_CREDENTIAL_HEADLINE` -- and this is what any other
    // surface reporting the same batch says.
    (
        "correction-credential-detected",
        "your correction contains a credential",
    ),
];

/// What an unrecognised wire label is called instead of itself.
///
/// Corrected 2026-08-20: this used to read "could not be sent"; that word
/// belonged to the old, now-false "Sent" clause 1. Fixed to "could not be
/// prepared", which happens to coincide with `not-pinned`'s own label --
/// both are, honestly, the least specific true statement available.
///
/// The spec's table is closed today, but a daemon newer than the shell can
/// send a label this build has never been taught, and the one thing that
/// must not then happen is the shell echoing protocol vocabulary at a
/// contributor. So an unknown label degrades to the least specific true
/// statement available, and is listed last.
pub const SUBMIT_SKIP_REASON_UNKNOWN: &str = "could not be prepared";

/// Translate one wire reason label. Never returns its argument.
pub fn submit_skip_reason_label(wire: &str) -> &'static str {
    SUBMIT_SKIP_REASONS
        .iter()
        .find(|(label, _)| *label == wire)
        .map(|(_, human)| *human)
        .unwrap_or(SUBMIT_SKIP_REASON_UNKNOWN)
}

/// Clauses 3 and 4: what was flagged, and what was not approved.
///
/// Corrected 2026-08-20: these used to be two independent clauses. The
/// spec now joins them into one, comma-separated, with each half present
/// only when non-zero -- `None` when both are zero, i.e. the whole clause
/// is absent.
///
/// The skip count is entries; the reason list is distinct reasons. Those
/// are different numbers whenever several entries were skipped for the same
/// reason, and the sentence says both because a contributor needs the first
/// to know how much is still queued and the second to know what to do about
/// it.
///
/// `SUBMIT_SKIP_REASON_UNKNOWN` now happens to share text with one of the
/// table's own labels (`not-pinned`), so the reason list is deduplicated by
/// its rendered text rather than assembled positionally -- otherwise a
/// batch mixing `not-pinned` and an unrecognised label would print "could
/// not be prepared" twice.
pub fn submit_flagged_and_skipped_clause(flagged: u64, skipped: &[&str]) -> Option<String> {
    let flagged_half = (flagged > 0).then(|| format!("{flagged} flagged"));

    let skipped_half = if skipped.is_empty() {
        None
    } else {
        let mut reasons: Vec<&'static str> = Vec::new();
        for (_, human) in SUBMIT_SKIP_REASONS {
            if !reasons.contains(&human)
                && skipped.iter().any(|w| submit_skip_reason_label(w) == human)
            {
                reasons.push(human);
            }
        }
        if !reasons.contains(&SUBMIT_SKIP_REASON_UNKNOWN)
            && skipped
                .iter()
                .any(|w| submit_skip_reason_label(w) == SUBMIT_SKIP_REASON_UNKNOWN)
        {
            reasons.push(SUBMIT_SKIP_REASON_UNKNOWN);
        }
        Some(format!(
            "{} not approved: {}",
            skipped.len(),
            reasons.join(", ")
        ))
    };

    match (flagged_half, skipped_half) {
        (None, None) => None,
        (Some(f), None) => Some(format!("{f}.")),
        (None, Some(s)) => Some(format!("{s}.")),
        (Some(f), Some(s)) => Some(format!("{f}, {s}.")),
    }
}

#[cfg(test)]
mod daily_cap_tests {
    use super::*;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// The reset instant rendered the way the banner renders it, so the
    /// assertions below do not depend on the machine's timezone.
    fn local_hhmm(t: chrono::DateTime<chrono::Utc>) -> String {
        t.with_timezone(&chrono::Local).format("%H:%M").to_string()
    }

    #[test]
    fn the_sentence_states_how_many_are_waiting_and_when_the_limit_resets() {
        let resets = at("2026-08-22T00:00:00Z");
        let text = daily_cap_sentence(14, Some(resets));
        assert_eq!(
            text,
            format!(
                "Today's upload limit is used up. 14 approved traces are waiting. Nothing has \
                 been lost -- they go out when the limit resets at {}.",
                local_hhmm(resets)
            )
        );
    }

    #[test]
    fn one_waiting_trace_is_not_described_in_the_plural() {
        let text = daily_cap_sentence(1, Some(at("2026-08-22T00:00:00Z")));
        assert!(text.contains("1 approved trace is waiting"), "{text}");
        assert!(!text.contains("traces are waiting"), "{text}");
    }

    #[test]
    fn with_no_reset_time_the_sentence_stops_rather_than_guessing() {
        // Never "tomorrow": the daemon has not said when, so neither do we.
        let text = daily_cap_sentence(3, None);
        assert_eq!(
            text,
            "Today's upload limit is used up. 3 approved traces are waiting. Nothing has been \
             lost -- they go out when the limit resets."
        );
        assert!(!text.contains("tomorrow"), "{text}");
    }

    #[test]
    fn the_sentence_never_reads_as_a_failure() {
        for text in [
            daily_cap_sentence(14, Some(at("2026-08-22T00:00:00Z"))),
            daily_cap_sentence(0, None),
            health_sentence("daily-cap-reached").to_string(),
        ] {
            let lower = text.to_lowercase();
            for word in ["error", "failed", "problem", "wrong"] {
                assert!(!lower.contains(word), "{word} in: {text}");
            }
            assert!(lower.contains("nothing has been lost"), "{text}");
        }
    }

    #[test]
    fn the_fallback_line_promises_no_particular_time() {
        // Used only when a daemon reports the label without the budget
        // object, and it must not invent what the object would have said.
        let text = health_sentence("daily-cap-reached");
        assert!(!text.contains("tomorrow"), "{text}");
        assert!(text.contains("resets"), "{text}");
    }
}

// --- Tools -------------------------------------------------------------
//
// One tool, one word.
//
// The words themselves are NOT here. They live in
// `trace_commons_contributor::routing_copy`, because the macOS and Windows
// shells render this same surface and reach them across the C ABI. A word
// kept in three places is three words that have not diverged yet, so this
// shell re-exports the one definition rather than holding a second.
//
// The forbidden-word sweep moved with them. It reads that module's source
// between its own `TOOLS-SURFACE-BEGIN` / `TOOLS-SURFACE-END` markers; a
// sweep left behind here would have walked a region with no strings in it
// and passed while covering nothing, which is the exact failure it was
// written to replace.
pub use trace_commons_contributor::routing_copy::{
    IRONWIRE_APPLIES_AT_ONCE, IRONWIRE_APPLY, IRONWIRE_CHECK_UNAVAILABLE, IRONWIRE_CHECKING,
    IRONWIRE_CONNECT, IRONWIRE_DERIVED_ORIGIN, IRONWIRE_FOLDER_NOTE, IRONWIRE_FOLDER_TITLE,
    IRONWIRE_INTRO, IRONWIRE_LOOK_AGAIN, IRONWIRE_OVERRIDE_TITLE, IRONWIRE_PORT_NOTE,
    IRONWIRE_PORT_TITLE, IRONWIRE_PROBE_REACHABLE, IRONWIRE_STATE_OFF, IRONWIRE_STATE_READING,
    IRONWIRE_STATE_TOKEN_UNREADABLE, IRONWIRE_STATE_WAITING, IRONWIRE_TOGGLE, StateTone,
    TOOL_CLAUDE, TOOL_CLINE, TOOL_CODEX, TOOL_DIRECT, TOOL_GEMINI, TOOL_NOT_USED, TOOL_PRIVATE,
    TOOL_UNKNOWN, TOOLS_HEADING, ToolTone, ToolWiring, ironwire_discovery_line,
    ironwire_folder_note_here, ironwire_shows_last_checked, ironwire_state_line,
    ironwire_state_tone, ironwire_token_line, ironwire_unreachable_line, tool_tone, tool_word,
};

// --- Model calls on this computer --------------------------------------
//
// The words are NOT here, for the reason stated above the Tools block: the
// macOS and Windows shells render this same offer and reach these sentences
// across the C ABI, so all three read one definition. The forbidden-word
// sweep lives with them, between that module's own
// `PRIVATE-INFERENCE-SURFACE-BEGIN` marker and its closing twin.
//
// `state_line` and `state_tone` are re-exported as a pair and must be used
// as one: a shell that recovered the tone by reading the sentence would be
// matching on text, and two refusal sentences begin with the same two
// words.
// The tools on this computer are part of the same surface and read from the
// same module. Nothing about a tool is spelled here -- not its name, which
// is IronWire's and arrives at runtime, and not its state, whose sentence
// and tone the view reads as a pair for the reason stated above.
//
// `harness_last_call_line` is assembled on the shared side rather than
// exported as a template with a hole in it, the same rule `serving_line`
// follows: a shell handed a pattern is a fourth place the wording drifts.
//
// `harness_spend_line` is assembled there for that reason and for a sharper
// one: it decides what an amount NOBODY COULD MEASURE looks like. A shell
// formatting its own dollars has to make that decision itself, and the
// answer it reaches for is zero -- which would tell a contributor with no
// readable figure that they had spent nothing today. `HARNESSES_SPEND_SCOPE`
// IS re-exported, because it is a fixed sentence and not a branch: it says
// what the amount leaves out, and it is drawn beside the amount and only
// when the amount is drawn.
pub use trace_commons_contributor::private_inference_copy::{
    DESTINATION as PRIVATE_INFERENCE_DESTINATION, OFFER_ACCEPT as PRIVATE_INFERENCE_OFFER_ACCEPT,
    OFFER_ASKED_ONCE as PRIVATE_INFERENCE_OFFER_ASKED_ONCE,
    OFFER_DECLINE as PRIVATE_INFERENCE_OFFER_DECLINE,
    OFFER_EXPOSURE as PRIVATE_INFERENCE_OFFER_EXPOSURE,
    OFFER_NO_REPOINT as PRIVATE_INFERENCE_OFFER_NO_REPOINT,
    OFFER_TITLE as PRIVATE_INFERENCE_OFFER_TITLE, OFFER_WHAT as PRIVATE_INFERENCE_OFFER_WHAT,
    PrivateInferenceTone, SETTINGS_APPLIES_AT_ONCE as PRIVATE_INFERENCE_APPLIES_AT_ONCE,
    SETTINGS_MOVED as PRIVATE_INFERENCE_SETTINGS_MOVED, SETTINGS_TITLE as PRIVATE_INFERENCE_TITLE,
    SETTINGS_TOGGLE as PRIVATE_INFERENCE_TOGGLE, STATE_OFF as PRIVATE_INFERENCE_STATE_OFF,
    STATE_UNKNOWN as PRIVATE_INFERENCE_STATE_UNKNOWN, SUBTITLE as PRIVATE_INFERENCE_SUBTITLE,
    TRAY_OPEN_TO_TURN_ON as PRIVATE_INFERENCE_TRAY_OPEN_TO_TURN_ON,
    TRAY_TURN_OFF as PRIVATE_INFERENCE_TRAY_TURN_OFF,
    WRITE_UNCONFIRMED as PRIVATE_INFERENCE_WRITE_UNCONFIRMED,
    serving_line as private_inference_serving_line, should_offer as private_inference_should_offer,
    state_line as private_inference_state_line, state_tone as private_inference_state_tone,
    write_confirmed as private_inference_write_confirmed,
};
//
// The three per-state sentences are NOT re-exported one by one. Which of
// them a row shows is `harness_state_line`'s decision, and it is the same
// decision the macOS and Windows shells reach across the C ABI as
// `tc_harness_state_line`. This shell asks it too rather than matching on
// the state itself, so the three cannot answer differently.
//
// The per-outcome sentences are not re-exported one by one either, and for
// the same reason. `HARNESS_UNREADABLE_CONFIG` used to be, because it was
// the only outcome with a sentence anywhere and this shell held the one arm
// that picked it -- while the four other non-committable outcomes had none,
// so their preview opened with a title, a path, no changes and a way out.
// `harness_outcome_line` is that decision, and it is the same one the other
// two shells reach as `tc_harness_outcome_line`.
//
// `HARNESS_NOT_INSTALLED` is re-exported, because it is not one of those
// tables: it is what a row whose tool is not on this computer shows INSTEAD
// of any state sentence, and the condition is a boolean on the row.
pub use trace_commons_contributor::private_inference_copy::{
    HARNESS_CONNECT, HARNESS_DISCONNECT, HARNESS_NEEDS_RESTART, HARNESS_NOT_INSTALLED,
    HARNESS_PREVIEW_CANCEL, HARNESS_PREVIEW_CONFIRM, HARNESS_PREVIEW_TITLE, HARNESS_SLOT_TAKEN,
    HARNESSES_NONE_FOUND, HARNESSES_SPEND_SCOPE, HARNESSES_TITLE, HARNESSES_WHAT,
    harness_last_call_line, harness_outcome_line, harness_spend_line, harness_state_line,
};

// --- The key this computer answers with --------------------------------
//
// Same rule as the two blocks above, and one sharper reason: the control
// these words sit beside MINTS A KEY at a third party, so the sentence in
// front of it is the only thing a contributor reads before a browser opens.
// Three shells holding three versions of that sentence is three versions of
// what somebody was told they were agreeing to.
//
// The per-state sentences are NOT re-exported one by one, for the reason
// `harness_state_line` is not: which one a state shows is
// `credential_state_line`'s decision, `credential_state_tone` paints it, and
// `credential_action` says what may be offered beside it. The three take the
// same label and are used as one -- a shell that picked the button from the
// state itself would be the second place that table lives, and the arm it
// would get wrong is the unread one, where offering `Obtain` is how somebody
// ends up with a second key.
//
// `harness_credential_notice` is a function and not a constant because its
// input has THREE answers and only one of them draws anything: a daemon that
// does not gate connects at all reports nothing, and a shell that read the
// absent field as "no key here" would tell a contributor to sign in before
// connecting a tool they could connect right now.
pub use trace_commons_contributor::private_inference_copy::{
    CREDENTIAL_CANCEL, CREDENTIAL_COST, CREDENTIAL_FORGET, CREDENTIAL_FORGET_EXPLAINS,
    CREDENTIAL_OBTAIN, CREDENTIAL_TITLE, CREDENTIAL_WHAT, CredentialAction, credential_action,
    credential_state_line, credential_state_tone, harness_credential_notice,
};

// --- What is left in the account ---------------------------------------
//
// Same rule as the block above, and it shares that block's enum: the one
// control this row has ever needed is the sign-in row's own `Obtain`, on
// `no_session` and `session_expired` and nothing else. A second enum whose
// `Obtain` had to mean the same thing would be a second table to keep in
// agreement with the button that opens a browser.
//
// The per-state sentences are NOT re-exported one by one, for
// `credential_state_line`'s reason. `known` answers the EMPTY STRING, which
// is the one arm a shell is likely to read as a missing case and fill in:
// that state's row is figures, and a sentence above them announcing the read
// succeeded is this app narrating itself.
//
// THE FOUR AMOUNT FUNCTIONS ARE ASSEMBLED THERE AND NOT HERE, and this is
// the sharpest reason on this whole surface. The figures are SIGNED -- an
// overdrawn account is negative -- so absence cannot ride on an out-of-range
// integer, and each of the four folds it differently: a null remaining
// figure is the no-limit sentence, a null limit and a null spend are the
// empty string, and a real zero is "$0.00" in all three. A shell formatting
// its own dollars has to make those choices itself, and the one it reaches
// for is "$0.00" everywhere -- which would tell a contributor with an
// uncapped account that they are out of money.
//
// `BALANCE_WHAT` IS re-exported, because it is a fixed sentence and not a
// branch: it says the figures are the whole account rather than this
// computer, and it is drawn beside them.
pub use trace_commons_contributor::private_inference_copy::{
    BALANCE_TITLE, BALANCE_WHAT, balance_action, balance_limit_line, balance_observed_line,
    balance_remaining_line, balance_spent_line, balance_state_line, balance_state_tone,
};

// --- Whether a session can be contributed at all ------------------------
//
// Same rule as the block above, and the reason this surface exists at all:
// a queue row that offers `Submit` beside a session the server will refuse
// is an action the transport cannot perform, discovered on the press. Three
// shells each deciding which rows get that button is three chances to draw
// one in the wrong place.
//
// The four state sentences and the thirteen reason sentences are NOT
// re-exported one by one. Which sentence a row shows is
// `eligibility_state_line`'s decision, `eligibility_state_tone` paints it,
// `eligibility_control` says whether the send control may be drawn at all,
// and `eligibility_reason_line` adds the detail underneath. All four take
// the SAME label and are used as one, so the words, the colour and the
// button cannot disagree.
//
// The arm that matters is the unread one. A state this build has never
// heard of answers the `unknown` sentence and `ContributionControl::None`
// -- never an ineligibility sentence, which would tell a contributor their
// own finished work is unsendable on no evidence at all. The reason line
// answers the EMPTY STRING there instead, and this shell draws nothing for
// it: the state sentence has already said what is true, and a second
// sentence guessing at a reason nobody established is a detail invented on
// screen.
pub use trace_commons_contributor::private_inference_copy::{
    ContributionControl, eligibility_control, eligibility_reason_line, eligibility_state_line,
    eligibility_state_tone, group_control, group_withheld_line,
};

// --- Whether a session carries proof of its model call ------------------
//
// The block above answers "may I send this?", and says nothing at all when
// nobody is asking. This one answers a different question that every
// contributor has all of the time: does this session carry a checkable copy
// of the model call that produced it? That is a fact about the trace, not a
// permission, so it is stated on EVERY row -- an invited contributor's
// included.
//
// `attestation_state_line` picks the sentence, `attestation_state_tone`
// paints it, and `attestation_reason_line` adds the detail underneath. All
// three take the same label and are used as one.
//
// There is no control in this trio, and its absence is the design: the mark
// describes the trace and offers nothing to press. Sendability stays the
// eligibility question above.
//
// `attestation_reason_line` is NOT `eligibility_reason_line` and must never
// be substituted for it. The thirteen labels are shared, because each names
// one property of the recorded session; the sentences are not, because the
// eligibility ones say "cannot be sent", which is false for an invited
// contributor whose session sends perfectly well.
//
// An unread mark answers the `unknown` sentence and `Neutral` -- never an
// unattested mark, which would be evidence this build does not have.
pub use trace_commons_contributor::private_inference_copy::{
    attestation_reason_line, attestation_state_line, attestation_state_tone,
};

// --- The certificate-held list -----------------------------------------
//
// One fact with two readings: a contributor without an invite is told a
// session is a candidate for submission, one with an invite that it is
// cryptographically attested. The pick is `certificate_row_line`'s and
// `certificate_list_title`'s, never this shell's, for the reason the
// attestation trio above is shared -- three shells choosing for themselves
// is three chances to promise an attestation that has not happened.
//
// NOT the attestation trio. That answers whether the session carries a copy
// of its model call; this answers whether a certificate is held over the
// reviewed bytes. Same row, different question.
pub use trace_commons_contributor::private_inference_copy::{
    certificate_list_empty, certificate_list_title, certificate_row_line,
};

// --- Joining with a NEAR AI login ---------------------------------------
//
// The way in that needs no wallet. A contributor cannot produce an
// admissible receipt without a NEAR AI account in the first place, so
// requiring a wallet as well is a second onboarding for an identity they
// already hold. Both paths are offered here and neither is removed.
//
// `near_ai_enroll_line` picks the sentence and `near_ai_enroll_tone` paints
// it; both take the daemon's control name and are used as one. Ten refusals,
// each with its own words -- and the three that refuse before anything is
// spent must not be run together: not signed in, commons unreachable, and
// commons not offering this are three different things to do about it.
//
// An unknown label reaches the generic sentence and never the empty string.
// Unlike an attestation reason, silence here would leave a control that did
// nothing and said nothing.
pub use trace_commons_contributor::private_inference_copy::{
    near_ai_enroll_line, near_ai_enroll_tone,
};

// --- The redaction witness ---------------------------------------------
//
// Same rule as the Tools block above, for the same reason. The witness
// surface's words live in `trace_commons_contributor::witness_copy`,
// because macOS and Windows render this same card across the C ABI and a
// privacy claim kept in three places is three claims that have not diverged
// yet. This shell re-exports the one definition.
//
// Two of these are the whole point of the module: `witness_state_line` and
// `witness_state_tone` take the SAME input, so the sentence and the colour
// cannot drift apart, and there is no boolean anywhere in the pair. "Is a
// witness configured?" has two yes-answers that are opposites -- a pinned
// witness certifies every submission, an unpinned one refuses every
// submission before a single byte leaves -- and a shell that reduced them
// to one bit would paint a total outage as "on".
pub use trace_commons_contributor::witness_copy::{
    WITNESS_APPLIES_AT_ONCE, WITNESS_CERTIFICATE_MEANS, WITNESS_CLEAR, WITNESS_CLEAR_NOTE,
    WITNESS_CONFIGURE, WITNESS_HEADING, WITNESS_INFERENCE_CANCEL, WITNESS_INFERENCE_CAPTURE_NOTE,
    WITNESS_INFERENCE_CONFIRM, WITNESS_INFERENCE_DISABLE, WITNESS_INFERENCE_DISABLED,
    WITNESS_INFERENCE_DISCLOSURE, WITNESS_INFERENCE_ENABLE, WITNESS_INFERENCE_ENABLED,
    WITNESS_INFERENCE_HEADING, WITNESS_INFERENCE_SAVE_FAILED, WITNESS_INFERENCE_SCOPE_NOTE,
    WITNESS_INTRO, WITNESS_MEASUREMENTS_NOTE, WITNESS_MEASUREMENTS_TITLE,
    WITNESS_SIGNING_ADDRESS_TITLE, WITNESS_TOKEN_CANCEL, WITNESS_TOKEN_CAPTURE_NOTE,
    WITNESS_TOKEN_CONFIRM, WITNESS_TOKEN_DISABLE, WITNESS_TOKEN_DISABLED, WITNESS_TOKEN_DISCLOSURE,
    WITNESS_TOKEN_ENABLE, WITNESS_TOKEN_ENABLED, WITNESS_TOKEN_HEADING, WITNESS_TOKEN_SAVE_FAILED,
    WITNESS_TOKEN_SCOPE_NOTE, WITNESS_URL_TITLE, WitnessTone, witness_last_result_line,
    witness_last_result_tone, witness_pinned_count_line, witness_state_line, witness_state_tone,
};

/// When the daemon last got an answer, or nothing.
///
/// The sentence is [`trace_commons_contributor::routing_copy::last_checked_line`];
/// the only thing this shell adds is its own humanised time, which is a
/// rendering of a `DateTime` and not wording about routing.
#[must_use]
pub fn ironwire_last_checked(at: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    at.map(|at| {
        trace_commons_contributor::routing_copy::last_checked_line(&crate::model::human_when(Some(
            at,
        )))
    })
}

#[cfg(test)]
mod tests {
    /// A refused contribution must not read as one that never left.
    ///
    /// This shell's outcome default is "Nothing was sent.", which on the
    /// admission path is false: the envelope was transmitted and the gate
    /// declined it after receiving it. Every one of the five refusal labels
    /// reaches this surface verbatim from the server.
    ///
    /// **Keyed from `AdmissionRefusal::label()`, not from a literal typed
    /// here.** Those labels are underscored -- the server's spelling -- while
    /// `daemon::health`'s constants for the same events are hyphenated. A
    /// test written against the wrong one would pass while the shell
    /// reproduced the bug.
    #[test]
    fn a_refused_contribution_does_not_read_as_unsent() {
        use trace_commons_protocol::admission::AdmissionRefusal;

        for refusal in AdmissionRefusal::ALL {
            let line = super::reason_sentence(refusal.label());
            let lower = line.to_lowercase();
            assert!(
                !lower.contains("nothing was sent"),
                "{} tells a contributor their work never left: {line}",
                refusal.label()
            );
            assert_ne!(
                line,
                super::reason_sentence("a-label-this-shell-has-never-seen"),
                "{} fell through to the default arm",
                refusal.label()
            );
        }
    }

    /// The labels this shell already answered still reach their own
    /// sentences: the refusal lookup is additive, not a takeover.
    #[test]
    fn queue_outcomes_use_the_shared_copy_and_neutral_fallback() {
        assert_eq!(
            super::reason_sentence("dismissed-by-contributor"),
            "Skipped; not sent"
        );
        assert_eq!(
            super::reason_sentence("a-label-this-shell-has-never-seen"),
            "Status unavailable"
        );
    }

    #[test]
    fn unsupported_export_uses_shared_recovery_sentence() {
        assert_eq!(
            super::health_sentence("opencode-export-version-unsupported"),
            trace_commons_contributor::source_copy::OPENCODE_VERSION_DETAIL
        );
    }

    /// The caption names a token shape as an example, so that shape has to
    /// be one the scrubber can actually produce. Only `local_path` and
    /// `private_email` mint a numbered placeholder; a secret never does.
    #[test]
    fn the_transcript_caption_names_only_a_token_shape_that_can_exist() {
        assert!(TRANSCRIPT_CAPTION.contains("<PRIVATE_LOCAL_PATH_1>"));
        assert!(
            !TRANSCRIPT_CAPTION.contains("<PRIVATE_SECRET"),
            "secrets mint no numbered placeholder"
        );
    }

    /// Marking makes the app look more thorough than it is, so the caption
    /// beside the marks has to concede what a mark does not cover.
    #[test]
    fn the_transcript_caption_concedes_what_a_mark_does_not_mean() {
        assert!(
            TRANSCRIPT_CAPTION.contains("no mark is not"),
            "{TRANSCRIPT_CAPTION}"
        );
    }

    #[test]
    fn a_redaction_mark_names_what_left() {
        assert_eq!(redaction_mark_tooltip("local path"), "Removed: local path");
    }

    /// The repeat wording may only ever be said of a numbered placeholder,
    /// so it has to be distinguishable from the plain one.
    #[test]
    fn a_repeated_mark_says_it_is_the_same_value() {
        let repeat = redaction_mark_repeat("local path");
        assert_ne!(repeat, redaction_mark_tooltip("local path"));
        assert!(repeat.contains("the same value"), "{repeat}");
    }

    /// An unnamed mark must not acquire a category it never had.
    #[test]
    fn an_unnamed_mark_names_no_category() {
        assert_eq!(REDACTION_MARK_UNNAMED, "Removed");
        assert!(!REDACTION_MARK_UNNAMED.contains(':'));
    }

    #[test]
    fn a_history_folder_summary_inflects_its_count() {
        assert_eq!(history_folder_summary(1), "1 submission");
        assert_eq!(history_folder_summary(4), "4 submissions");
    }

    /// The zero case names a doubt. It has to name the thing to do about it
    /// too, and that thing is the search tab -- which the card's chip now
    /// opens.
    #[test]
    fn the_nothing_matched_line_offers_a_next_step() {
        assert!(
            residual_risk_line(0).to_lowercase().contains("search"),
            "the line must point at the thing to do about it"
        );
    }

    #[test]
    fn a_panel_row_omits_a_distinct_count_that_repeats_the_occurrence_count() {
        assert_eq!(redaction_row_counts(185, 12), "185 (12 distinct)");
        assert_eq!(redaction_row_counts(3, 3), "3");
        assert_eq!(redaction_row_counts(3, 0), "3");
    }

    /// The one direction this panel must not fail in is understating what
    /// happened, and a survivor's description is where that is decided.
    #[test]
    fn the_residual_description_never_claims_a_removal() {
        assert!(REDACTION_CATEGORY_RESIDUAL.contains("still in what would be sent"));
        assert!(
            !REDACTION_CATEGORY_RESIDUAL
                .to_lowercase()
                .contains("removed")
        );
    }

    #[test]
    fn a_folder_summary_inflects_its_session_count() {
        assert!(folder_summary(1, 1024).starts_with("1 session "));
        assert!(folder_summary(2, 1024).starts_with("2 sessions "));
    }

    #[test]
    fn a_folder_summary_carries_its_size() {
        assert!(
            folder_summary(2, 1024).ends_with("1 KB"),
            "{}",
            folder_summary(2, 1024)
        );
    }
    use super::*;

    use crate::model::human_bytes;

    /// The correction disclosure, character for character, and then in the
    /// other two shells' actual sources.
    ///
    /// Same mechanism as the consent statement above, and load-bearing for
    /// a stronger reason. The published policy page says redaction happens
    /// locally and is re-applied on the server; a correction is the one
    /// exception and the page does not yet say so. Until it does, this
    /// sentence is the whole of what a contributor is told, so a shell that
    /// shortens it for layout is shipping the exception undisclosed.
    ///
    /// TODO(shell-copy slice 2): this goes when `CorrectionCopy` moves into
    /// `correction_copy.rs`. It is the scaffold the migration spec wants
    /// gone, and it stays exactly as long as the transcriptions it guards do.
    #[test]
    fn the_correction_disclosure_is_intact_in_all_three_shells() {
        assert_eq!(
            CORRECTION_CAPTION,
            "Stored exactly as you write it. Unlike the rest of the trace, a correction is not scrubbed here or on the server -- so leave out anything you would not want in the corpus: someone else's personal information, employer-confidential material, or anything you are not free to share."
        );
        // The two halves that must never quietly drop out: what is
        // different about a correction, and what not to put in one.
        assert!(CORRECTION_CAPTION.contains("Stored exactly as you write it"));
        assert!(CORRECTION_CAPTION.contains("not scrubbed here or on the server"));
        assert!(CORRECTION_CAPTION.contains("personal information"));
        assert!(CORRECTION_CAPTION.contains("employer-confidential"));
        assert!(CORRECTION_CAPTION.contains("not free to share"));
        // The refusal says both things it has to: nothing was sent, and
        // the credential still has to be rotated because it has been typed.
        assert!(CORRECTION_CREDENTIAL_HEADLINE.starts_with("Nothing was sent."));
        assert!(CORRECTION_CREDENTIAL_BODY.contains("rotate it"));
        assert!(CORRECTION_CREDENTIAL_BODY.contains("already been typed"));

        for relative in [
            "../../macos/Sources/TCShellCore/CorrectionCopy.swift",
            "../../windows/src/TraceCommons.Interop/CorrectionCopy.cs",
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
            for needle in [
                CORRECTION_CAPTION,
                CORRECTION_QUESTION,
                CORRECTION_PLACEHOLDER,
                CORRECTION_CREDENTIAL_HEADLINE,
                CORRECTION_CREDENTIAL_BODY,
            ] {
                assert!(
                    source.contains(needle),
                    "{} does not print {needle:?} verbatim",
                    path.display()
                );
            }
        }
    }

    /// No XAML comment in the Windows shell may contain a double hyphen.
    ///
    /// XML forbids `--` inside a comment, and `XamlCompiler.exe` answers one
    /// by **exiting 1 with no diagnostic**: MSBuild reports only `MSB3073`
    /// naming the command line, and the compiler's own `output.json` carries
    /// no error entry at all. There is nothing to read, so the only way to
    /// find it is to bisect the markup on a Windows box.
    ///
    /// This slice cost exactly that, because the repo's prose style writes a
    /// spaced double hyphen everywhere and three of those went into XAML
    /// comments. Checked from the Rust side because these tests already read
    /// the Windows sources for the copy pins, and because this runs on every
    /// platform -- so the mistake fails on a contributor's Mac in
    /// milliseconds instead of on the one CI job that can compile XAML.
    #[test]
    fn no_windows_xaml_comment_contains_a_double_hyphen() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../windows/src");
        let mut checked = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", dir.display()));
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("xaml") {
                    continue;
                }
                checked += 1;
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
                let mut rest = source.as_str();
                while let Some(open) = rest.find("<!--") {
                    let after = &rest[open + 4..];
                    let Some(close) = after.find("-->") else {
                        break;
                    };
                    if after[..close].contains("--") {
                        offenders.push(path.display().to_string());
                    }
                    rest = &after[close + 3..];
                }
            }
        }
        assert!(checked > 0, "{} held no .xaml files", root.display());
        assert!(
            offenders.is_empty(),
            "XAML comments with a double hyphen (XamlCompiler exits 1 silently \
             on these -- write a full stop or a semicolon instead): {offenders:?}"
        );
    }

    /// The wire label the shells match on is the one the daemon sends. Two
    /// spellings of it would make the refusal render as a generic skip.
    #[test]
    fn the_correction_refusal_label_is_the_daemons_own() {
        let (wire, _human) = SUBMIT_SKIP_REASONS
            .iter()
            .find(|(wire, _)| *wire == "correction-credential-detected")
            .expect("the correction refusal must be a known skip reason");
        assert_eq!(*wire, crate::model::CORRECTION_CREDENTIAL_REFUSAL);
        assert_ne!(
            submit_skip_reason_label(wire),
            SUBMIT_SKIP_REASON_UNKNOWN,
            "the refusal the contributor can fix must not degrade to \"could not be prepared\""
        );
    }

    #[test]
    fn too_large_caption_states_the_raw_size_and_never_a_would_send_figure() {
        // The 367.5 MB Codex outlier the preview-scheduler design is
        // grounded in: the caption has to name that number and must not
        // contain any other byte figure a reader could mistake for a
        // would-send estimate.
        let line = too_large_caption(385_305_395);
        assert!(
            line.contains(&human_bytes(385_305_395)),
            "caption must state the real raw size: {line}"
        );
        assert!(
            !line.contains("would send"),
            "the too-large caption must never claim a would-send figure: {line}"
        );
    }

    #[test]
    fn too_large_caption_changes_with_the_size_it_is_given() {
        // Not a constant string with a number spliced in by accident of one
        // test case -- two different sizes must produce two different
        // captions.
        assert_ne!(too_large_caption(1_000_000), too_large_caption(400_000_000));
    }

    #[test]
    fn the_evidence_line_counts_one_session_without_a_plural() {
        assert_eq!(roots_evidence(1, None), "1 session");
        assert_eq!(roots_evidence(0, None), "0 sessions");
        assert_eq!(roots_evidence(946, None), "946 sessions");
    }

    #[test]
    fn the_evidence_line_carries_the_recency_when_there_is_one() {
        assert_eq!(
            roots_evidence(946, Some("2 hours ago")),
            "946 sessions, most recent 2 hours ago"
        );
    }

    #[test]
    fn ago_reads_in_the_largest_unit_that_fits() {
        assert_eq!(roots_ago(5), "just now");
        assert_eq!(roots_ago(600), "10 minutes ago");
        assert_eq!(roots_ago(7200), "2 hours ago");
        assert_eq!(roots_ago(86_400 * 3), "3 days ago");
    }

    #[test]
    fn the_roots_copy_says_what_leaving_one_blank_actually_does() {
        // The rule is "always state the data consequence". A screen that
        // said only "answer both" would leave the contributor thinking a
        // blank means "skip that one", which is the fail-open this whole
        // slice removes.
        assert!(ROOTS_BOTH.contains("falls back"));
        assert!(ROOTS_BODY.contains("will not watch anything until you say"));
    }

    #[test]
    fn no_health_sentence_names_an_internal_mechanism() {
        // "privacy filter", "claim", "ingest" and "canary" are internal
        // words; the contributor-facing sentence must not use them even
        // though the labels themselves do.
        for label in [
            "not-logged-in",
            "pii-filter-unavailable",
            "privacy-filter-canary-failed",
            "near-ai-notice-not-acknowledged",
            "claim-mint-failed",
            "ingest-unreachable",
            "daily-cap-reached",
            "queue-full",
            "something-nobody-has-written-yet",
        ] {
            let sentence = health_sentence(label).to_lowercase();
            for forbidden in ["privacy filter", "canary self", "claim", "ingest", "pii"] {
                assert!(
                    !sentence.contains(forbidden),
                    "{label} names the mechanism: {sentence}"
                );
            }
        }
    }

    #[test]
    fn the_row_caveat_varies_and_still_concedes() {
        let none = residual_risk_line(0);
        let some = residual_risk_line(4);
        // The whole point: two different situations do not get the same
        // sentence. If these ever converge, the line is wallpaper again.
        assert_ne!(none, some);
        assert!(none.contains("matched nothing"));
        assert!(some.contains("4 things"));
        // And whatever it says, it concedes the limit. A row that reported
        // a count without the concession would be reassurance.
        for line in [&none, &some, &residual_risk_line(1)] {
            assert!(
                line.contains("seen before") || line.contains("patterns it has seen"),
                "the caveat must survive every count: {line}"
            );
        }
        // Singular and plural are both written out; "1 things" reads as a
        // bug, and it is one.
        assert!(residual_risk_line(1).contains("1 thing it"));
    }

    #[test]
    fn a_card_covering_nothing_delegated_says_nothing_at_all() {
        // Never a "0 dropped" row: a line that is always present is a line
        // nobody reads, and the one case that matters would be lost in it.
        assert_eq!(subagent_line(0, 0), None);
    }

    #[test]
    fn a_dropped_transcript_is_always_stated() {
        // The contract's one `must`. Every shape with a drop in it says so.
        for (kept, dropped) in [(0, 1), (0, 7), (3, 1), (42, 3)] {
            let line = subagent_line(kept, dropped).expect("a drop is never silent");
            assert!(
                line.contains(&dropped.to_string()) || (dropped == 1 && line.contains("largest")),
                "the count of what was left out has to appear: {line}"
            );
            // And it says what was NOT lost. The parent conversation is
            // never dropped, and a contributor reading this line is deciding
            // whether to send it.
            assert!(
                line.contains("the conversation itself is complete"),
                "a trimmed card must say what survived: {line}"
            );
            // Trimming is a size consequence, not a failure. No word here
            // may read as an error.
            for alarming in [
                "error",
                "failed",
                "corrupt",
                "incomplete",
                "lost",
                "missing",
            ] {
                assert!(
                    !line.to_lowercase().contains(alarming),
                    "{alarming} makes a normal trim read as a fault: {line}"
                );
            }
        }
    }

    #[test]
    fn the_extent_line_counts_in_words_a_person_can_read() {
        assert_eq!(
            subagent_line(1, 0).unwrap(),
            "Includes 1 delegated subagent transcript."
        );
        assert_eq!(
            subagent_line(42, 0).unwrap(),
            "Includes 42 delegated subagent transcripts."
        );
        // "The 1 largest" is a bug; one dropped transcript is "the largest".
        assert!(subagent_line(42, 1).unwrap().contains("The largest was"));
        assert!(subagent_line(42, 3).unwrap().contains("The 3 largest were"));
        // Everything dropped: there is no kept count to open with, so the
        // sentence starts from what was left out rather than claiming to
        // include nothing.
        assert!(
            subagent_line(0, 2)
                .unwrap()
                .starts_with("2 delegated subagent transcripts were left out")
        );
        assert!(
            subagent_line(0, 1)
                .unwrap()
                .starts_with("1 delegated subagent transcript was left out")
        );
    }

    #[test]
    fn credit_copy_carries_no_currency_projection_or_date() {
        for forbidden in ["$", "USD", "worth", "value of", "by 20", "payout of"] {
            assert!(
                !CREDIT_BODY.contains(forbidden),
                "credit copy must not imply a currency: {forbidden}"
            );
        }
    }

    /// The held queue is worked by an agent, not by a person reading traces.
    /// Saying otherwise invites a contributor to picture a staff member with
    /// their session open, which is both wrong and the more alarming reading
    /// of the two. Pinned because it is the kind of warm-sounding phrase that
    /// gets reintroduced by someone softening the copy.
    #[test]
    fn quarantine_copy_does_not_claim_a_human_reader() {
        let text = format!("{QUARANTINE_HEADING} {QUARANTINE_BODY} {HELD_ROW_BODY}").to_lowercase();
        for forbidden in [
            "a person at",
            "someone at",
            "our team",
            "a human",
            "staff",
            "the reviewer",
        ] {
            assert!(
                !text.contains(forbidden),
                "held copy must not imply a human reads these: {forbidden}"
            );
        }
        assert!(
            text.contains("agent"),
            "held copy must say what actually inspects a held trace"
        );
    }

    #[test]
    fn quarantine_copy_never_says_rejected_and_never_promises_a_wait() {
        let text = format!("{QUARANTINE_HEADING} {QUARANTINE_BODY}").to_lowercase();
        // The word appears exactly once, and only in the sentence denying
        // it. Any other use is the reading this copy exists to prevent.
        assert_eq!(text.matches("rejected").count(), 1);
        assert!(text.contains("have not been rejected"));
        for forbidden in [
            "48 hours",
            "business days",
            "within a week",
            "usually takes",
        ] {
            assert!(
                !text.contains(forbidden),
                "no turnaround time may be stated"
            );
        }
    }

    #[test]
    fn portal_status_matrix_says_only_what_is_true_in_each_cell() {
        use crate::portal::BackendState::{Absent, Present};

        let present_installed = portal_status_line(Present, true);
        let present_bare = portal_status_line(Present, false);
        let absent_installed = portal_status_line(Absent, true);
        let absent_bare = portal_status_line(Absent, false);

        // A backend that exists is always described as such, whether or
        // not systemd is doing the persisting.
        for line in [present_installed, present_bare] {
            assert!(line.contains(concat!("can list ", app_name!(), " as a background app")));
        }
        // A desktop with no backend never says it can -- that would be a
        // false claim, not just an optimistic one.
        for line in [absent_installed, absent_bare] {
            assert!(!line.contains(concat!("can list ", app_name!(), " as a background app")));
            assert!(line.contains("no background-app list"));
        }

        // The absent+installed cell is the one the spec calls out by name:
        // it must read as "nothing is wrong", not as a degraded product.
        assert!(absent_installed.to_lowercase().contains("nothing is wrong"));

        // Every cell where systemd *is* what's running the unit says so by
        // name, because that -- not the portal -- is what actually keeps
        // the process running.
        for line in [present_installed, absent_installed] {
            assert!(line.to_lowercase().contains("systemd"));
        }

        // The four conclusive cells are pairwise distinct: each one says
        // something only true in that cell.
        let conclusive = [
            present_installed,
            present_bare,
            absent_installed,
            absent_bare,
        ];
        for (i, a) in conclusive.iter().enumerate() {
            for b in &conclusive[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn update_copy_never_names_the_portal_or_dbus() {
        // Contributor-facing copy talks about the app, the queue and the
        // machine -- never the mechanism doing the work underneath.
        let all = [
            UPDATE_AVAILABLE_BODY,
            UPDATE_CONFIRM_HEADING,
            UPDATE_CONFIRM_BODY,
            UPDATE_READY_BODY,
            UPDATE_FAILED_BODY,
            UPDATE_UNMANAGED_BODY,
            UPDATE_UNAVAILABLE_BODY,
            &update_offer_line("beefbeefbeef"),
            &update_installing_line(50),
        ]
        .join(" ")
        .to_lowercase();
        for forbidden in ["d-bus", "dbus", "portal", "monitor", "commit", "ostree"] {
            assert!(
                !all.contains(forbidden),
                "update copy names {forbidden}: {all}"
            );
        }
    }

    #[test]
    fn an_unknown_probe_never_asserts_either_answer() {
        use crate::portal::BackendState::Unknown;

        for systemd_unit_installed in [true, false] {
            let line = portal_status_line(Unknown, systemd_unit_installed);
            assert!(!line.contains(concat!("can list ", app_name!(), " as a background app")));
            assert!(!line.contains("no background-app list"));
            assert!(line.to_lowercase().contains("couldn't tell"));
        }
    }

    // --- Withdrawal ------------------------------------------------------
    //
    // These are assertions on the copy, not on the plumbing. This block is
    // a second copy of wording whose canonical form lives in a document,
    // and an edit that shortens the cannot-be-recalled clause, or hands an
    // `accepted` trace only the gentler body, is exactly the change nobody
    // would notice in review.

    #[test]
    fn the_canonical_bodies_are_still_the_documents_own_words() {
        // Transcribed from the "Canonical confirmation copy" table in
        // `docs/contributor-daemon-ipc-v1_1.md`. Compared whole rather than
        // by keyword: a paraphrase that kept every keyword would still be a
        // paraphrase.
        assert_eq!(
            WITHDRAW_BODY_NOT_DISTRIBUTED,
            "This trace never entered the commons. Withdrawing deletes it. Nothing was \
             distributed and nothing needs recalling."
        );
        assert_eq!(
            WITHDRAW_BODY_COMMONS_NOT_DISTRIBUTED,
            "This trace is in the commons but has not been included in any published export or \
             benchmark yet. Withdrawing deletes it and excludes it from everything published \
             from here on."
        );
        assert_eq!(
            WITHDRAW_BODY_COMMONS_DISTRIBUTED,
            "This trace has already been included in a published export or benchmark. \
             Withdrawing deletes our copy and excludes it from everything published from here \
             on, but copies that have already been distributed cannot be recalled. Withdrawing \
             does not undo that."
        );
    }

    #[test]
    fn a_trace_already_in_the_commons_is_never_shown_only_the_gentler_tier() {
        // Rule 2. `accepted` may resolve to either commons tier and this
        // window cannot tell which, so showing only the gentler body would
        // be claiming more erasure than may have been achieved.
        let commons = withdraw_confirmation(WithdrawStage::InTheCommons);
        assert!(
            commons.bodies.contains(&WITHDRAW_BODY_COMMONS_DISTRIBUTED),
            "an accepted trace is not warned about distributed copies"
        );
        assert!(
            commons.ambiguity.is_some(),
            "an accepted trace is shown a tier this window cannot know"
        );
        assert_eq!(commons.gravest, Some(1));
        assert_eq!(commons.confirm_label, WITHDRAW_ANYWAY);
    }

    #[test]
    fn a_trace_that_never_entered_the_commons_is_not_told_it_was_excluded() {
        // The other half of rule 2: `submitted`/`quarantined` maps to
        // `not_distributed` exactly, so the gentlest body is shown alone
        // and no export it was never in is mentioned.
        let outside = withdraw_confirmation(WithdrawStage::NotInTheCommons);
        assert_eq!(outside.bodies, &[WITHDRAW_BODY_NOT_DISTRIBUTED]);
        assert_eq!(outside.gravest, None);
        assert_eq!(outside.confirm_label, WITHDRAW);
        assert_eq!(
            WithdrawStage::of_status("submitted"),
            WithdrawStage::NotInTheCommons
        );
        assert_eq!(
            WithdrawStage::of_status("quarantined"),
            WithdrawStage::NotInTheCommons
        );
        assert_eq!(
            WithdrawStage::of_status("accepted"),
            WithdrawStage::InTheCommons
        );
        assert_eq!(
            WithdrawStage::of_status("something-new"),
            WithdrawStage::Unknown
        );
    }

    #[test]
    fn an_unrecognised_stage_cannot_rule_out_the_furthest_reach() {
        let unknown = withdraw_confirmation(WithdrawStage::Unknown);
        assert_eq!(unknown.bodies, &[WITHDRAW_BODY_COMMONS_DISTRIBUTED]);
        assert_eq!(unknown.gravest, Some(0));
    }

    #[test]
    fn every_tier_states_the_same_verified_thing_about_credit() {
        // Rule 3. Credit already awarded stays awarded, and no tier says
        // anything else about it.
        for stage in [
            WithdrawStage::NotInTheCommons,
            WithdrawStage::InTheCommons,
            WithdrawStage::Unknown,
        ] {
            assert_eq!(withdraw_confirmation(stage).credit, WITHDRAW_CREDIT_NOTE);
        }
    }

    #[test]
    fn no_outcome_is_ever_reported_as_a_bare_withdrawn() {
        // Rule 1. Each tier's report carries that tier's canonical body,
        // and an unknown tier is not smoothed into the mild answer.
        for reach in [
            REACH_NOT_DISTRIBUTED,
            REACH_COMMONS_NOT_DISTRIBUTED,
            REACH_COMMONS_DISTRIBUTED,
        ] {
            let sentence = withdraw_result_sentence(Some(reach));
            assert!(
                sentence.contains(withdraw_canonical_body(reach).unwrap()),
                "{reach} does not carry its tier's canonical wording"
            );
        }
        assert!(withdraw_result_sentence(None).contains("cannot be recalled"));
        assert!(
            withdraw_result_sentence(Some("a-tier-from-the-future")).contains("cannot be recalled")
        );
    }

    #[test]
    fn a_failed_withdrawal_opens_by_saying_nothing_happened() {
        // A contributor must not walk away from a failure believing their
        // trace was taken back, whichever failure it was.
        for sentence in [
            WITHDRAW_ACCOUNT_SESSION_REQUIRED.to_string(),
            WITHDRAW_NOT_FOUND.to_string(),
            withdraw_failure_sentence("withdraw-failed"),
            withdraw_failure_sentence("account-session-required"),
            withdraw_failure_sentence("not-found"),
        ] {
            assert!(
                sentence.starts_with("Nothing was withdrawn"),
                "a failure sentence does not open by saying nothing happened: {sentence}"
            );
        }
    }

    #[test]
    fn the_not_found_sentence_discloses_neither_existence_nor_ownership() {
        // Rule 4: the server answers identically whether a submission
        // belongs to somebody else or does not exist, so that accounts
        // cannot be enumerated. This window must not undo that.
        let lower = WITHDRAW_NOT_FOUND.to_lowercase();
        assert!(!lower.contains("belongs to"));
        assert!(!lower.contains("does not exist"));
    }

    #[test]
    fn asking_for_an_update_never_claims_one_arrived() {
        // `refresh_history` answers `requested: true` and nothing else --
        // the poller owns the network call. Copy that said "Updated" would
        // be a claim about a round trip that has not happened yet.
        let lower = CHECK_FOR_UPDATES_ASKED.to_lowercase();
        assert!(lower.starts_with("asked"));
        assert!(!lower.contains("updated"));
        assert!(!lower.contains("refreshed"));
    }

    #[test]
    fn a_profile_that_was_published_never_reads_as_one_that_was_not() {
        // `handle_persisted: false` is a failed *local cache write*, not a
        // failed claim: the server has already taken the handle. Both
        // sentences must therefore open by saying the contributor is on the
        // roster, and neither may contain the vocabulary of a refusal.
        for sentence in [PROFILE_PUBLISHED, PROFILE_PUBLISHED_NOT_CACHED] {
            assert!(
                sentence.starts_with("You're on the roster"),
                "a published profile must be reported as published: {sentence}"
            );
            let lower = sentence.to_lowercase();
            for forbidden in [
                "couldn't publish",
                "failed",
                "wasn't published",
                "nothing changed",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "a published profile must not read as a failure ({forbidden}): {sentence}"
                );
            }
        }
        // And the uncached one still says the weaker true thing, rather
        // than being the same sentence twice.
        assert_ne!(PROFILE_PUBLISHED, PROFILE_PUBLISHED_NOT_CACHED);
        assert!(PROFILE_PUBLISHED_NOT_CACHED.contains("until you save it once more"));
    }

    #[test]
    fn a_withdrawal_that_happened_never_reads_as_one_that_did_not() {
        // The mirror rule. The row is gone from the server whether or not
        // the local clear stuck, so neither sentence may leave a
        // contributor thinking they are still listed.
        for sentence in [PROFILE_LEFT_ROSTER, PROFILE_LEFT_ROSTER_NOT_CACHED] {
            assert!(
                sentence.starts_with("You've left the roster"),
                "a completed withdrawal must be reported as completed: {sentence}"
            );
            assert!(sentence.to_lowercase().contains("isn't published any more"));
        }
    }

    #[test]
    fn every_refusal_says_nothing_was_published() {
        // A refusal happens before or instead of the PUT, so in every one
        // of these cases the handle did not go up -- and the contributor
        // has to be able to tell this apart from the published-but-uncached
        // case above.
        for label in [
            "handle-required",
            "handle-too-short",
            "handle-too-long",
            "handle-invalid-character",
            "handle-invalid-boundary",
            "handle-consecutive-separators",
            "handle-reserved",
            "bio-too-long",
            "bio-invalid-character",
            "bio-required-or-null",
            "not-logged-in",
            "profile-update-failed",
            "a-label-nobody-has-written-yet",
        ] {
            let sentence = profile_failure_sentence(label);
            assert!(
                sentence.contains("Nothing was published"),
                "{label} does not say the handle stayed private: {sentence}"
            );
        }
    }

    #[test]
    fn a_failed_withdrawal_never_borrows_the_claim_sentence() {
        // "Nothing was published" is false comfort after a failed
        // withdrawal: the handle is published, which is precisely the
        // problem. This one has to say the contributor is still listed.
        for label in ["not-logged-in", "profile-withdraw-failed"] {
            let sentence = roster_leave_failure_sentence(label);
            assert!(!sentence.contains("Nothing was published"));
            assert!(
                sentence.contains("still on the roster"),
                "{label} does not say the listing survived: {sentence}"
            );
        }
    }

    #[test]
    fn no_profile_sentence_echoes_a_server_error() {
        // The daemon never forwards the underlying error -- it can carry a
        // response body or a URL -- and this mapping must not invent a
        // place to put one either. Every branch is a fixed sentence, so
        // an unknown label reads as the generic failure and nothing else.
        let unknown = profile_failure_sentence("https://ingest.example/v1/community/profile");
        assert!(!unknown.contains("https://"));
        assert_eq!(unknown, profile_failure_sentence("something-else"));
    }

    #[test]
    fn every_detector_has_a_human_label() {
        // The list on screen is generated from this table, so a detector
        // added upstream appears whether or not anyone taught this shell to
        // say its name. This fails the day that happens, so the name it
        // appears under is a decision rather than a de-slugged accident.
        for slug in trace_commons_protocol::trace_contribution::secret_leak_pattern_names() {
            let label = scrub_detector_label(slug);
            assert_ne!(
                label,
                slug.replace('_', " "),
                "detector {slug} has no human label in scrub_detector_label"
            );
        }
    }

    /// The words themselves, against the copy the other two shells read.
    ///
    /// `every_detector_has_a_human_label` above proves a label EXISTS. It
    /// cannot see what the label says, and each shell hardcodes its own nine
    /// strings, so all three could satisfy their coverage guards while
    /// telling contributors three different things about the same detector.
    /// That is not hypothetical about `provider_token` and `cursor_api_key`
    /// in particular: the entire reason those are two detectors rather than
    /// one is the words each is published under.
    ///
    /// The fixture is the single copy of those words, read by this test and
    /// by the macOS and Windows ones named in its `checked_by`. A label
    /// changed in one shell fails here; a label changed in the fixture fails
    /// in the other two until they follow.
    #[test]
    fn scrub_detector_labels_match_the_shared_fixture() {
        const FIXTURE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/scrub-detectors/labels.json"
        );

        let raw = std::fs::read_to_string(FIXTURE)
            .unwrap_or_else(|e| panic!("reading the shared scrub-label fixture {FIXTURE}: {e}"));
        let parsed: serde_json::Value =
            serde_json::from_str(&raw).expect("the shared scrub-label fixture must be JSON");
        let labels = parsed["labels"]
            .as_object()
            .expect("the fixture must carry a `labels` object");

        // The fixture describes exactly the detectors that exist. Without
        // this, a detector added upstream is simply absent from the fixture
        // and every shell's parity test passes over a gap.
        let detectors = trace_commons_protocol::trace_contribution::secret_leak_pattern_names();
        let mut fixture_slugs: Vec<&str> = labels.keys().map(String::as_str).collect();
        let mut expected: Vec<&str> = detectors.clone();
        fixture_slugs.sort_unstable();
        expected.sort_unstable();
        assert_eq!(
            fixture_slugs, expected,
            "tests/fixtures/scrub-detectors/labels.json does not describe the detectors that \
             exist. Add the new detector's words there, then to all three shells."
        );

        for slug in detectors {
            let want = labels[slug]
                .as_str()
                .unwrap_or_else(|| panic!("{slug}'s label in the fixture must be a string"));
            assert_eq!(
                scrub_detector_label(slug),
                want,
                "this shell words {slug} differently from the shared fixture; the other two \
                 shells read that file, so this is a contributor being told something \
                 different on Linux"
            );
        }
    }

    #[test]
    fn a_detector_nobody_named_still_renders() {
        // The safety net, asserted rather than assumed: an unrecognised slug
        // must not render as an empty row on a screen whose whole job is
        // saying what is scrubbed.
        assert_eq!(
            scrub_detector_label("some_new_vendor_key"),
            "some new vendor key"
        );
    }

    #[test]
    fn the_ignore_confirmation_counts_in_words_a_person_can_read() {
        assert!(ignore_project_body(1).contains("1 waiting trace"));
        assert!(!ignore_project_body(1).contains("traces"));
        assert!(ignore_project_body(12).contains("12 waiting traces"));
    }

    #[test]
    fn the_ignore_confirmation_says_nothing_about_zero() {
        let body = ignore_project_body(0);
        assert!(!body.contains('0'), "{body}");
        assert!(!body.to_lowercase().contains("removes"), "{body}");
        assert!(body.contains("Stops this project being offered."), "{body}");
    }

    #[test]
    fn the_ignore_confirmation_always_names_the_way_back() {
        for n in [0usize, 1, 7] {
            let body = ignore_project_body(n);
            assert!(body.contains("undo this in Settings"), "n={n}: {body}");
            assert!(
                body.contains("Nothing already submitted is affected."),
                "n={n}"
            );
        }
    }

    #[test]
    fn the_ignore_reconciliation_speaks_only_when_the_count_moved() {
        assert_eq!(ignore_project_reconciled("api", 3, 3), None);
        assert_eq!(ignore_project_reconciled("api", 0, 0), None);
        let line = ignore_project_reconciled("api", 3, 5).expect("a moved count is said out loud");
        assert!(line.contains("5 waiting traces"), "{line}");
        assert!(line.contains("not 3"), "{line}");
        let one = ignore_project_reconciled("api", 3, 1).expect("fewer is still a moved count");
        assert!(one.contains("1 waiting trace was removed"), "{one}");
        assert!(!one.contains("traces"), "{one}");
    }

    #[test]
    fn the_ignore_title_names_the_project() {
        assert_eq!(ignore_project_title("api"), "Ignore api?");
    }

    /// This shell prints the shared words and not its own.
    ///
    /// Deliberately literal. Every other assertion on this surface compares
    /// one re-exported constant to another and would keep passing if all
    /// four were renamed together; this one is the tripwire that a word
    /// changed at all, and it is the same assertion the macOS and Windows
    /// suites make against the C ABI. Changing a word is meant to turn all
    /// three red at once.
    #[test]
    fn the_shell_prints_the_shared_words() {
        assert_eq!(TOOL_PRIVATE, "Private");
        assert_eq!(TOOL_DIRECT, "Sends direct");
        assert_eq!(TOOL_UNKNOWN, "Not known");
        assert_eq!(TOOL_NOT_USED, "Not used");
    }

    /// The evidence is stated before the question, so a contributor who
    /// reads only the first line still learns why they are being asked.
    #[test]
    fn the_arming_offer_states_its_evidence() {
        assert_eq!(
            arming_offer_evidence("api", 5),
            "You've contributed from api 5 times."
        );
    }

    /// The daemon's threshold is five, so this branch is unreachable today.
    /// It is here because the sentence must be right about whatever count it
    /// is handed, and "contributed from api 1 times" is not.
    #[test]
    fn the_arming_offer_is_singular_for_one() {
        assert_eq!(
            arming_offer_evidence("api", 1),
            "You've contributed from api once."
        );
    }

    #[test]
    fn the_arming_question_names_the_project() {
        assert_eq!(
            arming_offer_question("api"),
            "Contribute from api automatically?"
        );
    }

    /// The offer's own words must match the confirmation sheet's, because a
    /// contributor who accepts here has agreed to the same thing.
    #[test]
    fn the_offer_and_the_confirmation_agree_on_the_action() {
        assert_eq!(ARMING_OFFER_CONFIRM, ARMING_CONFIRM);
        assert_eq!(ARMING_OFFER_DECLINE, NOT_NOW);
    }

    /// "Not now", not "No": the daemon silences the offer for thirty days
    /// rather than forever, and the button must not promise otherwise.
    #[test]
    fn declining_the_offer_does_not_sound_permanent() {
        let lower = ARMING_OFFER_DECLINE.to_lowercase();
        assert!(!lower.contains("never"), "{ARMING_OFFER_DECLINE}");
        assert!(!lower.contains("don't ask"), "{ARMING_OFFER_DECLINE}");
    }
}

#[cfg(test)]
mod residual_copy_tests {
    use super::*;

    #[test]
    fn one_survivor_reads_as_one() {
        assert_eq!(
            residual_secret_line(1, &[]),
            "A secret found here is still in what would be sent"
        );
    }

    #[test]
    fn several_survivors_inflect() {
        assert!(residual_secret_line(3, &[]).starts_with("Secrets found in 3 places are"));
    }

    /// The line must say STILL IN, never anything that reads as removal --
    /// stating the opposite is the defect this whole change exists to fix.
    #[test]
    fn the_line_never_claims_the_secret_was_removed() {
        let line = residual_secret_line(1, &["events.3.correction".to_string()]);
        assert!(line.contains("still in what would be sent"), "{line}");
        assert!(!line.to_lowercase().contains("removed"), "{line}");
    }

    #[test]
    fn sites_are_listed_when_known() {
        let line = residual_secret_line(2, &["events.1".to_string(), "events.9".to_string()]);
        assert!(line.ends_with("(events.1, events.9)"), "{line}");
    }
}
