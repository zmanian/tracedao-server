using System;
using System.Collections.Generic;
using System.Globalization;
using TraceCommons.Interop;

namespace TraceCommons.App.ViewModels;

/// <summary>
/// What a withdrawal attempt has done to one record so far.
/// </summary>
/// <remarks>
/// Held per submission on <see cref="HistoryViewModel"/> rather than on the
/// row, because the row is rebuilt from the daemon's cache on every refresh
/// and the outcome must survive that. It is the one thing on this screen the
/// daemon does not remember for us: <c>list_history</c> reports the record's
/// status, never the tier a withdrawal applied.
/// </remarks>
public enum WithdrawalState
{
    /// <summary>Nothing has been tried.</summary>
    None,

    /// <summary>The request is out. Present tense: nothing has happened yet.</summary>
    InFlight,

    /// <summary>The server answered, and said which tier it applied.</summary>
    Done,

    /// <summary>The request did not go through. The button stays.</summary>
    Failed,
}

/// <summary>
/// A withdrawal attempt's result, kept whole so the row can report the tier
/// the server actually applied rather than a generic success.
/// </summary>
public sealed class WithdrawalAttempt
{
    private WithdrawalAttempt(WithdrawalState state, string? reach, string? label)
    {
        State = state;
        Reach = reach;
        Label = label;
    }

    public WithdrawalState State { get; }

    /// <summary>
    /// <c>distribution_reach</c> exactly as the server spelled it, or null if
    /// it reported none. Never interpreted here: <see cref="WithdrawCopy"/>
    /// owns what each tier means, and an unknown one has its own sentence.
    /// </summary>
    public string? Reach { get; }

    /// <summary>The daemon's fixed failure label. Never free text.</summary>
    public string? Label { get; }

    public static WithdrawalAttempt InFlight() => new(WithdrawalState.InFlight, null, null);

    public string? TokenDeletionNote { get; private set; }
    public static WithdrawalAttempt Done(string? reach, string? note = null) => new(WithdrawalState.Done, reach, null) { TokenDeletionNote = note };

    public static WithdrawalAttempt Failed(string? label) => new(WithdrawalState.Failed, null, label);
}

/// <summary>
/// One history row, formatted for display.
///
/// A read-only projection of <see cref="HistoryRecord"/>, in the same spirit
/// as <see cref="QueueEntryViewModel"/>: it exposes what a row shows and
/// nothing else. There is no path on the wire here and there must be none
/// invented -- history is the surface most likely to be screenshotted.
/// </summary>
public sealed class HistoryRecordViewModel
{
    private readonly HistoryRecord _record;
    private readonly WithdrawalAttempt? _attempt;

    public HistoryRecordViewModel(HistoryRecord record, WithdrawalAttempt? attempt)
    {
        _record = record ?? throw new ArgumentNullException(nameof(record));
        _attempt = attempt;
    }

    /// <summary>The id <c>withdraw</c> takes, and the key the attempt is filed under.</summary>
    public string SubmissionId => _record.SubmissionId;

    /// <summary>
    /// Which history folder this record belongs to.
    /// </summary>
    /// <remarks>
    /// Derived through <see cref="HistoryFolders.KeyOf"/> rather than restated
    /// here, so a row and the folder it sits under cannot come to disagree
    /// about which project it is: the id, falling back to a label-derived key
    /// for a record written before ids reached history.
    /// </remarks>
    public string FolderKey => HistoryFolders.KeyOf(_record);

    public string ProjectLabel =>
        string.IsNullOrWhiteSpace(_record.ProjectLabel) ? "Unknown project" : _record.ProjectLabel;

    /// <summary>
    /// When it was sent, in the viewer's local time. An unparsable timestamp
    /// degrades to a dash rather than to the epoch, which would read as a
    /// real date.
    /// </summary>
    public string SubmittedText =>
        DateTimeOffset.TryParse(
            _record.SubmittedAt,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out DateTimeOffset parsed)
            ? parsed.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : "—";

    /// <summary>
    /// The state, in the same words the stat cards at the top of the screen
    /// use, so a chip on a record and a card above it cannot say different
    /// things about one state.
    /// </summary>
    public string StatusWord => HistoryCopy.StatusWord(_record.Status);

    /// <summary>
    /// True on a withdrawn record, so the chip can be toned as the
    /// contributor's own act rather than as a refusal or a success.
    /// </summary>
    public bool IsWithdrawn =>
        string.Equals(_record.Status, HistoryCopy.StatusWithdrawn, StringComparison.Ordinal);

    public bool IsHeld =>
        string.Equals(_record.Status, HistoryCopy.StatusQuarantined, StringComparison.Ordinal);

    public bool IsAccepted =>
        string.Equals(_record.Status, HistoryCopy.StatusAccepted, StringComparison.Ordinal);

    /// <summary>
    /// Everything else, including a status this build has no name for.
    ///
    /// The four flags are exhaustive and mutually exclusive on purpose: the
    /// chip is drawn from them, and a status from a newer server must land in
    /// the neutral "waiting" chip rather than in no chip at all. A record with
    /// no chip would read as a record with no state.
    /// </summary>
    public bool IsWaiting => !IsAccepted && !IsHeld && !IsWithdrawn;

    /// <summary>
    /// The server's own prose about this submission, rendered verbatim.
    /// "Held because a passage looked like a personal address" is enormously
    /// better than a status word, and it is the server's sentence to write,
    /// not this window's to paraphrase.
    /// </summary>
    public IReadOnlyList<string> Explanations => _record.Explanations;

    public bool HasExplanations => _record.Explanations.Count > 0;

    /// <summary>
    /// Only a held record gets a sentence it did not earn from the server,
    /// and only when the server sent none: it is the one state a person can
    /// misread as a refusal. The other three are said by the chip, and
    /// repeating them under it is noise.
    /// </summary>
    public bool ShowsHeldExplanation => IsHeld && _record.Explanations.Count == 0;

    public string HeldExplanation => HistoryCopy.HeldRowBody;

    /// <summary>
    /// The record's own figures, or empty. A withdrawn record keeps whatever
    /// it recorded: withdrawal does not reverse settled credit, and implying
    /// it did would be a lie about what the action achieved.
    /// </summary>
    public string CreditText =>
        HistoryCopy.CreditLine(_record.CreditPointsFinal, _record.CreditPointsPending)
        ?? string.Empty;

    public bool HasCredit => CreditText.Length > 0;

    /// <summary>
    /// Whether the row offers a withdraw button. See
    /// <see cref="WithdrawCopy.OffersWithdrawal"/> for why an already-withdrawn
    /// record does not get one.
    /// </summary>
    public bool OffersWithdrawal =>
        WithdrawCopy.OffersWithdrawal(_record.Status, _record.SubmissionId)
        && _attempt?.State != WithdrawalState.InFlight
        && _attempt?.State != WithdrawalState.Done;

    /// <summary>
    /// The progress label, present tense, while the request is out.
    /// </summary>
    public bool IsWithdrawing => _attempt?.State == WithdrawalState.InFlight;

    public string WithdrawingText => WithdrawCopy.Withdrawing;

    /// <summary>
    /// What the attempt actually did, once there is an answer.
    /// </summary>
    /// <remarks>
    /// The outcome replaces the button rather than sitting beside it, because
    /// the two are answers to different questions: before, "do you want to
    /// take this back?"; after, "here is what taking it back achieved". A
    /// failure keeps the button, since a failed withdrawal is one the
    /// contributor may well want to retry.
    ///
    /// Never a generic "withdrawn": on success this names the tier the server
    /// applied, and says so plainly when the server reported a tier this build
    /// does not know.
    /// </remarks>
    public string WithdrawOutcomeText => _attempt?.State switch
    {
        WithdrawalState.Done => WithdrawCopy.ResultSentence(_attempt.Reach) + (string.IsNullOrEmpty(_attempt.TokenDeletionNote) ? "" : "\n" + _attempt.TokenDeletionNote),
        WithdrawalState.Failed => WithdrawCopy.FailureSentence(_attempt.Label),
        _ => string.Empty,
    };

    public bool HasWithdrawOutcome => WithdrawOutcomeText.Length > 0;

    /// <summary>
    /// Shown only beside a successful withdrawal, and only ever says that
    /// credit already recorded stays. Rule 3: withdrawal does not reverse
    /// settled credit, and nothing here may imply it does.
    /// </summary>
    public bool ShowsWithdrawCreditNote => _attempt?.State == WithdrawalState.Done;

    public string WithdrawCreditNote => WithdrawCopy.CreditNote;

    /// <summary>
    /// The stage the confirmation is keyed on, read off the local status --
    /// which is the weaker thing this machine knows before it asks.
    /// </summary>
    public WithdrawStage Stage => WithdrawStageExtensions.StageOf(_record.Status);
}
