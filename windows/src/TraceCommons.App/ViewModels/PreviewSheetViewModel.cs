using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using TraceCommons.Interop;

namespace TraceCommons.App.ViewModels;

/// <summary>Which tab of the preview sheet is showing.</summary>
public enum PreviewTab
{
    /// <summary>
    /// First and focused, always. "Does this mention my client's name?" is a
    /// question a contributor can answer in five seconds; judging redaction
    /// quality by eye is not, and this sheet never asks them to.
    /// </summary>
    Search,
    WhatsInIt,
    Transcript,
    Permissions,
}

/// <summary>
/// "Look inside": the one surface in this app that deliberately shows trace
/// content, because consent to send something you cannot see is not consent.
///
/// <para>
/// Four tabs in the shared spec's order, and <b>Contribute exists here and
/// nowhere else</b>. The queue row has no approve button on purpose:
/// approving from the row is approving without looking, which is the misclick
/// the preview-then-approve rule exists to prevent.
/// </para>
/// <para>
/// The invariant this whole class serves is that <b>an approval covers exactly
/// the bytes a preview pinned</b>. It is enforced by <see cref="Gate"/>, which
/// lives in the interop assembly so it can be tested on a machine that cannot
/// build WinUI, and it is the only thing that arms
/// <see cref="CanContribute"/>. It used to enforce two more conditions -- a
/// transcript shown and an acknowledgement ticked -- and <see cref="ReadGate"/>
/// records why they went and what took their place. The Linux shell applies the
/// same rule in <c>sync_contribute</c>; the macOS sheet applies it through
/// <c>TCShellCore.ReadGate</c>.
/// </para>
/// <para>
/// <b>One sheet, one session, one decision.</b> Both decisions close the
/// sheet. It does not load the next waiting session into itself, which the
/// shared spec's "Approving" section describes and the macOS sheet
/// deliberately stopped doing: that put Contribute under the same pixels for a
/// second session, so one more click sent a transcript nobody had looked at,
/// and it stranded the recovery bar behind a sheet where it could not be seen.
/// A sheet that advanced would also have to re-pin under the contributor's
/// cursor, which is a worse thing to get wrong than an extra click is to
/// require.
/// </para>
/// </summary>
public sealed class PreviewSheetViewModel : INotifyPropertyChanged, IDisposable
{
    /// <summary>
    /// Shown where the sheet body would be while the redaction pass runs.
    /// </summary>
    private const string LocalLoadingTitle = "Scrubbing it locally…";

    private const string LocalLoadingDetail = "Reading the session and running the redaction pass.";

    /// <summary>
    /// A preview that could not be opened or could not be understood. The
    /// second sentence is the promise that makes the failure survivable.
    /// </summary>
    public const string FailureTitle = "This one can't be shown.";

    public const string FailureDetail =
        "Nothing has been sent, and nothing will be until it can be shown to you.";

    /// <summary>
    /// The scrubbing caveat, word for word as the queue window prints it and
    /// as the macOS and Linux shells print it.
    /// </summary>
    /// <remarks>
    /// Bound from <see cref="ScrubbingCaveatCopy"/> rather than written here:
    /// it has to be identical everywhere it appears, so that a person who read
    /// it under the queue recognises it above Contribute rather than reading a
    /// second, weaker message.
    /// </remarks>
    public static string ScrubbingCaveat => ScrubbingCaveatCopy.Sentence;

    /// <summary>
    /// The same sentence as an instance property, because x:Bind binds against
    /// the view model instance and cannot reach a static member.
    /// </summary>
    public string ScrubbingCaveatSentence => ScrubbingCaveatCopy.Sentence;

    /// <summary>
    /// The gold chip's line: what a session where no pattern fired says, and
    /// what to do about it.
    /// </summary>
    public string NothingMatchedLine => ScrubbingCaveatCopy.RowLine(
        _summary is null ? 0 : RedactionLabels.Total(_summary.Redactions));

    private readonly DaemonHost _host;
    private readonly WitnessReviewCopy? _witnessCopy = WitnessSurface.Copy()?.Review;
    private bool _witnessSupported;
    private bool _witnessRequested;
    /// The daemon's sentence for a review it refused, kept apart from
    /// <see cref="FailureDetail"/> so only a classified refusal can be shown.
    private string? _witnessRefusal;
    private bool _witnessWorking;
    private bool _witnessConfigured;
    private bool _admissionSupported;
    private bool _admissionBusy;
    private string _admissionMessage = string.Empty;
    public bool CanPrepareAdmission => _admissionSupported && !_admissionBusy && !_witnessWorking;
    private bool _admissionRefused;
    public string AdmissionMessage => _admissionMessage;
    public string AdmissionRefusalMessage => _admissionRefused ? _admissionMessage : string.Empty;
    public string AdmissionNeutralMessage => _admissionRefused ? string.Empty : _admissionMessage;
    public string AdmissionGlyph => _admissionRefused ? AdmissionPreparation.Copy?.RefusedGlyph ?? string.Empty : string.Empty;
    public string AdmissionHeading => AdmissionPreparation.Heading;
    public string ImmutableNote => CanEditOutcome ? string.Empty : _witnessCopy?.Immutable ?? string.Empty;
    public async Task PrepareAdmissionAsync(string backend)
    {
        if (!CanPrepareAdmission || string.IsNullOrWhiteSpace(backend)) return;
        _admissionBusy = true; _admissionRefused = false; _admissionMessage = AdmissionPreparation.Copy?.Working ?? "";
        Raise(nameof(CanPrepareAdmission)); Raise(nameof(AdmissionMessage)); Raise(nameof(AdmissionRefusalMessage)); Raise(nameof(AdmissionNeutralMessage)); Raise(nameof(AdmissionGlyph)); Raise(nameof(CanRequestWitness));
        try {
            var response = await _host.CallAsync(AdmissionPreparation.Method, AdmissionPreparation.Request(Entry.EntryId, backend)).ConfigureAwait(true);
            _admissionRefused = !AdmissionPreparation.IsReady(response);
            _admissionMessage = _admissionRefused ? AdmissionPreparation.Refusal(response) : AdmissionPreparation.Success;
        } catch { _admissionRefused = true; _admissionMessage = AdmissionPreparation.Failed; }
        finally { _admissionBusy = false; Raise(nameof(CanPrepareAdmission)); Raise(nameof(AdmissionMessage)); Raise(nameof(AdmissionRefusalMessage)); Raise(nameof(AdmissionNeutralMessage)); Raise(nameof(AdmissionGlyph)); Raise(nameof(CanRequestWitness)); }
    }

    public string WitnessHeading => _witnessCopy?.Heading ?? string.Empty;
    public string WitnessDisclosure => _witnessCopy?.Disclosure ?? string.Empty;
    public string WitnessAction => _witnessCopy?.Action ?? string.Empty;
    public string WitnessConfirm => _witnessCopy?.Confirm ?? string.Empty;
    public string WitnessCancel => _witnessCopy?.Cancel ?? string.Empty;
    /// <summary>
    /// A refusal the daemon classified wins; otherwise the one fixed
    /// sentence. <see cref="FailureDetail"/> can hold local error text and
    /// must not reach a screen once a witness was requested.
    /// </summary>
    public string PreviewFailureDetail => _witnessRequested
        ? _witnessRefusal ?? _witnessCopy?.Failed ?? FailureDetail
        : FailureDetail;
    public string LoadingTitle => _witnessWorking ? _witnessCopy?.Heading ?? string.Empty : LocalLoadingTitle;
    public string LoadingDetail => _witnessWorking ? _witnessCopy?.Working ?? string.Empty : LocalLoadingDetail;
    public bool CanRequestWitness => _witnessSupported && _witnessConfigured && !_witnessWorking && !_admissionBusy && _witnessCopy?.IsComplete == true;
    public bool CanEditOutcome => !_witnessConfigured && !_witnessRequested && !_witnessWorking;

    public async Task RequestWitnessAsync()
    {
        if (!CanRequestWitness) return;
        _witnessRequested = true;
        _witnessWorking = true;
        _witnessRefusal = null;
        Gate.SetPinnedPreview(false);
        IsLoading = true;
        HasFailed = false;
        Raise(nameof(CanRequestWitness));
        Raise(nameof(CanEditOutcome)); Raise(nameof(ImmutableNote));
        Raise(nameof(LoadingTitle));
        Raise(nameof(LoadingDetail));
        Raise(nameof(PreviewFailureDetail));
        try
        {
            var response = await _host.CallAsync(NativeWitnessReview.Method, NativeWitnessReview.ConfirmedRequest(Entry.EntryId)).ConfigureAwait(true);
            _witnessWorking = false;
            if (!NativeWitnessReview.IsReady(response))
            {
                _witnessRefusal = NativeWitnessReview.Refusal(response);
                Fail();
                return;
            }
            await LoadAsync().ConfigureAwait(true);
        }
        catch { _witnessWorking = false; Fail(); }
        finally {
            Raise(nameof(CanRequestWitness));
            Raise(nameof(LoadingTitle));
            Raise(nameof(LoadingDetail));
        }
    }


    private TcPreview? _preview;
    private PreviewSummary? _summary;
    private string _transcript = string.Empty;
    private string _needle = string.Empty;
    private IReadOnlyList<int> _matches = Array.Empty<int>();
    private bool _searched;
    private bool _searchFailed;
    private OriginalSearchOutcome? _originalOutcome;
    private bool _loading = true;
    private bool _failed;
    private bool _deciding;
    private string? _verdict;
    private string _correction = string.Empty;
    private bool _correctionRefused;
    private PreviewTab _tab = PreviewTab.Search;

    /// <remarks>
    /// <paramref name="liveEntry"/> is REQUIRED AND HAS NO DEFAULT. Making it
    /// optional would mean a caller that forgot it silently got the stale
    /// behaviour back -- the exact defect this parameter exists to remove,
    /// re-armed as a default, with no test failure and no warning to whoever
    /// added the call site. Required, it fails at compile time where the
    /// mistake is. A caller that genuinely has no queue to resolve against
    /// passes <c>liveEntry: null</c> and says why, so choosing it is visible
    /// in the code and indistinguishable from nothing.
    /// </remarks>
    public PreviewSheetViewModel(
        DaemonHost host,
        QueueEntryViewModel entry,
        Func<string, QueueEntryViewModel?>? liveEntry)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        Entry = entry ?? throw new ArgumentNullException(nameof(entry));
        _liveEntry = liveEntry;

        // Every gate transition re-raises the properties the footer binds to,
        // so there is no path that changes a condition without the button
        // noticing.
        Gate.Changed += OnGateChanged;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Raised once the contributor has decided, with the approval's hold when
    /// there is one to undo against.
    /// </summary>
    /// <remarks>
    /// The undo belongs to the queue window, not to this sheet: recovery has
    /// to live on the screen a contributor lands on after deciding, not behind
    /// a sheet that has already closed.
    /// </remarks>
    public event Action<PreviewDecision>? Decided;

    public QueueEntryViewModel Entry { get; }

    /// <summary>
    /// Looks this session up in the queue as it stands NOW, by entry id.
    /// </summary>
    /// <remarks>
    /// Null when the sheet was opened without a queue to resolve against, in
    /// which case <see cref="LiveEntry"/> falls back to the pinned copy --
    /// the honest answer for a sheet that has no live queue, and the same
    /// answer this sheet gave before.
    /// </remarks>
    private readonly Func<string, QueueEntryViewModel?>? _liveEntry;

    /// <summary>
    /// This session as the queue describes it now, falling back to the copy
    /// the sheet opened with.
    /// </summary>
    /// <remarks>
    /// <b><see cref="Entry"/> IS THE COPY THIS SHEET OPENED WITH, AND IT CAN
    /// GO STALE.</b> The queue rebuilds every row object on refresh
    /// (<c>MainViewModel.ReplacePending</c> clears and refills rather than
    /// diffing), so an open sheet keeps an entry nobody updates. A
    /// submit-time failure writes its reason back into the row -- Decision 1
    /// of the design -- so a session can be downgraded to
    /// <c>ineligible_permanent</c> while its sheet is on screen, and a gate
    /// computed from the opening copy would go on offering Contribute
    /// indefinitely. No write undoes the gate; the gate simply reads a copy
    /// that has stopped being true.
    ///
    /// <para>
    /// ONLY THE GATE AND ITS SENTENCES READ THIS. What the sheet actually
    /// approves still goes through <see cref="Entry"/>: the entry id is
    /// identical either way, so nothing a contributor started moves under
    /// them mid-read, and the preview they are looking at stays the one they
    /// opened.
    /// </para>
    ///
    /// <para>
    /// It reads the queue rather than assuming the worst, so an entry the
    /// daemon UPGRADES becomes offerable without closing the sheet.
    /// </para>
    /// </remarks>
    private QueueEntryViewModel LiveEntry =>
        (_liveEntry is null ? null : _liveEntry(Entry.EntryId)) ?? Entry;

    /// <summary>
    /// The queue changed underneath this sheet: re-read everything derived
    /// from the entry.
    /// </summary>
    /// <remarks>
    /// Resolving live is only half of it. These properties are pull-bound, so
    /// without a raise the footer keeps drawing the answer it last read --
    /// which for an entry downgraded while the sheet is open is an armed
    /// Contribute that stays armed for as long as the sheet is up.
    /// </remarks>
    public void QueueChanged()
    {
        Raise(nameof(CanContribute));
        Raise(nameof(HasEligibilityText));
        Raise(nameof(EligibilityText));
        Raise(nameof(HasEligibilityReason));
        Raise(nameof(EligibilityReasonText));
    }

    /// <summary>The consent invariant. See <see cref="ReadGate"/>.</summary>
    public ReadGate Gate { get; } = new();

    /// <summary>
    /// The consent surface's sentences, read once. Null if the payload did
    /// not arrive or would not parse, in which case the sheet shows no
    /// claim rather than a blank one -- see ConsentSurface.Parse.
    /// </summary>
    private readonly ConsentCopy? _consent = ConsentSurface.Copy();

    /// <summary>Matched excerpts for the current search, newest search only.</summary>
    public ObservableCollection<string> Excerpts { get; } = new();

    /// <summary>The contributor's earlier search terms, for one-click recall.</summary>
    public ObservableCollection<string> RecentSearches { get; } = new();

    public bool IsLoading
    {
        get => _loading;
        private set
        {
            if (Set(ref _loading, value))
            {
                Raise(nameof(IsShowingContent));
            }
        }
    }

    public bool HasFailed
    {
        get => _failed;
        private set
        {
            if (Set(ref _failed, value))
            {
                Raise(nameof(IsShowingContent));
            }
        }
    }

    public bool IsShowingContent => !IsLoading && !HasFailed;

    /// <summary>
    /// The redacted transcript: the exact bytes an approval covers.
    ///
    /// Trace content. It is bound to a text control and to nothing else --
    /// never a log line, never an error string, never a notification.
    /// </summary>
    public string Transcript
    {
        get => _transcript;
        private set => Set(ref _transcript, value);
    }

    public PreviewTab Tab
    {
        get => _tab;
        private set
        {
            if (!Set(ref _tab, value))
            {
                return;
            }

            Raise(nameof(IsSearchTab));
            Raise(nameof(IsWhatsInItTab));
            Raise(nameof(IsTranscriptTab));
            Raise(nameof(IsPermissionsTab));
        }
    }

    public bool IsSearchTab => Tab == PreviewTab.Search;
    public bool IsWhatsInItTab => Tab == PreviewTab.WhatsInIt;
    public bool IsTranscriptTab => Tab == PreviewTab.Transcript;
    public bool IsPermissionsTab => Tab == PreviewTab.Permissions;

    /// <summary>What would leave this machine, in bytes, from the preview.</summary>
    /// <remarks>
    /// Deliberately not the queue row's figure. A queue entry's
    /// <c>size_bytes</c> is the session file on disk; "would send" is the
    /// redacted envelope, which is usually larger because it also carries
    /// schema, consent and privacy metadata. Only a preview knows it, which is
    /// why only this screen prints it.
    /// </remarks>
    public string ProbabilitySummary => _summary?.ProbabilitySummary ?? string.Empty;
    public string WouldSendText =>
        _summary is null ? "—" : QueueEntryViewModel.FormatBytes(_summary.WouldSendBytes);

    public string RawSessionText =>
        _summary is null ? "—" : QueueEntryViewModel.FormatBytes(_summary.RawSessionBytes);

    /// <summary>"12 secrets · 4 tokens", or "nothing matched".</summary>
    public string ScrubbingFoundText => _summary?.ScrubbingFound ?? "—";

    /// <summary>
    /// True when scrubbing removed nothing, which is the one manifest state
    /// drawn to be found rather than reassured over: a session that obviously
    /// touched credentials and matched no pattern is worth a second look.
    /// </summary>
    /// <summary>
    /// Whether scrubbing REMOVED nothing.
    /// </summary>
    /// <remarks>
    /// Not "the map is empty": <c>Redactions</c> also carries
    /// <c>residual_secret_at:*</c>, which counts a secret the scan found and
    /// did NOT remove. A session whose only entry was a survivor therefore
    /// used to read as one where scrubbing had done something, and lost the
    /// note that asks somebody to look. See <c>RedactionLabels</c>.
    /// </remarks>
    public bool NothingMatched =>
        _summary is not null && RedactionLabels.RemovedTotal(_summary.Redactions) == 0;

    /// <summary>Secrets the scan found and left in what would be sent.</summary>
    public string SurvivingSecrets => _summary?.SurvivingSecrets ?? string.Empty;

    /// <summary>Whether to show <see cref="SurvivingSecrets"/> at all.</summary>
    public bool HasSurvivingSecrets => _summary?.HasSurvivingSecrets ?? false;

    public string TurnsText =>
        _summary is null
            ? "—"
            : _summary.EventCount.ToString("N0", CultureInfo.CurrentCulture);

    public string ResidualRiskText =>
        string.IsNullOrWhiteSpace(_summary?.ResidualRisk)
            ? "—"
            : _summary!.ResidualRisk.Replace('_', ' ');

    /// <summary>Category labels only. The matched text is never reported.</summary>
    public string PiiLabelsText =>
        _summary is null || _summary.PiiLabelsPresent.Count == 0
            ? string.Empty
            : string.Join(", ", _summary.PiiLabelsPresent);

    public bool HasPiiLabels => PiiLabelsText.Length > 0;

    /// <summary>
    /// One row per category scrubbing REMOVED, for "What's in it".
    /// </summary>
    /// <remarks>
    /// Grouped by family, described, and counted by
    /// <see cref="RedactionSummary.Rows"/> in the interop assembly, which is
    /// where it can be tested. This collection only carries that decision to
    /// the markup.
    /// </remarks>
    public ObservableCollection<RedactionSummaryRow> RemovedCategories { get; } = new();

    /// <summary>
    /// One row per category the scan FOUND AND DID NOT REMOVE.
    /// </summary>
    /// <remarks>
    /// A separate list rather than a flag on the rows above, because these are
    /// the opposite fact and they render under the opposite heading. The
    /// daemon sends both in one map, and every shell used to draw the whole
    /// map under "Removed by pattern" -- so a session with a surviving secret
    /// reported it as a thing that had been taken out, on the one screen where
    /// somebody is deciding whether to send it.
    /// </remarks>
    public ObservableCollection<RedactionSummaryRow> StillPresentCategories { get; } = new();

    /// <summary>Whether anything was found and left in what would be sent.</summary>
    public bool HasStillPresentCategories => StillPresentCategories.Count > 0;

    /// <summary>
    /// The scopes this upload asks for, restated at the moment of consent
    /// rather than only at onboarding.
    /// </summary>
    public ObservableCollection<PermissionRow> Permissions { get; } = new();

    /// <summary>Badge on the "What's in it" tab: how much scrubbing removed.</summary>
    public string RedactionBadge =>
        _summary is null || _summary.TotalRedactions == 0
            ? string.Empty
            : _summary.TotalRedactions.ToString(CultureInfo.CurrentCulture);

    public bool HasRedactionBadge => RedactionBadge.Length > 0;

    public string PermissionsBadge =>
        _summary is null
            ? string.Empty
            : _summary.ConsentScopes.Count.ToString(CultureInfo.CurrentCulture);

    public string Needle
    {
        get => _needle;
        set => Set(ref _needle, value ?? string.Empty);
    }

    /// <summary>The answer to the only question the Search tab exists for.</summary>
    public string SearchResultText =>
        !_searched || Needle.Length == 0
            ? "Type to search. Nothing is sent while you look."
            : _searchFailed ? "The search couldn't run on this trace."
            : _matches.Count == 0 ? "0 matches"
            : _matches.Count == 1 ? "1 match"
            : $"{_matches.Count} matches";

    /// <summary>
    /// True for a search that found nothing, so the caveat beneath it can be
    /// shown. A search finding nothing is not evidence that nothing is there.
    /// </summary>
    public bool ShowNothingMatchedNote =>
        _searched && Needle.Length > 0 && !_searchFailed && _matches.Count == 0;

    public string NothingMatchedNote =>
        "A search only finds what is written the way you typed it. If it matters, try the "
        + "other spellings you would worry about — a hostname, an internal code name, an address.";

    /// <summary>
    /// Whether a value the search found was actually taken out.
    /// </summary>
    /// <remarks>
    /// Absent until a committed search has been answered, so the tab says
    /// nothing rather than saying something it has not checked.
    /// </remarks>
    public bool HasOriginalOutcome => _originalOutcome is not null;

    /// <summary>The sentence for that answer, from the shared outcome type.</summary>
    public string OriginalOutcomeText => _originalOutcome?.Sentence ?? string.Empty;

    /// <summary>
    /// Whether that answer is the alarming one. True only for a value still in
    /// what would be sent -- never for one the check could not be made about,
    /// which is unproven rather than alarming and says so in its own words.
    /// </summary>
    public bool OriginalOutcomeIsAlarming => _originalOutcome?.IsAlarming == true;

    /// <summary>
    /// The same answer, in the ordinary tone.
    /// </summary>
    /// <remarks>
    /// A second boolean rather than a converter, matching how every other
    /// either/or on this window is drawn: two elements, each bound to the
    /// condition under which it belongs on screen. Both are false before a
    /// committed search has been answered, which is what keeps the line absent
    /// rather than blank.
    /// </remarks>
    public bool OriginalOutcomeIsCalm => HasOriginalOutcome && !OriginalOutcomeIsAlarming;

    /// <summary>
    /// Armed only with a pinned preview, the sentences that explain the
    /// button, no decision already in flight, and a session the shared crate
    /// says may be offered at all. See <see cref="ReadGate.CanArm"/>: a build
    /// that cannot read the claim must not take an approval against it.
    /// </summary>
    /// <remarks>
    /// The eligibility half is the same rule the queue row follows, and it
    /// has to be here too: "Look inside" is a second route to the send, and a
    /// button the row withheld would otherwise be waiting one click behind
    /// it. <see cref="QueueEntryViewModel.CanContribute"/> is true for a row
    /// the daemon never asked the question of, so an invited contributor's
    /// sheet is unchanged.
    ///
    /// <para>
    /// The sentence saying why is drawn beside the button by
    /// <see cref="EligibilityText"/>, so this is never a control that
    /// vanished without explanation.
    /// </para>
    /// </remarks>
    public bool CanContribute =>
        ReadGate.CanArm(_consent, Gate.CanContribute) && !_deciding && LiveEntry.CanContribute;

    /// <summary>
    /// Whether this session carries a sentence about whether it can be
    /// contributed. See <see cref="QueueEntryViewModel.HasEligibilityText"/>.
    /// </summary>
    public bool HasEligibilityText => LiveEntry.HasEligibilityText;

    /// <summary>That sentence, from the shared crate.</summary>
    public string EligibilityText => LiveEntry.EligibilityText;

    /// <summary>Whether a reason worth naming came with it.</summary>
    public bool HasEligibilityReason => LiveEntry.HasEligibilityReason;

    /// <summary>That reason, from the shared crate.</summary>
    public string EligibilityReasonText => LiveEntry.EligibilityReasonText;

    public bool CanDecide => !_deciding;

    /// <summary>
    /// The tooltip that explains the current answer, chosen by the ABI.
    ///
    /// Empty when the sentences are unavailable -- the same condition that
    /// disarms <see cref="CanContribute"/>, so nothing is claimed and
    /// nothing is pressable. A sentence written here instead would be a
    /// fourth place the wording lives.
    /// </summary>
    public string ContributeHelp =>
        (_consent is null ? null : ConsentSurface.GateHelp(Gate.CanContribute)) ?? string.Empty;

    /// <summary>
    /// The contributor's answer to <see cref="VerdictCopy.Question"/>: one of
    /// <see cref="Verdict"/>'s three values, or <c>null</c> for the answer
    /// they are entitled to give, which is none.
    /// </summary>
    /// <remarks>
    /// Nothing here reads this except <see cref="ContributeAsync"/>, and it
    /// reads it only to decide whether <c>approve</c> carries an
    /// <c>outcome</c> key at all. It is deliberately NOT part of
    /// <see cref="CanContribute"/>: the verdict question never gates the
    /// approve control, and a sheet that refused to send until it was
    /// answered would be asking for an opinion under duress.
    ///
    /// One sheet is one entry -- this view model is constructed with the
    /// entry it previews -- so there is no path by which a verdict answered
    /// for one session can attach to another.
    /// </remarks>
    public string? SelectedVerdict => _verdict;

    public string VerdictQuestion => VerdictCopy.Question;

    public string VerdictWorkedLabel => VerdictCopy.Worked;

    public string VerdictPartlyLabel => VerdictCopy.Partly;

    public string VerdictFailedLabel => VerdictCopy.Failed;

    /// <summary>
    /// The disclosure under the verdict control. Load-bearing: the outcome
    /// fields sit outside the "exactly what would be sent" guarantee the rest
    /// of this sheet makes, and this is where a contributor is told so.
    /// </summary>
    public string VerdictCaption => VerdictCopy.Caption;

    /// <summary>
    /// What the contributor wrote in the correction box.
    /// </summary>
    /// <remarks>
    /// Optional throughout and never part of <see cref="CanContribute"/>,
    /// for the same reason the verdict is not: an approval that refused to
    /// proceed until something was typed would be asking for an explanation
    /// under duress.
    ///
    /// Capped at <see cref="CorrectionCopy.MaxCharacters"/> here, where the
    /// person can see it happen, rather than letting the daemon refuse the
    /// submission as <c>correction-too-long</c> after the click.
    /// </remarks>
    public string Correction
    {
        get => _correction;
        set
        {
            if (!CanEditOutcome) return;
            string clipped = value ?? string.Empty;
            if (clipped.Length > CorrectionCopy.MaxCharacters)
            {
                clipped = clipped[..CorrectionCopy.MaxCharacters];
            }

            Set(ref _correction, clipped);
        }
    }

    /// <summary>
    /// Whether the correction control is on screen: only under
    /// <c>partly</c> and <c>failed</c>.
    /// </summary>
    /// <remarks>
    /// A guard, not only semantics. You cannot correct a run you have just
    /// called successful, so the surface for correction-shaped credit
    /// farming is halved and the field appears only where a correction is
    /// meaningful. The daemon enforces the same rule
    /// (<c>correction-needs-outcome</c>) rather than trusting this.
    /// </remarks>
    public bool IsCorrectionOffered =>
        _verdict is Verdict.Partly or Verdict.Failed;

    public string CorrectionQuestion => CorrectionCopy.Question;

    public string CorrectionPlaceholder => CorrectionCopy.Placeholder;

    /// <summary>
    /// The disclosure under the correction box, printed in full.
    ///
    /// Load-bearing in the strongest sense on this sheet. Everything else
    /// here is scrubbed locally and scrubbed again on the server; a
    /// correction is the one exception, and the published policy page does
    /// not yet say so. Until it does, this sentence is the whole of what a
    /// contributor is told. Do not shorten it for layout.
    /// </summary>
    public string CorrectionCaption => CorrectionCopy.Caption;

    /// <summary>
    /// Set when the daemon refused this submission because the correction
    /// contains something credential-shaped. The sheet stays open with the
    /// text still in the box: the next thing the contributor has to do is
    /// edit it.
    /// </summary>
    public bool WasRefusedForACorrectionCredential => _correctionRefused;

    public string CorrectionRefusalHeadline => CorrectionCopy.CredentialHeadline;

    public string CorrectionRefusalBody => CorrectionCopy.CredentialBody;

    public bool IsWorkedSelected => _verdict == Verdict.Worked;

    public bool IsPartlySelected => _verdict == Verdict.Partly;

    public bool IsFailedSelected => _verdict == Verdict.Failed;

    /// <summary>
    /// Selects <paramref name="outcome"/>, or clears the selection if it was
    /// already the answer.
    /// </summary>
    /// <remarks>
    /// Clearing matters as much as selecting: a contributor who clicks
    /// "Failed" and then thinks better of it must be able to get back to
    /// having said nothing, and "nothing" is a state the daemon has a real
    /// representation for. The three controls behave as a radio group that
    /// can also be emptied, which is why they are toggles and not a
    /// <c>RadioButtons</c> group -- the latter cannot be returned to unset.
    /// </remarks>
    public void ToggleVerdict(string outcome)
    {
        if (!CanEditOutcome) return;
        _verdict = _verdict == Verdict.Require(outcome) ? null : outcome;

        // A contributor who wrote a correction under "Failed" and then
        // answered "Worked" has withdrawn it. Clearing it here is what stops
        // text nobody can see any more from riding along on the approval.
        if (!IsCorrectionOffered)
        {
            _correction = string.Empty;
            _correctionRefused = false;
            Raise(nameof(Correction));
            Raise(nameof(WasRefusedForACorrectionCredential));
        }

        Raise(nameof(SelectedVerdict));
        Raise(nameof(IsWorkedSelected));
        Raise(nameof(IsPartlySelected));
        Raise(nameof(IsFailedSelected));
        Raise(nameof(IsCorrectionOffered));
    }

    /// <summary>
    /// What the sheet says about redaction above Contribute. Always shown,
    /// because it is a statement about the mechanism and not a report on
    /// the state of anything.
    /// </summary>
    public string GateStatement => _consent?.GateStatement ?? string.Empty;

    public void SelectTab(PreviewTab tab) => Tab = tab;

    /// <summary>
    /// Opens the preview and fills the sheet.
    ///
    /// Every failure path ends with the gate unpinned, so a sheet that could
    /// not show the bytes cannot approve them.
    /// </summary>
    public async Task LoadAsync()
    {
        IsLoading = true;
        HasFailed = false;
        _witnessConfigured = WitnessSurface.TrustState(_host.ConfigDir) == WitnessTools.StatePinned;
        var hello = await _host.CallAsync("hello").ConfigureAwait(true);
        _witnessSupported = NativeWitnessReview.Supports(hello);
        var settings = await _host.CallAsync("get_settings").ConfigureAwait(true);
        _admissionSupported = AdmissionPreparation.Available(hello, settings.ResultAs<DaemonSettingsSnapshot>());
        Raise(nameof(CanPrepareAdmission));
        Raise(nameof(CanRequestWitness));
        Raise(nameof(CanEditOutcome)); Raise(nameof(ImmutableNote));

        TcPreview preview;
        try
        {
            preview = await _host.OpenPreviewAsync(Entry.EntryId).ConfigureAwait(true);
        }
        catch (TcException)
        {
            // The ABI label is not interpolated into the message shown. It is
            // a fixed label and safe, but "this one can't be shown" plus the
            // promise underneath is what a contributor needs, and the label
            // would only invite them to debug the daemon.
            Fail();
            return;
        }

        _preview = preview;
        Transcript = preview.Body;

        PreviewSummary? summary = PreviewSummary.Parse(preview.SummaryJson);
        if (summary is null)
        {
            Fail();
            return;
        }

        _summary = summary;
        _witnessRequested = summary.EnvelopeDigest?.StartsWith("witness-sha256:", StringComparison.Ordinal) == true;
        Raise(nameof(CanEditOutcome)); Raise(nameof(ImmutableNote));
        FillManifest(summary);

        // An unenrolled preview is an illustration: it was built from a
        // placeholder identity, nothing was pinned, and no approval can bind
        // to it. The gate holds Contribute shut and says so.
        Gate.SetPinnedPreview(summary.Enrolled);

        RefillRecentSearches();

        IsLoading = false;
    }

    /// <summary>
    /// Runs the search over the redacted body.
    /// </summary>
    /// <remarks>
    /// On the UI thread deliberately, as the macOS sheet does: the scan is a
    /// local in-memory pass, and keeping every touch of the <c>tc_preview*</c>
    /// pointer on one thread is what the ABI header asks for. Its wrong-pointer
    /// check narrows accidental misuse to an error; it does not make concurrent
    /// use safe.
    /// </remarks>
    public void RunSearch() => RunSearch(remember: false);

    /// <summary>
    /// Runs the search, recording the term only when the contributor
    /// committed it.
    /// </summary>
    /// <remarks>
    /// Live search on every keystroke is the good part and stays. Recording
    /// there is what filled the six-slot strip with the prefixes of one word:
    /// typing "xyz" recorded "x", "xy", and "xyz". A recent search is a
    /// question the contributor asked, and they ask it by pressing Enter or
    /// the button, not by passing through a prefix on the way. The GTK shell
    /// has taken the intent as a parameter from the start; this matches it.
    /// </remarks>
    public void RunSearch(bool remember)
    {
        _searched = true;
        _searchFailed = false;
        SetOriginalOutcome(null);
        Excerpts.Clear();

        if (Needle.Length == 0 || _preview is null)
        {
            _matches = Array.Empty<int>();
            RaiseSearchResults();
            return;
        }

        try
        {
            _matches = _preview.Search(Needle);
        }
        catch (TcException)
        {
            _matches = Array.Empty<int>();
            _searchFailed = true;
            RaiseSearchResults();
            return;
        }
        catch (ObjectDisposedException)
        {
            _matches = Array.Empty<int>();
            _searchFailed = true;
            RaiseSearchResults();
            return;
        }

        foreach (string excerpt in SearchContexts.Build(Transcript, Needle, _matches))
        {
            Excerpts.Add(excerpt);
        }

        if (remember)
        {
            if (_matches.Count > 0)
            {
                Remember(Needle);
            }

            // Only on a COMMITTED search, never on a keystroke. This one
            // re-reads the whole session file on the daemon side, and it is
            // the one call in the ABI that touches pre-redaction bytes; doing
            // it per keystroke would spend that on every prefix of the word.
            _ = CheckOriginalAsync(Needle, _matches.Count);
        }

        RaiseSearchResults();
    }

    /// <summary>
    /// Asks the daemon how many times the needle appears in the session AS
    /// RECORDED, and turns the pair of counts into the tab's answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A count, never content. The redacted body is already in hand, so
    /// matches in it are known; this supplies the only other number, and
    /// <see cref="OriginalSearchOutcome.Classify"/> makes every decision about
    /// what the two together mean, including what to do when the second one
    /// cannot be had.
    /// </para>
    /// <para>
    /// The needle is re-checked against <see cref="Needle"/> before the answer
    /// lands: the contributor keeps typing while this runs, and an answer
    /// about a term they have moved on from would be attached to the wrong
    /// question.
    /// </para>
    /// </remarks>
    private async Task CheckOriginalAsync(string needle, int remaining)
    {
        int? original;
        try
        {
            original = await _host
                .SearchOriginalAsync(Entry.EntryId, needle)
                .ConfigureAwait(true);
        }
        catch (TcException)
        {
            // Null, not zero: a check that could not run must not render as a
            // clean result.
            original = null;
        }

        if (!string.Equals(needle, Needle, StringComparison.Ordinal))
        {
            return;
        }

        SetOriginalOutcome(OriginalSearchOutcome.Classify(remaining, original));
    }

    private void SetOriginalOutcome(OriginalSearchOutcome? outcome)
    {
        _originalOutcome = outcome;
        Raise(nameof(HasOriginalOutcome));
        Raise(nameof(OriginalOutcomeText));
        Raise(nameof(OriginalOutcomeIsAlarming));
        Raise(nameof(OriginalOutcomeIsCalm));
    }

    /// <summary>
    /// "Not this one": skips this session only, and says as much in its
    /// tooltip. The project keeps being offered, which is what makes dismiss
    /// and ignore different decisions rather than the same button.
    /// </summary>
    public async Task DismissAsync()
    {
        if (_deciding)
        {
            return;
        }

        SetDeciding(true);

        DaemonResponse response = await _host
            .CallAsync(DaemonProtocol.Methods.Dismiss, EntryParams())
            .ConfigureAwait(true);

        SetDeciding(false);
        Decided?.Invoke(
            response.IsError
                ? PreviewDecision.Failed("That couldn't be skipped just now. Nothing has been sent.")
                : PreviewDecision.Dismissed());
    }

    /// <summary>
    /// The one irreversible click in the product.
    ///
    /// It is behind the preview by design -- it cannot arm until one has
    /// loaded and pinned -- and it carries no keyboard accelerator: an
    /// approval one Return away from a hand resting on the keyboard is the
    /// misclick this sheet was built to make impossible.
    /// </summary>
    public async Task ContributeAsync()
    {
        // Re-checked here rather than trusted from the button's enabled state.
        // The gate is the invariant; a disabled control is only how it is
        // usually expressed.
        //
        // Draw time decides what is offered; the press decides what is sent,
        // and only the second is load-bearing. CanContribute resolves the
        // entry against the live queue, so this asks the queue as it stands
        // NOW -- a session downgraded between the last redraw and this click
        // is refused here rather than sent and turned away.
        //
        // Refuses and redraws rather than sending: QueueChanged re-reads
        // everything the footer draws, so the button disables itself and the
        // sentence beside it says why. Not a throw, and not a silent no-op.
        if (!CanContribute)
        {
            QueueChanged();
            return;
        }

        _correctionRefused = false;
        Raise(nameof(WasRefusedForACorrectionCredential));

        SetDeciding(true);

        DaemonResponse response = await _host
            .CallAsync(DaemonProtocol.Methods.Approve, ApproveParams())
            .ConfigureAwait(true);

        SetDeciding(false);

        if (response.IsError)
        {
            Decided?.Invoke(
                PreviewDecision.Failed(
                    "That couldn't be approved just now. Nothing has been sent."));
            return;
        }

        ApprovalHold? hold = ApprovalHold.Parse(response);

        // The one refusal the contributor caused and can fix. The sheet
        // stays open -- no `Decided` -- with the correction still in the
        // box, because the next thing they have to do is edit it, and it
        // says so in its own words rather than as a line in the submit
        // toast. Nothing here is derived from the response beyond the fixed
        // label, so no correction text can reach the screen a second time.
        if (hold?.WasRefusedForACorrectionCredential == true)
        {
            _correctionRefused = true;
            Raise(nameof(WasRefusedForACorrectionCredential));
            return;
        }

        Decided?.Invoke(PreviewDecision.Approved(hold));
    }

    /// <summary>
    /// Frees the preview.
    ///
    /// The native body dies with it, which is the point: the one content
    /// exemption in the ABI is bounded to an open sheet and does not outlive
    /// the window that asked for it.
    /// </summary>
    public void Dispose()
    {
        Gate.Changed -= OnGateChanged;
        _preview?.Dispose();
        _preview = null;
    }

    /// <summary>
    /// The <c>approve</c> request for this sheet's entry, carrying the
    /// verdict only if one was given.
    /// </summary>
    /// <remarks>
    /// Built through <see cref="SubmitParams"/> rather than inline, so the
    /// sheet and the queue window cannot drift into two spellings of the same
    /// call, and so the omit-versus-empty rule is checked by a test that does
    /// not need a live pipe. No selection omits <c>outcome</c> entirely:
    /// <c>null</c> and <c>""</c> are both refused as
    /// <c>outcome-invalid</c>, and a refusal approves nothing.
    /// </remarks>
    private string ApproveParams() =>
        SubmitParams.ForEntry(Entry.EntryId, SelectedVerdict, CorrectionToSend);

    /// <summary>
    /// What would actually be sent for the correction box, or null for a box
    /// that is hidden or holds nothing but whitespace.
    /// </summary>
    /// <remarks>
    /// The visibility check is deliberate rather than redundant. The box is
    /// emptied when it is hidden, so this would answer null anyway; the
    /// check states the rule -- a hidden control contributes nothing -- so
    /// it survives a future change that stops emptying on hide.
    /// </remarks>
    private string? CorrectionToSend
    {
        get
        {
            if (!IsCorrectionOffered)
            {
                return null;
            }

            string written = _correction.Trim();
            return written.Length == 0 ? null : written;
        }
    }

    /// <summary>
    /// This sheet's entry, named alone. What <c>dismiss</c> sends -- and it
    /// takes no verdict: a session that is never sent has no outcome to
    /// record, and the daemon has no parameter for one here.
    /// </summary>
    private string EntryParams() => SubmitParams.ForEntry(Entry.EntryId);

    private void FillManifest(PreviewSummary summary)
    {
        RemovedCategories.Clear();
        StillPresentCategories.Clear();
        (IReadOnlyList<RedactionSummaryRow> removed,
         IReadOnlyList<RedactionSummaryRow> stillPresent) =
            RedactionSummary.Rows(summary.Redactions, summary.RedactionsDistinct);
        foreach (RedactionSummaryRow row in removed)
        {
            RemovedCategories.Add(row);
        }

        foreach (RedactionSummaryRow row in stillPresent)
        {
            StillPresentCategories.Add(row);
        }

        Permissions.Clear();
        foreach (string scope in summary.ConsentScopes)
        {
            Permissions.Add(new PermissionRow(ConsentScopeViewModel.ScopeTitle(scope)));
        }

        Raise(nameof(WouldSendText));
        Raise(nameof(ProbabilitySummary));
        Raise(nameof(RawSessionText));
        Raise(nameof(ScrubbingFoundText));
        Raise(nameof(NothingMatched));
        Raise(nameof(SurvivingSecrets));
        Raise(nameof(HasSurvivingSecrets));
        Raise(nameof(TurnsText));
        Raise(nameof(ResidualRiskText));
        Raise(nameof(PiiLabelsText));
        Raise(nameof(HasPiiLabels));
        Raise(nameof(HasStillPresentCategories));
        Raise(nameof(NothingMatchedLine));
        Raise(nameof(RedactionBadge));
        Raise(nameof(HasRedactionBadge));
        Raise(nameof(PermissionsBadge));
    }

    private void Fail()
    {
        // Unpin first. A sheet that cannot show the bytes must not be able to
        // approve them, and this is the line that guarantees it regardless of
        // which failure got here.
        Gate.SetPinnedPreview(false);
        _summary = null;
        Transcript = string.Empty;
        IsLoading = false;
        HasFailed = true;
    }

    /// <summary>
    /// Records a committed term. Trimming, the blank guard, dedupe and the cap
    /// live in <see cref="TraceCommons.Interop.RecentSearches"/>, where they
    /// are tested, along with the reason the list is never written to disk.
    /// </summary>
    private void Remember(string term)
    {
        TraceCommons.Interop.RecentSearches.Remember(term);
        RefillRecentSearches();
    }

    private void RefillRecentSearches()
    {
        RecentSearches.Clear();
        foreach (string recent in TraceCommons.Interop.RecentSearches.Current)
        {
            RecentSearches.Add(recent);
        }
    }

    private void SetDeciding(bool deciding)
    {
        _deciding = deciding;
        Raise(nameof(CanContribute));
        Raise(nameof(CanDecide));
    }

    private void OnGateChanged()
    {
        Raise(nameof(CanContribute));
        Raise(nameof(ContributeHelp));
    }

    private void RaiseSearchResults()
    {
        Raise(nameof(SearchResultText));
        Raise(nameof(ShowNothingMatchedNote));
    }

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        Raise(name);
        return true;
    }

    private void Raise(string? name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>One scope row in the Permissions tab.</summary>
public sealed class PermissionRow
{
    public PermissionRow(string title)
    {
        Title = title;
    }

    public string Title { get; }
}

/// <summary>What the contributor decided, handed back to the queue window.</summary>
public sealed class PreviewDecision
{
    private PreviewDecision(PreviewOutcome outcome, ApprovalHold? hold, string? message)
    {
        Outcome = outcome;
        Hold = hold;
        Message = message;
    }

    public PreviewOutcome Outcome { get; }

    /// <summary>
    /// The daemon's hold on an approval, or null when it granted none. Null
    /// means no undo may be offered, which the queue window says plainly
    /// rather than drawing a button that would fail.
    /// </summary>
    public ApprovalHold? Hold { get; }

    /// <summary>A fixed sentence for a decision the daemon refused.</summary>
    public string? Message { get; }

    public static PreviewDecision Approved(ApprovalHold? hold) =>
        new(PreviewOutcome.Approved, hold, null);

    public static PreviewDecision Dismissed() => new(PreviewOutcome.Dismissed, null, null);

    public static PreviewDecision Failed(string message) =>
        new(PreviewOutcome.Failed, null, message);
}

public enum PreviewOutcome
{
    Approved,
    Dismissed,
    Failed,
}
