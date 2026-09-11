using System;
using System.Text.Json.Serialization;

namespace TraceCommons.Interop;

/// <summary>
/// The redaction-witness card's fixed words, read from the Rust rather than
/// kept here.
///
/// Every property is filled from <c>tc_witness_copy</c>'s payload and none has
/// a word of this shell's in it. The GTK shell reads the same strings from the
/// same Rust module without going through the C ABI at all, so a word invented
/// here would be a word two of the three shells do not print -- on a surface
/// whose whole subject is whether a raw session leaves the machine.
///
/// <see cref="CertificateMeans"/> is the sentence that says what a certificate
/// does and does not establish. It is carried rather than summarised: no shell
/// may shorten it, and none may add the word "attested" beside it.
/// </summary>
public sealed record WitnessCopy
{
    [JsonPropertyName("wallet")] public WalletCopy? Wallet { get; init; }
    [JsonPropertyName("admission")] public AdmissionCopy? Admission { get; init; }
    [JsonPropertyName("review")] public WitnessReviewCopy? Review { get; init; }
    [JsonPropertyName("onboarding")] public FirstContributionCopy? Onboarding { get; init; }
    [JsonPropertyName("heading")] public string Heading { get; init; } = "";
    [JsonPropertyName("intro")] public string Intro { get; init; } = "";

    /// <summary>What a certificate records, and what it does not claim.</summary>
    [JsonPropertyName("certificate_means")] public string CertificateMeans { get; init; } = "";

    /// <summary>Why the pin is a list rather than a value.</summary>
    [JsonPropertyName("measurements_note")] public string MeasurementsNote { get; init; } = "";

    [JsonPropertyName("url_title")] public string UrlTitle { get; init; } = "";

    [JsonPropertyName("signing_address_title")]
    public string SigningAddressTitle { get; init; } = "";

    [JsonPropertyName("measurements_title")] public string MeasurementsTitle { get; init; } = "";
    [JsonPropertyName("configure")] public string Configure { get; init; } = "";
    [JsonPropertyName("clear")] public string Clear { get; init; } = "";

    /// <summary>
    /// What clearing actually does. Not "off": redaction still happens, on
    /// this machine, and rendering the clear action without this sentence
    /// beside it would read as switching redaction off.
    /// </summary>
    [JsonPropertyName("clear_note")] public string ClearNote { get; init; } = "";

    [JsonPropertyName("applies_at_once")] public string AppliesAtOnce { get; init; } = "";

    [JsonPropertyName("token_heading")] public string TokenHeading { get; init; } = "";
    [JsonPropertyName("token_disclosure")] public string TokenDisclosure { get; init; } = "";
    [JsonPropertyName("token_capture_note")] public string TokenCaptureNote { get; init; } = "";
    [JsonPropertyName("token_scope_note")] public string TokenScopeNote { get; init; } = "";
    [JsonPropertyName("token_enable")] public string TokenEnable { get; init; } = "";
    [JsonPropertyName("token_disable")] public string TokenDisable { get; init; } = "";
    [JsonPropertyName("token_confirm")] public string TokenConfirm { get; init; } = "";
    [JsonPropertyName("token_cancel")] public string TokenCancel { get; init; } = "";
    [JsonPropertyName("token_enabled")] public string TokenEnabled { get; init; } = "";
    [JsonPropertyName("token_disabled")] public string TokenDisabled { get; init; } = "";
    [JsonPropertyName("token_save_failed")] public string TokenSaveFailed { get; init; } = "";
    [JsonPropertyName("inference_heading")] public string InferenceHeading { get; init; } = "";
    [JsonPropertyName("inference_disclosure")] public string InferenceDisclosure { get; init; } = "";
    [JsonPropertyName("inference_capture_note")] public string InferenceCaptureNote { get; init; } = "";
    [JsonPropertyName("inference_scope_note")] public string InferenceScopeNote { get; init; } = "";
    [JsonPropertyName("inference_enable")] public string InferenceEnable { get; init; } = "";
    [JsonPropertyName("inference_disable")] public string InferenceDisable { get; init; } = "";
    [JsonPropertyName("inference_confirm")] public string InferenceConfirm { get; init; } = "";
    [JsonPropertyName("inference_cancel")] public string InferenceCancel { get; init; } = "";
    [JsonPropertyName("inference_enabled")] public string InferenceEnabled { get; init; } = "";
    [JsonPropertyName("inference_disabled")] public string InferenceDisabled { get; init; } = "";
    [JsonPropertyName("inference_save_failed")] public string InferenceSaveFailed { get; init; } = "";

    /// <summary>
    /// Every word the payload carries, for the whole-or-nothing check.
    ///
    /// A field the Rust stopped exporting deserialises to the empty string and
    /// would render as a blank line under a heading about privacy. The parse
    /// refuses the whole payload instead of showing a partly-filled card.
    /// </summary>
    public string[] Words => new[]
    {
        Heading,
        Intro,
        CertificateMeans,
        MeasurementsNote,
        UrlTitle,
        SigningAddressTitle,
        MeasurementsTitle,
        Configure,
        Clear,
        ClearNote,
        AppliesAtOnce,
        InferenceHeading,
        InferenceDisclosure,
        InferenceCaptureNote,
        InferenceScopeNote,
        InferenceEnable,
        InferenceDisable,
        InferenceConfirm,
        InferenceCancel,
        InferenceEnabled,
        InferenceDisabled,
        InferenceSaveFailed,

    };
}

/// <summary>
/// <c>tc_witness_status_json</c>'s answer.
///
/// <see cref="StateCode"/> is the whole verdict and the only thing that may be
/// branched on. DO NOT DERIVE A STATE FROM <see cref="Url"/> BEING NON-NULL:
/// that is the boolean this surface refuses to hand anybody, spelled
/// differently, and its two yes-answers are opposites.
/// </summary>
public sealed record WitnessStatus
{
    /// <summary>
    /// The state as a snake_case name. Carried for completeness; nothing
    /// renders it and nothing branches on it -- <see cref="StateCode"/> is
    /// what the sentence and the tone are both taken from.
    /// </summary>
    [JsonPropertyName("state")] public string State { get; init; } = "";

    /// <summary>
    /// The state as a <c>TC_WITNESS_STATE_*</c> value.
    /// </summary>
    /// <remarks>
    /// Nullable deliberately. A non-nullable int would bind an absent key to
    /// the default zero, and zero is ABSENT -- so a payload from a build that
    /// renamed the key would report a witness-free machine. The parse rejects
    /// the payload instead.
    /// </remarks>
    [JsonPropertyName("state_code")] public int? StateCodeOrNull { get; init; }

    /// <summary>The state code, once the parse has established there is one.</summary>
    public int StateCode => StateCodeOrNull ?? 0;

    /// <summary>
    /// The fixed operator label for a refusing state, or null. NOT WORDING:
    /// it is never rendered. The sentence a contributor reads comes from
    /// <c>tc_witness_state_line</c>.
    /// </summary>
    [JsonPropertyName("refusal")] public string? Refusal { get; init; }

    /// <summary>
    /// The witness address, verbatim.
    /// </summary>
    /// <remarks>
    /// One of the ABI's three named exemptions from the no-identifiers rule.
    /// A screen that will not show what it is asking a contributor to trust
    /// with their raw session is not a settings screen. It may be rendered; it
    /// may not be logged or persisted anywhere else.
    /// </remarks>
    [JsonPropertyName("url")] public string? Url { get; init; }

    /// <summary>The witness signing address, verbatim, under the same rule as <see cref="Url"/>.</summary>
    [JsonPropertyName("signing_address")] public string? SigningAddress { get; init; }

    /// <summary>
    /// How many measurement sets are pinned. Always
    /// <see cref="PinnedMeasurements"/>'s length; the two can never disagree.
    /// </summary>
    [JsonPropertyName("pinned_measurement_count")] public int PinnedMeasurementCount { get; init; }

    /// <summary>
    /// The sentence for that count, or null where there is no witness to
    /// count for.
    /// </summary>
    /// <remarks>
    /// Null on absent, not-enrolled and unreadable. A shell must render this
    /// or nothing: a bare numeral on a privacy surface is a shell inventing
    /// wording by omission, and a count of the pins on a witness that does not
    /// exist is not a shorter sentence but a wrong one.
    /// </remarks>
    [JsonPropertyName("pinned_measurement_line")] public string? PinnedMeasurementLine { get; init; }

    /// <summary>
    /// The pinned measurement sets themselves, VERBATIM, in stored order.
    /// </summary>
    /// <remarks>
    /// Exactly what <c>tc_witness_configure</c> takes: pre-fill the editor
    /// from it and hand it straight back. NOT REFORMATTED ON THE WAY THROUGH
    /// -- a shell that re-emits a pin from a parsed form is a shell that can
    /// re-emit it wrongly, and it would rewrite a pin nobody touched.
    ///
    /// A stored entry this build cannot parse comes back as it is stored
    /// rather than omitted, so a contributor can see the typo instead of
    /// having their work deleted the next time they save. The read is
    /// permissive; handing that same entry back to configure is still
    /// refused.
    /// </remarks>
    [JsonPropertyName("pinned_measurements")] public string[] PinnedMeasurements { get; init; } =
        Array.Empty<string>();
}

/// <summary>
/// A read of the witness configuration: the status, or the fixed label the ABI
/// declined with.
/// </summary>
/// <remarks>
/// A null <see cref="Status"/> is NEVER "no witness". No witness is a
/// successful read reporting the absent state. This is an unenrolled device or
/// a config that could not be read, and the second of those is a refusal.
/// </remarks>
public sealed record WitnessReadResult(WitnessStatus? Status, string? Error);

/// <summary>
/// A write to the witness configuration: the ABI's return value, and the fixed
/// label it failed with.
/// </summary>
/// <remarks>
/// <see cref="Error"/> is an operator label and not a sentence. It is carried
/// so a caller can tell a failure from a success without reading the state
/// back twice; it is never rendered.
/// </remarks>
public sealed record WitnessWriteResult(int Code, string? Error);

public sealed record WitnessReviewCopy
{
    [JsonPropertyName("heading")] public string Heading { get; init; } = "";
    [JsonPropertyName("disclosure")] public string Disclosure { get; init; } = "";
    [JsonPropertyName("action")] public string Action { get; init; } = "";
    [JsonPropertyName("confirm")] public string Confirm { get; init; } = "";
    [JsonPropertyName("cancel")] public string Cancel { get; init; } = "";
    [JsonPropertyName("working")] public string Working { get; init; } = "";
    [JsonPropertyName("failed")] public string Failed { get; init; } = "";
    [JsonPropertyName("immutable")] public string Immutable { get; init; } = "";
    public bool IsComplete => !string.IsNullOrWhiteSpace(Heading) && !string.IsNullOrWhiteSpace(Disclosure)
        && !string.IsNullOrWhiteSpace(Action) && !string.IsNullOrWhiteSpace(Confirm)
        && !string.IsNullOrWhiteSpace(Cancel) && !string.IsNullOrWhiteSpace(Working)
        && !string.IsNullOrWhiteSpace(Failed) && !string.IsNullOrWhiteSpace(Immutable);
}

public sealed record FirstContributionCopy
{
    [JsonPropertyName("heading")] public string Heading { get; init; } = "";
    [JsonPropertyName("start")] public string Start { get; init; } = "";
    [JsonPropertyName("review")] public string Review { get; init; } = "";
    [JsonPropertyName("follow_up")] public string FollowUp { get; init; } = "";
    [JsonPropertyName("agent_setup")] public string AgentSetup { get; init; } = "";
}

public sealed record WalletCopy
{
    [JsonPropertyName("heading")] public string Heading { get; init; } = "";
    [JsonPropertyName("disclosure")] public string Disclosure { get; init; } = "";
    [JsonPropertyName("commons")] public string Commons { get; init; } = "";
    [JsonPropertyName("account")] public string Account { get; init; } = "";
    [JsonPropertyName("check")] public string Check { get; init; } = "";
    [JsonPropertyName("start")] public string Start { get; init; } = "";
    [JsonPropertyName("cancel")] public string Cancel { get; init; } = "";
    [JsonPropertyName("available")] public string Available { get; init; } = "";
    [JsonPropertyName("unavailable")] public string Unavailable { get; init; } = "";
    [JsonPropertyName("address_refused")] public string AddressRefused { get; init; } = "";
    [JsonPropertyName("unreachable")] public string Unreachable { get; init; } = "";
    [JsonPropertyName("opening")] public string Opening { get; init; } = "";
    [JsonPropertyName("waiting")] public string Waiting { get; init; } = "";
    [JsonPropertyName("failed")] public string Failed { get; init; } = "";
    [JsonPropertyName("cancelled")] public string Cancelled { get; init; } = "";
    [JsonPropertyName("refused_glyph")] public string RefusedGlyph { get; init; } = "";
    [JsonPropertyName("refused_tone")] public string RefusedTone { get; init; } = "";
}
public sealed record AdmissionCopy
{
    [JsonPropertyName("heading")] public string Heading { get; init; } = "";
    [JsonPropertyName("disclosure")] public string Disclosure { get; init; } = "";
    [JsonPropertyName("prerequisite")] public string Prerequisite { get; init; } = "";
    [JsonPropertyName("backend")] public string Backend { get; init; } = "";
    [JsonPropertyName("confirm")] public string Confirm { get; init; } = "";
    [JsonPropertyName("cancel")] public string Cancel { get; init; } = "";
    [JsonPropertyName("permission")] public string Permission { get; init; } = "";
    [JsonPropertyName("working")] public string Working { get; init; } = "";
    [JsonPropertyName("ready")] public string Ready { get; init; } = "";
    [JsonPropertyName("failed")] public string Failed { get; init; } = "";
    [JsonPropertyName("failed_receipt_endpoint")] public string FailedReceiptEndpoint { get; init; } = "";
    [JsonPropertyName("failed_receipt_endpoint_invalid")] public string FailedReceiptEndpointInvalid { get; init; } = "";
    [JsonPropertyName("failed_permission")] public string FailedPermission { get; init; } = "";
    [JsonPropertyName("failed_not_enrolled")] public string FailedNotEnrolled { get; init; } = "";
    [JsonPropertyName("failed_session_unreadable")] public string FailedSessionUnreadable { get; init; } = "";
    [JsonPropertyName("failed_source_unsupported")] public string FailedSourceUnsupported { get; init; } = "";
    [JsonPropertyName("failed_proxy_missing")] public string FailedProxyMissing { get; init; } = "";
    [JsonPropertyName("failed_proxy_untrusted")] public string FailedProxyUntrusted { get; init; } = "";
    [JsonPropertyName("failed_hosts_untrusted")] public string FailedHostsUntrusted { get; init; } = "";
    [JsonPropertyName("failed_backend")] public string FailedBackend { get; init; } = "";
    [JsonPropertyName("failed_try_again")] public string FailedTryAgain { get; init; } = "";
    [JsonPropertyName("refused_glyph")] public string RefusedGlyph { get; init; } = "";
    [JsonPropertyName("refused_tone")] public string RefusedTone { get; init; } = "";
}
