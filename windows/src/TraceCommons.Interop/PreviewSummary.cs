using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TraceCommons.Interop;

/// <summary>
/// The <c>summary_json</c> half of an open preview: what would be sent, how
/// big it is, and what scrubbing found.
///
/// Mirrors <c>PreviewSummary</c> in
/// <c>crates/trace-commons-contributor/src/daemon/preview.rs</c>. Almost every
/// field here is a count, a size, or a fixed label, and the contract
/// guarantees the redaction and PII maps never carry matched text.
/// <see cref="OpeningPrompt"/> is the exception: that one IS redacted trace
/// content and carries the same rule <see cref="TcPreview.Body"/> does --
/// display it, never log it.
/// </summary>
public sealed class PreviewSummary
{
    [JsonPropertyName("envelope_digest")] public string? EnvelopeDigest { get; set; }
    [JsonPropertyName("token_distribution_summary")] public string? ProbabilitySummary { get; init; }
    [JsonPropertyName("would_send_bytes")]
    public long WouldSendBytes { get; set; }

    [JsonPropertyName("raw_session_bytes")]
    public long RawSessionBytes { get; set; }

    [JsonPropertyName("event_count")]
    public long EventCount { get; set; }

    /// <summary>
    /// The redacted opening prompt. Trace content: display only, never a log
    /// line.
    /// </summary>
    [JsonPropertyName("opening_prompt")]
    public string OpeningPrompt { get; set; } = string.Empty;

    /// <summary>Category label to count. Never the matched text.</summary>
    [JsonPropertyName("redactions")]
    public Dictionary<string, int> Redactions { get; set; } = new();

    /// <summary>
    /// The same category labels, counting DISTINCT VALUES rather than
    /// occurrences.
    /// </summary>
    /// <remarks>
    /// The redactor mints one placeholder per distinct value and reuses it,
    /// so one path referenced two hundred times is two hundred occurrences
    /// and one value. <c>185 local path</c> is the first number;
    /// <c>185 local path (12 distinct)</c> is the one a person is actually
    /// trying to estimate risk from.
    ///
    /// Empty against a daemon predating the field, which reads as "no
    /// distinct figure to show" and never as zero distinct values.
    /// </remarks>
    [JsonPropertyName("redactions_distinct")]
    public Dictionary<string, int> RedactionsDistinct { get; set; } = new();

    [JsonPropertyName("pii_labels_present")]
    public List<string> PiiLabelsPresent { get; set; } = new();

    /// <summary>
    /// The scopes this device <em>requests</em>. The issuer can narrow them
    /// and never widen them, so this is an upper bound -- which is why the
    /// Permissions tab says what this upload asks for rather than what it
    /// will be sent as.
    /// </summary>
    [JsonPropertyName("consent_scopes")]
    public List<string> ConsentScopes { get; set; } = new();

    [JsonPropertyName("residual_risk")]
    public string ResidualRisk { get; set; } = string.Empty;

    /// <summary>
    /// False when the preview was built from the placeholder identity a
    /// device that has not enrolled carries.
    ///
    /// This is a hard gate on approving rather than a cosmetic flag: nothing
    /// was pinned, so there is no envelope for an approval to bind to. The
    /// sheet keeps Contribute off and says why.
    /// </summary>
    [JsonPropertyName("enrolled")]
    public bool Enrolled { get; set; }

    /// <summary>
    /// Parses a summary, or returns null when it cannot be read.
    ///
    /// Null rather than an exception, because the sheet turns null into "this
    /// one can't be shown" with Contribute off. A summary that cannot be
    /// parsed describes a session the app cannot describe either, and a
    /// session the app cannot describe must not be approvable -- so the
    /// failure has to arrive at the gate rather than unwind past it.
    /// </summary>
    public static PreviewSummary? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<PreviewSummary>(
                json,
                DaemonProtocol.SerializerOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Occurrences removed. Never the whole map: see
    /// <see cref="RedactionLabels"/>, which is why this goes through
    /// <see cref="RedactionLabels.Total"/> rather than summing the values.
    /// </summary>
    public int TotalRedactions => RedactionLabels.Total(Redactions);

    /// <summary>
    /// "scrubbed: 12 secrets, 4 tokens, 31 paths" -- the shared spec's
    /// redaction receipt, largest category first, ties broken alphabetically
    /// so the same summary always renders the same line.
    /// </summary>
    public string RedactionReceipt =>
        "scrubbed: " + (TotalRedactions == 0
            ? RedactionLabels.NothingMatched
            : string.Join(", ", Categories));

    /// <summary>
    /// The same figures under the header's "Scrubbing found" label, which is
    /// the number a contributor reads the transcript against.
    /// </summary>
    public string ScrubbingFound => RedactionLabels.Line(Redactions, RedactionsDistinct);

    /// <summary>
    /// Secrets the scan FOUND and did not remove, or an empty string when
    /// there are none.
    /// </summary>
    /// <remarks>
    /// Excluding survivors from the figures above is only half the fix:
    /// filtering one out and then saying nothing would trade a wrong
    /// statement for silence about a secret that is still in the payload.
    /// See <see cref="RedactionLabels"/>.
    /// </remarks>
    public string SurvivingSecrets => RedactionLabels.SurvivorLine(Redactions);

    /// <summary>Whether this session left a found secret in the payload.</summary>
    public bool HasSurvivingSecrets => RedactionLabels.SurvivorTotal(Redactions) > 0;

    /// <summary>
    /// Removals only, one phrase per category, largest first. Survivors are
    /// excluded because these render under headings that say "removed" --
    /// see <see cref="RedactionLabels"/>.
    /// </summary>
    private IReadOnlyList<string> Categories =>
        RedactionLabels.Categories(Redactions, RedactionsDistinct);
}
