using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace TraceCommons.Interop;

/// <summary>
/// The <c>list_history</c> payload.
/// </summary>
public sealed class HistoryList
{
    [JsonPropertyName("history")]
    public List<HistoryRecord> History { get; set; } = new();
}

/// <summary>
/// One contribution record, mirroring <c>HistoryRecord</c> in
/// <c>crates/trace-commons-contributor/src/daemon/history.rs</c>.
///
/// Note what is absent, and why the Rust type says so at the top of its own
/// file: history records carry <b>no local path</b>. This is the surface most
/// likely to be screenshotted, exported, or shared. A field added here
/// because it was convenient is a field that ends up in a screenshot.
/// </summary>
public sealed class HistoryRecord
{
    [JsonPropertyName("submission_id")]
    public string SubmissionId { get; set; } = string.Empty;

    [JsonPropertyName("submitted_at")]
    public string? SubmittedAt { get; set; }

    [JsonPropertyName("project_label")]
    public string ProjectLabel { get; set; } = string.Empty;

    /// <summary>
    /// The opaque project identifier, for grouping history by folder.
    /// </summary>
    /// <remarks>
    /// Admissible in this sink by construction rather than by policy:
    /// <c>project_id_for</c> is a one-way SHA-256 prefix that leaks no path
    /// component, which is the property it was built for. A path is not
    /// admissible here and is deliberately absent -- see the type's own
    /// remarks.
    ///
    /// Grouping on <see cref="ProjectLabel"/> is not an option: a label is a
    /// display name, is not unique across two projects, and grouping on it
    /// would merge them.
    ///
    /// Empty for a record written before the field existed. Those records
    /// cannot be backfilled -- nothing retained the key they were minted
    /// from -- so they group by label instead. See <see cref="HistoryFolders"/>.
    /// </remarks>
    [JsonPropertyName("project_id")]
    public string ProjectId { get; set; } = string.Empty;

    [JsonPropertyName("source")]
    public string? Source { get; set; }

    [JsonPropertyName("session_hash")]
    public string? SessionHash { get; set; }

    /// <summary>
    /// One of <c>submitted</c>, <c>accepted</c>, <c>quarantined</c>, or the
    /// locally stamped <c>withdrawn</c>. Any other value is a status this
    /// build has no stable name for and degrades to "waiting to be scored".
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("consent_scopes")]
    public List<string> ConsentScopes { get; set; } = new();

    [JsonPropertyName("credit_points_pending")]
    public float CreditPointsPending { get; set; }

    /// <summary>
    /// The settled figure, absent while the trace is still being scored.
    /// </summary>
    [JsonPropertyName("credit_points_final")]
    public float? CreditPointsFinal { get; set; }

    /// <summary>
    /// The server's own prose about this submission, e.g. why it was held.
    ///
    /// Rendered verbatim. "Held because a passage looked like a personal
    /// address" is enormously better than a status word, and it is the
    /// server's sentence to write, not this window's to paraphrase.
    /// </summary>
    [JsonPropertyName("explanations")]
    public List<string> Explanations { get; set; } = new();

    [JsonPropertyName("last_refreshed_at")]
    public string? LastRefreshedAt { get; set; }

    [JsonPropertyName("withdrawn_at")]
    public string? WithdrawnAt { get; set; }
}

/// <summary>Counts by status over one window.</summary>
public sealed class HistoryCounts
{
    [JsonPropertyName("submitted")]
    public int Submitted { get; set; }

    [JsonPropertyName("accepted")]
    public int Accepted { get; set; }

    [JsonPropertyName("quarantined")]
    public int Quarantined { get; set; }

    /// <summary>
    /// Statuses this client has no stable name for. Not a failure bucket, and
    /// never drawn as one.
    /// </summary>
    [JsonPropertyName("other")]
    public int Other { get; set; }
}

/// <summary>
/// The <c>history_rollup</c> payload.
/// </summary>
public sealed class HistoryRollup
{
    [JsonPropertyName("week")]
    public HistoryCounts Week { get; set; } = new();

    [JsonPropertyName("month")]
    public HistoryCounts Month { get; set; } = new();

    [JsonPropertyName("all_time")]
    public HistoryCounts AllTime { get; set; } = new();

    [JsonPropertyName("credit_pending")]
    public float CreditPending { get; set; }

    [JsonPropertyName("credit_final")]
    public float CreditFinal { get; set; }

    /// <summary>
    /// Reported separately by the contract and <b>must be rendered
    /// separately</b>. Quarantine means held for operator privacy review, not
    /// rejected; a contributor who sees it grouped with failures reads it as
    /// rejection.
    /// </summary>
    [JsonPropertyName("quarantined")]
    public int Quarantined { get; set; }

    /// <summary>
    /// Null when history has never been refreshed from the server. Show
    /// staleness rather than presenting a stale cache as current.
    /// </summary>
    [JsonPropertyName("last_refreshed_at")]
    public string? LastRefreshedAt { get; set; }

    /// <summary>
    /// This contributor's row on the public roster, present only while they
    /// have a standing on it.
    /// </summary>
    /// <remarks>
    /// <b>Absent means no standing, and absent is not null.</b> The contract
    /// omits the object entirely rather than sending it zero-filled, in every
    /// case where there is nothing to say -- no published handle, no served
    /// snapshot, not on the roster, or a count that cannot be represented. A
    /// client renders all of those identically by drawing no community
    /// section at all, which is what a null here means.
    /// </remarks>
    [JsonPropertyName("community")]
    public CommunityStanding? Community { get; set; }

    /// <summary>
    /// How many traces are sent and waiting to hear back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the <c>submitted</c> bucket, straight through. It used to be
    /// <c>submitted - (accepted + quarantined)</c>, which read
    /// <c>submitted</c> as a running total when it is one bucket of four --
    /// so the arithmetic was permanently negative, saturated to zero, and
    /// the card said nothing was ever in flight even while a dozen traces
    /// genuinely were.
    /// </para>
    /// <para>
    /// Still floored at zero: the figure comes from a cache, and a negative
    /// count rendered as "-1 waiting" would be this screen's first visibly
    /// wrong number.
    /// </para>
    /// </remarks>
    public int WaitingToBeScored => Math.Max(0, AllTime.Submitted);

    /// <summary>
    /// Everything ever contributed, across all four buckets.
    /// </summary>
    public int TotalContributed =>
        AllTime.Submitted + AllTime.Accepted + AllTime.Quarantined + AllTime.Other;
}

/// <summary>
/// The additive <c>community</c> object on <c>history_rollup</c>: this
/// contributor's own row on the roster the server serves publicly.
/// </summary>
public sealed class CommunityStanding
{
    /// <summary>Null is a dash, never <c>#0</c>.</summary>
    [JsonPropertyName("rank")]
    public int? Rank { get; set; }

    [JsonPropertyName("novelty_credit")]
    public double NoveltyCredit { get; set; }

    [JsonPropertyName("accepted_in_window")]
    public int AcceptedInWindow { get; set; }

    /// <summary>A decimal in 0..=1, not a percentage. Null is a dash.</summary>
    [JsonPropertyName("accept_rate")]
    public double? AcceptRate { get; set; }

    [JsonPropertyName("window_label")]
    public string? WindowLabel { get; set; }

    [JsonPropertyName("public_since")]
    public string? PublicSince { get; set; }

    [JsonPropertyName("snapshot_at")]
    public string? SnapshotAt { get; set; }

    /// <summary>
    /// Whether corpus-wide aggregates were withheld. When true, say so in
    /// words rather than drawing an empty chart.
    /// </summary>
    [JsonPropertyName("analytics_withheld")]
    public bool AnalyticsWithheld { get; set; }
}

/// <summary>
/// The <c>queue_outcome_counts</c> payload: a count by <c>reason_label</c>
/// across every entry currently on the queue in any state.
/// </summary>
/// <remarks>
/// This does <b>not</b> cover sessions that were never queued. The contract
/// names the method as it does precisely to leave room for a future one that
/// can, and says not to present this as answering "I finished a session, why
/// is nothing pending?".
/// </remarks>
public sealed class QueueOutcomeCounts
{
    [JsonPropertyName("reasons")]
    public Dictionary<string, int> Reasons { get; set; } = new();
}

/// <summary>
/// The <c>withdraw</c> payload. <see cref="DistributionReach"/> is the tier
/// the server actually applied, computed during the call from live export
/// membership -- which is why no client can state it beforehand.
/// </summary>
public sealed class WithdrawResult
{
    [JsonPropertyName("token_deletion_note")]
    public string? TokenDeletionNote { get; set; }
    [JsonPropertyName("withdrawn")]
    public bool Withdrawn { get; set; }

    [JsonPropertyName("distribution_reach")]
    public string? DistributionReach { get; set; }
}
