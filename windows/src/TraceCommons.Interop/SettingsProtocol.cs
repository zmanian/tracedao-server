using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TraceCommons.Interop;

/// <summary><c>consent_options</c>: daemon-owned names and descriptions.</summary>
public sealed class ConsentOptionsPayload
{
    [JsonPropertyName("scopes")]
    public List<ConsentOption> Scopes { get; set; } = new();
}

public sealed class ConsentOption
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("always_on")]
    public bool AlwaysOn { get; set; }

    [JsonPropertyName("grants_data_use")]
    public bool GrantsDataUse { get; set; }
}

/// <summary>
/// Privacy-safe <c>get_settings</c> projection. Paths and credentials are
/// represented only by configured-or-not booleans.
/// </summary>
public sealed class DaemonSettingsSnapshot
{
    [JsonPropertyName("quiescence_secs")]
    public ulong QuiescenceSeconds { get; set; }

    [JsonPropertyName("digest_interval_secs")]
    public ulong DigestIntervalSeconds { get; set; }

    [JsonPropertyName("approval_hold_secs")]
    public ulong ApprovalHoldSeconds { get; set; }

    [JsonPropertyName("queue_ttl_days")]
    public long QueueTtlDays { get; set; }

    [JsonPropertyName("local_notifications")]
    public bool LocalNotifications { get; set; }

    [JsonPropertyName("claude_root_configured")]
    public bool ClaudeRootConfigured { get; set; }

    [JsonPropertyName("codex_root_configured")]
    public bool CodexRootConfigured { get; set; }

    [JsonPropertyName("near_ai_configured")]
    public bool NearAiConfigured { get; set; }

    [JsonPropertyName("admission_evidence_required")]
    public bool? AdmissionEvidenceRequired { get; set; }

    [JsonPropertyName("token_distributions_contribution")] public bool? ProbabilityContributionAllowed { get; init; }
    [JsonPropertyName("token_storage")] public ProbabilityStorageView? ProbabilityStorage { get; set; }
    public bool ProbabilityContributionEnabled => ProbabilityContributionAllowed == true;
    [JsonPropertyName("ironwire_attested_bodies")]
    public bool? IronwireAttestedBodies { get; set; }
    public bool InferenceEvidenceEnabled => IronwireAttestedBodies == true;

    /// <summary>
    /// <c>watch</c>, <c>off</c> or <c>unset</c>, for the Claude Code source.
    /// </summary>
    /// <remarks>
    /// <see cref="ClaudeRootConfigured"/> cannot carry the distinction the
    /// routing surface needs: it is false both for a source pointed at the
    /// conventional location and for one the contributor said they do not
    /// use, and only the second of those reads as an unused tool.
    /// </remarks>
    [JsonPropertyName("claude_source_mode")]
    public string ClaudeSourceMode { get; set; } = string.Empty;

    [JsonPropertyName("codex_source_mode")]
    public string CodexSourceMode { get; set; } = string.Empty;

    /// <summary>
    /// The Gemini CLI source. There is deliberately no
    /// <c>gemini_root_configured</c> beside it: the <c>*_root_configured</c>
    /// pair exists for shells written before the modes did, and none of them
    /// knows about this source.
    /// </summary>
    [JsonPropertyName("gemini_source_mode")]
    public string GeminiSourceMode { get; set; } = string.Empty;

    /// <summary>
    /// The Cline source. Optional exactly as Gemini CLI is, and likewise
    /// without a <c>*_root_configured</c> twin.
    /// </summary>
    [JsonPropertyName("cline_source_mode")]
    public string ClineSourceMode { get; set; } = string.Empty;

    /// <summary>
    /// The local proxy declaration as the daemon holds it. Absent means off:
    /// there is no conventional fallback for a local service, so unlike a
    /// source root there is no third state.
    /// </summary>
    [JsonPropertyName("ironwire")]
    public RoutingDeclarationSnapshot? Routing { get; set; }

    /// <summary>Whether IronWire is declared on this machine.</summary>
    public bool RoutingDeclared =>
        string.Equals(Routing?.Mode, "watch", System.StringComparison.Ordinal);

    /// <summary>
    /// Whether this daemon was asked to answer model calls itself. What was
    /// ASKED FOR; what happened is <see cref="PrivateInferenceState"/> beside
    /// it, and the two differ exactly when the listener refused to start.
    /// </summary>
    [JsonPropertyName("private_inference")]
    public bool? PrivateInference { get; set; }

    /// <summary>Whether that switch is on.</summary>
    public bool PrivateInferenceOn => PrivateInference == true;

    /// <summary>
    /// Whether the contributor has already been asked about that switch.
    /// Absent on a daemon that predates the key, which reads as unanswered --
    /// and is what makes the offer appear once after an upgrade.
    /// </summary>
    [JsonPropertyName("private_inference_offer_seen")]
    public bool? PrivateInferenceOfferSeen { get; set; }

    /// <summary>Whether the question has been put.</summary>
    public bool PrivateInferenceAnswered => PrivateInferenceOfferSeen == true;

    /// <summary>
    /// What the listener is actually doing.
    ///
    /// Named <c>Report</c> rather than <c>State</c> so it cannot shadow the
    /// <see cref="PrivateInferenceState"/> type at a call site that needs
    /// both -- which is every call site, since the type is what reads it.
    /// </summary>
    [JsonPropertyName("private_inference_state")]
    public PrivateInferenceStateSnapshot? PrivateInferenceReport { get; set; }
}

/// <summary>
/// <c>private_inference_state</c>, as <c>get_settings</c>, <c>set_settings</c>
/// and <c>status</c> all report it.
///
/// Carries the daemon's own label string. No path, no token, no account: the
/// port is a loopback number this shell already knows how to print.
/// </summary>
public sealed class PrivateInferenceStateSnapshot
{
    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;

    [JsonPropertyName("port")]
    public ushort? Port { get; set; }
}

public enum BehaviorSetting
{
    QuiescenceMinutes,
    ApprovalHoldSeconds,
    DigestHours,
}

/// <summary>Serializes exactly one <c>set_settings</c> key per user edit.</summary>
public static class BehaviorSettingsRequest
{
    public static string Serialize(BehaviorSetting setting, double displayedValue)
    {
        if (!double.IsFinite(displayedValue) || displayedValue < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(displayedValue));
        }

        double seconds = setting switch
        {
            BehaviorSetting.QuiescenceMinutes => displayedValue * 60,
            BehaviorSetting.ApprovalHoldSeconds => displayedValue,
            BehaviorSetting.DigestHours => displayedValue * 3600,
            _ => throw new ArgumentOutOfRangeException(nameof(setting)),
        };
        ulong wholeSeconds = checked((ulong)Math.Round(seconds, MidpointRounding.AwayFromZero));
        string key = setting switch
        {
            BehaviorSetting.QuiescenceMinutes => "quiescence_secs",
            BehaviorSetting.ApprovalHoldSeconds => "approval_hold_secs",
            BehaviorSetting.DigestHours => "digest_interval_secs",
            _ => throw new ArgumentOutOfRangeException(nameof(setting)),
        };

        return JsonSerializer.Serialize(new Dictionary<string, ulong> { [key] = wholeSeconds });
    }
}

/// <summary>
/// <c>list_projects</c>. Carries a display path and nothing else path-shaped:
/// see <see cref="ProjectSetting.ProjectPath"/> for the one relaxation and
/// the rule it is bounded by.
/// </summary>
public sealed class ProjectSettingsPayload
{
    [JsonPropertyName("projects")]
    public List<ProjectSetting> Projects { get; set; } = new();
}

public sealed class ProjectSetting
{
    [JsonPropertyName("project_id")]
    public string ProjectId { get; set; } = string.Empty;

    [JsonPropertyName("project_label")]
    public string ProjectLabel { get; set; } = string.Empty;

    /// <summary>
    /// The project's folder, <c>~</c>-abbreviated, for display only.
    /// </summary>
    /// <remarks>
    /// Same field, same rule, same reasoning as
    /// <see cref="QueueEntry.ProjectPath"/>: it may be rendered, and it may
    /// not be logged, audited, notified, or persisted to history. This is
    /// where history's folder paths are resolved from, by matching a
    /// record's <see cref="HistoryRecord.ProjectId"/> against these rows.
    ///
    /// Empty against a daemon predating the field.
    /// </remarks>
    [JsonPropertyName("project_path")]
    public string ProjectPath { get; set; } = string.Empty;

    /// <summary>How many sessions of this project are waiting. Always sent.</summary>
    [JsonPropertyName("pending_count")]
    public int PendingCount { get; set; }

    /// <summary>
    /// How many of them a group submit would actually send.
    /// </summary>
    /// <remarks>
    /// <b>NULL MEANS THE KEY WAS ABSENT, AND ABSENT IS NOT ZERO.</b> The
    /// daemon omits it when eligibility does not apply -- an invited
    /// contributor has no "3 of 7" to be told about, and
    /// <see cref="PendingCount"/> alone is their answer. Reading absent as
    /// zero would take the group control away from every project they have,
    /// which is the failure that silently stops people submitting; reading
    /// zero as absent would offer a send that has nothing to send.
    ///
    /// <para>
    /// This is the daemon's own count, never recomputed here. A group approve
    /// applies the same filter server-side, and three shells each
    /// reimplementing it is what put the hole here in the first place.
    /// </para>
    /// </remarks>
    [JsonPropertyName("contributable_count")]
    public int? ContributableCount { get; set; }

    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "ask";

    [JsonPropertyName("configured")]
    public bool Configured { get; set; }

    /// <summary>
    /// Marks the row holding sessions whose project the daemon cannot name.
    ///
    /// The daemon decides this, because the daemon is what enforces it: it
    /// refuses <c>auto_upload</c> for that bucket in two independent places.
    /// A client MUST NOT infer the row from <c>project_label</c> -- see
    /// <c>docs/contributor-daemon-ipc-v1_1.md</c> -- because the wire carries
    /// the slug <c>unknown-project</c> as that label, and any project a
    /// contributor happened to name the same would be told it can never be
    /// armed.
    /// </summary>
    [JsonPropertyName("is_unresolved_bucket")]
    public bool IsUnresolvedBucket { get; set; }
}

/// <summary><c>list_audit</c>'s privacy-safe local change log.</summary>
public sealed class AuditSettingsPayload
{
    [JsonPropertyName("entries")]
    public List<AuditSettingEntry> Entries { get; set; } = new();
}

public sealed class AuditSettingEntry
{
    [JsonPropertyName("at")]
    public DateTimeOffset At { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("project_label")]
    public string? ProjectLabel { get; set; }
}

public sealed class ProbabilityStorageView {
    [JsonPropertyName("capture_enabled")] public bool CaptureEnabled { get; set; }
    [JsonPropertyName("capture_label")] public string CaptureLabel { get; set; } = "";
    [JsonPropertyName("capture_confirmation")] public string CaptureConfirmation { get; set; } = "";
    [JsonPropertyName("capture_notice")] public string CaptureNotice { get; set; } = "";
    [JsonPropertyName("state_line")] public string StateLine { get; set; } = "";
    [JsonPropertyName("scope_note")] public string ScopeNote { get; set; } = "";
    [JsonPropertyName("cleanup_label")] public string CleanupLabel { get; set; } = "";
    [JsonPropertyName("discard_label")] public string DiscardLabel { get; set; } = "";
    [JsonPropertyName("discard_confirmation")] public string DiscardConfirmation { get; set; } = "";
    [JsonPropertyName("cancel_label")] public string CancelLabel { get; set; } = "";
    [JsonPropertyName("confirm_label")] public string ConfirmLabel { get; set; } = "";
    [JsonPropertyName("failure_line")] public string FailureLine { get; set; } = "";
}
