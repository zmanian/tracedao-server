using System;
using System.Text.Json;

namespace TraceCommons.Interop;

/// <summary>Independent consent to send captured inference content to a witness.</summary>
public static class TokenContributionConsent
{
    public static string Serialize(bool enabled, bool disclosureConfirmed)
    {
        if (enabled && !disclosureConfirmed)
        {
            throw new InvalidOperationException("token-disclosure-required");
        }
        return JsonSerializer.Serialize(new { token_distributions_contribution = enabled });
    }

    public static bool ConfirmsWrite(DaemonSettingsSnapshot? settings, bool enabled) =>
        settings?.ProbabilityContributionAllowed == enabled;
}
