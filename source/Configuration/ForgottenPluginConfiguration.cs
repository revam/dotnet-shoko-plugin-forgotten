using Shoko.Abstractions.Config;

namespace Shoko.Plugin.Forgotten.Configuration;

/// <summary>
/// Configuration for the Forgotten plugin.
/// </summary>
public class ForgottenPluginConfiguration : IConfiguration
{
    /// <summary>
    /// Gets or sets a value indicating whether to trust X-Forwarded-For headers from proxies.
    /// </summary>
    public bool TrustProxy { get; set; } = false;
}
