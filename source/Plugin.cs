using System;
using Microsoft.Extensions.DependencyInjection;
using Shoko.Abstractions.Plugin;
using Shoko.Plugin.Forgotten.Services;

namespace Shoko.Plugin.Forgotten;

/// <inheritdoc/>
public class Plugin : IPlugin, IPluginServiceRegistration
{
    /// <inheritdoc/>
    public Guid ID { get; private init; } = new("118ffeee-943d-40b2-af63-2416da4beca9");

    /// <inheritdoc/>
    public string Name { get; private set; } = "Forgotten";

    /// <inheritdoc/>
    public string Description { get; private set; } = """
        Password reset and username recovery for Shoko.
        Provides a 4-step forgot-password flow with token verification and a forgot-username sub-flow.
    """;

    /// <inheritdoc/>
    public static void RegisterServices(IServiceCollection serviceCollection, IApplicationPaths applicationPaths)
    {
        serviceCollection.AddSingleton<TokenStore>();
    }
}
