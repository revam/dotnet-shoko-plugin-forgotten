using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.Config.Enums;
using Shoko.Abstractions.Config.Events;
using Shoko.Abstractions.Config.Services;
using Shoko.Abstractions.Metadata.Anidb;
using Shoko.Abstractions.Metadata.Enums;
using Shoko.Abstractions.Metadata.Shoko;
using Shoko.Abstractions.Plugin;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Events;
using Shoko.Abstractions.User.Services;
using Shoko.Abstractions.User.Update;
using Shoko.Plugin.Forgotten.Configuration;

// The host's interfaces declare events these fakes have no reason to raise.
#pragma warning disable CS0067

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// The host, reduced to the four things this plugin actually asks it for:
/// does this user exist, list them, change a password, revoke the keys.
/// </summary>
/// <remarks>
/// Everything else throws rather than returning a plausible default, so a
/// future call into the host that these tests do not model announces itself
/// instead of quietly passing.
/// </remarks>
internal sealed class FakeUserService : IUserService
{
    private readonly List<IUser> _users = [];

    /// <summary>What the next password change should do instead of succeeding.</summary>
    public Func<Exception>? PasswordChangeFailure { get; set; }

    /// <summary>What the next key revocation should do instead of succeeding.</summary>
    public Func<Exception>? TokenRevocationFailure { get; set; }

    public string? LastPasswordSet { get; private set; }

    public int PasswordChanges { get; private set; }

    public int TokenRevocations { get; private set; }

    public FakeUser Add(string username)
    {
        var user = new FakeUser(_users.Count + 1, username);
        _users.Add(user);
        return user;
    }

    public event EventHandler<UserChangedEventArgs>? UserAdded;

    public event EventHandler<UserChangedEventArgs>? UserUpdated;

    public event EventHandler<UserChangedEventArgs>? UserRemoved;

    public IEnumerable<IUser> GetUsers() => _users;

    public IUser? GetUserByID(int id) => _users.FirstOrDefault(user => user.ID == id);

    // Matched the way the host matches it, which is the whole point of
    // several of these tests.
    public IUser? GetUserByUsername(string username)
        => string.IsNullOrEmpty(username)
            ? null
            : _users.FirstOrDefault(user => string.Equals(user.Username, username, StringComparison.InvariantCultureIgnoreCase));

    public Task ChangeUserPassword(IUser user, string newPassword)
    {
        if (PasswordChangeFailure is { } failure)
            return Task.FromException(failure());

        PasswordChanges++;
        LastPasswordSet = newPassword;
        return Task.CompletedTask;
    }

    public Task<bool> InvalidateApiTokensForUser(IUser user)
    {
        if (TokenRevocationFailure is { } failure)
            return Task.FromException<bool>(failure());

        TokenRevocations++;
        return Task.FromResult(true);
    }

    // Not modelled: reaching any of these means the plugin grew a
    // dependency on the host that nothing here is checking.
    public IUser? GetUserFromHttpContext(HttpContext context) => throw new NotSupportedException();

    public IUser? GetUserFromHubCallerContext(HubCallerContext context) => throw new NotSupportedException();

    public Task<IUser> CreateUser(UserUpdate initialData) => throw new NotSupportedException();

    public Task ResetUserPassword(IUser user) => throw new NotSupportedException();

    public Task<IUser> UpdateUser(IUser user, UserUpdate updateData) => throw new NotSupportedException();

    public Task DeleteUser(IUser user) => throw new NotSupportedException();

    public IUser? AuthenticateUser(string username, string password) => throw new NotSupportedException();

    public IReadOnlyList<ApiToken> GetApiTokensForUser(IUser user) => throw new NotSupportedException();

    public Task<ApiToken> GenerateApiTokenForUser(IUser user, string deviceName) => throw new NotSupportedException();

    public Task<ApiToken> GenerateApiTokenForUser(IUser user, string deviceName, DateTime expiresAt) => throw new NotSupportedException();

    public ApiToken? GetApiTokenFromHttpContext(HttpContext context) => throw new NotSupportedException();

    public Task<bool> InvalidateApiDeviceForUser(IUser user, string deviceName) => throw new NotSupportedException();

    public Task<bool> InvalidateApiToken(ApiToken token) => throw new NotSupportedException();

    public Task<bool> InvalidateApiToken(string token) => throw new NotSupportedException();
}

/// <summary>
/// A user, as far as this plugin is concerned: a name and an identifier.
/// </summary>
internal sealed class FakeUser(int id, string username) : IUser
{
    public int ID { get; } = id;

    public string Username { get; } = username;

    public DataSource Source => DataSource.Shoko;

    public bool IsAdmin => false;

    public bool IsAnidbUser => false;

    public IReadOnlyList<IAnidbTag> RestrictedTags => [];

    public bool IsAllowedToSee(IShokoGroup group) => true;

    public bool IsAllowedToSee(IShokoSeries series) => true;

    public bool IsAllowedToSee(IAnidbAnime anime) => true;
}

/// <summary>
/// Just enough configuration service to hand the plugin back one
/// configuration object.
/// </summary>
internal sealed class FakeConfigurationService(ForgottenPluginConfiguration configuration) : IConfigurationService
{
    public event EventHandler<ConfigurationSavedEventArgs>? Saved;

    public event EventHandler<ConfigurationRequiresRestartEventArgs>? RequiresRestart;

    public TConfig Load<TConfig>(bool copy = false) where TConfig : class, IConfiguration, new()
        => (TConfig)(object)configuration;

    public IReadOnlyDictionary<Guid, IReadOnlySet<string>> RestartPendingFor => throw new NotSupportedException();

    public IReadOnlyDictionary<Guid, IReadOnlySet<string>> LoadedEnvironmentVariables => throw new NotSupportedException();

    public void AddParts(IEnumerable<Type> configurationTypes) => throw new NotSupportedException();

    public ConfigurationProvider<TConfig> CreateProvider<TConfig>() where TConfig : class, IConfiguration, new() => new(this);

    public IEnumerable<ConfigurationInfo> GetAllConfigurationInfos() => throw new NotSupportedException();

    public IReadOnlyList<ConfigurationInfo> GetConfigurationInfo(IPlugin plugin) => throw new NotSupportedException();

    public ConfigurationInfo? GetConfigurationInfo(Guid configurationId) => throw new NotSupportedException();

    public ConfigurationInfo? GetConfigurationInfo(Type type) => throw new NotSupportedException();

    // The provider routes Load() through the configuration's info, and the
    // info is only ever compared for identity on a Saved event this fake
    // never raises — so it need not be a real one.
    public ConfigurationInfo GetConfigurationInfo<TConfig>() where TConfig : class, IConfiguration, new() => null!;

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Validate(ConfigurationInfo info, string json) => throw new NotSupportedException();

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Validate(ConfigurationInfo info, IConfiguration config) => throw new NotSupportedException();

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Validate<TConfig>(TConfig config) where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Validate(string json, NJsonSchema.JsonSchema schema) => throw new NotSupportedException();

    public ConfigurationActionResult PerformCustomAction(ConfigurationInfo info, IConfiguration configuration, string path, string actionID, IUser? user = null, Uri? uri = null) => throw new NotSupportedException();

    public ConfigurationActionResult PerformCustomAction<TConfig>(TConfig configuration, string path, string actionID, IUser? user = null, Uri? uri = null) where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public ConfigurationActionResult PerformReactiveAction(ConfigurationInfo info, IConfiguration configuration, string path, ConfigurationActionType actionType, ReactiveEventType reactiveEventType = ReactiveEventType.All, IUser? user = null, Uri? uri = null) => throw new NotSupportedException();

    public ConfigurationActionResult PerformReactiveAction<TConfig>(TConfig configuration, string path, ConfigurationActionType actionType, ReactiveEventType reactiveEventType = ReactiveEventType.All, IUser? user = null, Uri? uri = null) where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public IConfiguration New(ConfigurationInfo info) => throw new NotSupportedException();

    public TConfig New<TConfig>() where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public IConfiguration Load(ConfigurationInfo info, bool copy = false) => configuration;

    public bool Save(ConfigurationInfo info, IConfiguration json) => throw new NotSupportedException();

    public bool Save(ConfigurationInfo info, string json) => throw new NotSupportedException();

    public bool Save<TConfig>() where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public bool Save<TConfig>(TConfig config) where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public bool Save<TConfig>(string json) where TConfig : class, IConfiguration, new() => throw new NotSupportedException();

    public string GetSchema(ConfigurationInfo info) => throw new NotSupportedException();

    public NJsonSchema.JsonSchema GenerateSchema(Type type) => throw new NotSupportedException();

    public string Serialize(IConfiguration config) => throw new NotSupportedException();

    public IConfiguration Deserialize(ConfigurationInfo info, string json) => throw new NotSupportedException();
}
