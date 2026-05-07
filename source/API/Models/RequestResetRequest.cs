using Newtonsoft.Json;

namespace Shoko.Plugin.Forgotten.API.Models;

/// <summary>
/// Represents a request to initiate a password reset.
/// </summary>
public class RequestResetRequest
{
    /// <summary>
    /// Gets the username for which to request a password reset.
    /// </summary>
    [JsonProperty("username")]
    public required string Username { get; init; }
}
