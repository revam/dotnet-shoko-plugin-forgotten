using Newtonsoft.Json;

namespace Shoko.Plugin.Forgotten.API.Models;

/// <summary>
/// Represents a request to verify a reset token.
/// </summary>
public class VerifyTokenRequest
{
    /// <summary>
    /// Gets the username associated with the token.
    /// </summary>
    [JsonProperty("username")]
    public required string Username { get; init; }

    /// <summary>
    /// Gets the token to verify.
    /// </summary>
    [JsonProperty("token")]
    public required string Token { get; init; }
}
