using Newtonsoft.Json;

namespace Shoko.Plugin.Forgotten.API.Models;

/// <summary>
/// Represents a request to reset a user's password.
/// </summary>
public class ResetPasswordRequest
{
    /// <summary>
    /// Gets the username of the account to reset.
    /// </summary>
    [JsonProperty("username")]
    public required string Username { get; init; }

    /// <summary>
    /// Gets the reset token for verification.
    /// </summary>
    [JsonProperty("token")]
    public required string Token { get; init; }

    /// <summary>
    /// Gets the new password to set.
    /// </summary>
    [JsonProperty("newPassword")]
    public required string NewPassword { get; init; }
}
