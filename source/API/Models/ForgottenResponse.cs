using System;
using Newtonsoft.Json;

namespace Shoko.Plugin.Forgotten.API.Models;

/// <summary>
/// Represents a response from the Forgotten plugin API.
/// </summary>
public class ForgottenResponse
{
    /// <summary>
    /// Gets or sets a value indicating whether the operation was successful.
    /// </summary>
    [JsonProperty("success")]
    public bool Success { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the token is valid.
    /// </summary>
    [JsonProperty("valid")]
    public bool Valid { get; set; }

    /// <summary>
    /// Gets or sets the response message.
    /// </summary>
    [JsonProperty("message")]
    public string? Message { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the client can retry the request.
    /// </summary>
    [JsonProperty("retryAfter")]
    public DateTimeOffset? RetryAfter { get; set; }
}
