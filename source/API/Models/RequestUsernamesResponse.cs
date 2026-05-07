using System;
using Newtonsoft.Json;

namespace Shoko.Plugin.Forgotten.API.Models;

/// <summary>
/// Represents a response for a username recovery request.
/// </summary>
public class RequestUsernamesResponse
{
    /// <summary>
    /// Gets or sets the timestamp when the request was made.
    /// </summary>
    [JsonProperty("requestedAt")]
    public DateTimeOffset? RequestedAt { get; set; }

    /// <summary>
    /// Gets or sets the timestamp when the client can retry the request.
    /// </summary>
    [JsonProperty("retryAfter")]
    public DateTimeOffset? RetryAfter { get; set; }

    /// <summary>
    /// Gets or sets the response message.
    /// </summary>
    [JsonProperty("message")]
    public string? Message { get; set; }
}
