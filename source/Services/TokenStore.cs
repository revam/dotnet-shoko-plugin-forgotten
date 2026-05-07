using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace Shoko.Plugin.Forgotten.Services;

/// <summary>
/// Provides storage and management of password reset tokens with rate limiting and IP tracking.
/// </summary>
public class TokenStore
{
    private readonly ConcurrentDictionary<string, TokenEntry> _tokens = new();

    // Global username request tracking
    private DateTimeOffset _lastUsernameRequest = DateTimeOffset.MinValue;
    private static readonly TimeSpan UsernameRequestCooldown = TimeSpan.FromHours(24);

    // Per-IP reset request tracking
    private readonly ConcurrentDictionary<string, ResetRequestEntry> _resetRequests = new();
    private static readonly int MaxResetRequestsPerIp = 5;
    private static readonly TimeSpan ResetRequestWindow = TimeSpan.FromDays(1);

    private static readonly TimeSpan TokenExpiry = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Checks if username requests are allowed (global 24h cooldown).
    /// </summary>
    /// <param name="nextAllowedAt">When set, contains the timestamp when the next request will be allowed.</param>
    /// <returns><c>true</c> if the request is allowed; otherwise, <c>false</c>.</returns>
    public bool CanRequestUsernames(out DateTimeOffset? nextAllowedAt)
    {
        var nextAllowed = _lastUsernameRequest + UsernameRequestCooldown;
        if (DateTimeOffset.UtcNow < nextAllowed)
        {
            nextAllowedAt = nextAllowed;
            return false;
        }

        nextAllowedAt = null;
        return true;
    }

    /// <summary>
    /// Records that a username request was made.
    /// </summary>
    public void RecordUsernameRequest()
    {
        _lastUsernameRequest = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Checks if a reset request is allowed for the given IP.
    /// </summary>
    /// <param name="ip">The client IP address.</param>
    /// <param name="username">The username being requested.</param>
    /// <param name="nextAllowedAt">When set, contains the timestamp when the next request will be allowed.</param>
    /// <returns><c>true</c> if the request is allowed; otherwise, <c>false</c>.</returns>
    public bool CanRequestReset(string ip, string username, out DateTimeOffset? nextAllowedAt)
    {
        nextAllowedAt = null;

        // Clean up expired entries
        CleanupResetRequests();

        // Check if IP has reached daily limit
        if (_resetRequests.TryGetValue(ip, out var entry))
        {
            // Check if we're in a new window
            if (DateTimeOffset.UtcNow - entry.WindowStart >= ResetRequestWindow)
            {
                // Reset the window
                entry = new ResetRequestEntry { WindowStart = DateTimeOffset.UtcNow };
                _resetRequests[ip] = entry;
            }

            if (entry.Count >= MaxResetRequestsPerIp)
            {
                nextAllowedAt = entry.WindowStart + ResetRequestWindow;
                return false;
            }

            // Check for concurrent request for same username+IP
            if (entry.TryGetPendingRequestTime(username, out var requestTime))
            {
                // Calculate when the pending request will expire
                nextAllowedAt = requestTime + TokenExpiry;
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Records that a reset request was made for tracking purposes.
    /// </summary>
    /// <param name="ip">The client IP address.</param>
    /// <param name="username">The username being requested.</param>
    public void RecordResetRequest(string ip, string username)
    {
        var entry = _resetRequests.AddOrUpdate(ip,
            _ => new ResetRequestEntry
            {
                WindowStart = DateTimeOffset.UtcNow,
                Count = 1
            },
            (_, existing) =>
            {
                existing.Count++;
                return existing;
            });

        entry.AddPendingUsername(username);
    }

    /// <summary>
    /// Generates a new reset token for the specified username and IP.
    /// </summary>
    /// <param name="username">The username for which to generate the token.</param>
    /// <param name="ip">The client IP address.</param>
    /// <returns>The generated token string.</returns>
    public string Generate(string username, string ip)
    {
        var token = RandomNumberGenerator.GetHexString(32, lowercase: false);
        var entry = new TokenEntry
        {
            Token = token,
            Username = username,
            IpAddress = ip,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow + TokenExpiry
        };
        _tokens[token] = entry;
        Cleanup();
        return token;
    }

    /// <summary>
    /// Verifies if a token is valid for the specified username and IP.
    /// </summary>
    /// <param name="username">The username to verify against.</param>
    /// <param name="token">The token to verify.</param>
    /// <param name="ip">The client IP address.</param>
    /// <returns><c>true</c> if the token is valid for the username and IP; otherwise, <c>false</c>.</returns>
    public bool Verify(string username, string token, string ip)
    {
        Cleanup();
        if (!_tokens.TryGetValue(token, out var entry))
            return false;
        return !entry.IsConsumed && entry.Username == username && entry.IpAddress == ip;
    }

    /// <summary>
    /// Consumes a token, marking it as used.
    /// </summary>
    /// <param name="username">The username to verify against.</param>
    /// <param name="token">The token to consume.</param>
    /// <param name="ip">The client IP address.</param>
    /// <returns><c>true</c> if the token was successfully consumed; otherwise, <c>false</c>.</returns>
    public bool Consume(string username, string token, string ip)
    {
        Cleanup();
        if (!_tokens.TryGetValue(token, out var entry))
            return false;
        if (entry.Username != username || entry.IpAddress != ip)
            return false;
        return entry.TryConsume();
    }

    private void Cleanup()
    {
        var cutoff = DateTimeOffset.UtcNow - TokenExpiry;
        var keysToRemove = _tokens
            .Where(kvp => kvp.Value.CreatedAt < cutoff)
            .Select(kvp => kvp.Key)
            .ToArray();

        foreach (var key in keysToRemove)
        {
            _tokens.TryRemove(key, out _);
        }
    }

    private void CleanupResetRequests()
    {
        var cutoff = DateTimeOffset.UtcNow - ResetRequestWindow;
        var keysToRemove = _resetRequests
            .Where(kvp => kvp.Value.WindowStart < cutoff)
            .Select(kvp => kvp.Key)
            .ToArray();

        foreach (var key in keysToRemove)
        {
            _resetRequests.TryRemove(key, out _);
        }
    }

    private sealed class TokenEntry
    {
        public required string Token { get; init; }
        public required string Username { get; init; }
        public required string IpAddress { get; init; }
        public required DateTimeOffset CreatedAt { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        private int _consumed;

        public bool IsConsumed => _consumed == 1;

        public bool TryConsume()
        {
            return Interlocked.CompareExchange(ref _consumed, 1, 0) == 0;
        }
    }

    private sealed class ResetRequestEntry
    {
        public DateTimeOffset WindowStart { get; set; }
        public int Count { get; set; }
        private readonly ConcurrentDictionary<string, DateTimeOffset> _pendingUsernames = new();

        public bool TryGetPendingRequestTime(string username, out DateTimeOffset requestTime)
        {
            return _pendingUsernames.TryGetValue(username, out requestTime);
        }

        public void AddPendingUsername(string username)
        {
            _pendingUsernames[username] = DateTimeOffset.UtcNow;
        }
    }
}
