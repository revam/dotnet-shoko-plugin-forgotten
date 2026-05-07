using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Shoko.Plugin.Forgotten.Services;

/// <summary>
/// Provides storage and management of password reset tokens with rate limiting and IP tracking.
/// </summary>
public class TokenStore : IDisposable
{
    private readonly ConcurrentDictionary<string, TokenEntry> _tokens = new();

    // Global username request tracking
    private DateTimeOffset _lastUsernameRequest = DateTimeOffset.MinValue;
    private static readonly TimeSpan UsernameRequestCooldown = TimeSpan.FromHours(24);

    // Per-IP reset request tracking
    private readonly ConcurrentDictionary<string, ResetRequestEntry> _resetRequests = new();
    private static readonly int MaxResetRequestsPerIp = 5;
    private static readonly TimeSpan ResetRequestWindow = TimeSpan.FromDays(1);

    // Per-IP verify/reset attempt tracking (same 24h window as reset requests)
    private readonly ConcurrentDictionary<string, VerifyAttemptEntry> _verifyAttempts = new();
    private static readonly int MaxVerifyAttemptsPerIp = 10;
    private static readonly TimeSpan VerifyAttemptWindow = TimeSpan.FromDays(1);

    // Per-token failed attempt tracking
    private readonly ConcurrentDictionary<string, TokenAttemptEntry> _tokenAttempts = new();
    private static readonly int MaxFailedAttemptsPerToken = 5;

    private static readonly TimeSpan TokenExpiry = TimeSpan.FromMinutes(15);
    private const int TokenLength = 12;
    private const int MaxInputLength = 23; // 12 chars + 11 dashes/spaces

    private readonly Timer _cleanupTimer;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenStore"/> class and starts the background cleanup timer.
    /// </summary>
    public TokenStore()
    {
        _cleanupTimer = new Timer(_ => RunCleanup(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Disposes the background cleanup timer.
    /// </summary>
    public void Dispose()
    {
        _cleanupTimer.Dispose();
    }

    private void RunCleanup()
    {
        CleanupTokens();
        CleanupResetRequests();
        CleanupVerifyAttempts();
        CleanupTokenAttempts();
    }

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
            // Check if the pending token has expired
            var tokenExpiry = requestTime + TokenExpiry;
            if (DateTimeOffset.UtcNow >= tokenExpiry)
            {
                // Token has expired, allow retry
                entry.RemovePendingUsername(username);
            }
            else
            {
                nextAllowedAt = tokenExpiry;
                return false;
            }
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
                existing.IncrementCount();
                return existing;
            });

        entry.AddPendingUsername(username);
    }

    /// <summary>
    /// Checks if verify/reset attempts are allowed for the given IP.
    /// </summary>
    /// <param name="ip">The client IP address.</param>
    /// <param name="nextAllowedAt">When set, contains the timestamp when attempts will be allowed again.</param>
    /// <returns><c>true</c> if attempts are allowed; otherwise, <c>false</c>.</returns>
    public bool CanAttemptVerify(string ip, out DateTimeOffset? nextAllowedAt)
    {
        nextAllowedAt = null;

        if (_verifyAttempts.TryGetValue(ip, out var entry))
        {
            // Check if we're in a new window
            if (DateTimeOffset.UtcNow - entry.WindowStart >= VerifyAttemptWindow)
            {
                // Reset the window
                entry = new VerifyAttemptEntry { WindowStart = DateTimeOffset.UtcNow };
                _verifyAttempts[ip] = entry;
            }

            if (entry.Count >= MaxVerifyAttemptsPerIp)
            {
                nextAllowedAt = entry.WindowStart + VerifyAttemptWindow;
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Records a verify/reset attempt for rate limiting.
    /// </summary>
    /// <param name="ip">The client IP address.</param>
    public void RecordVerifyAttempt(string ip)
    {
        _verifyAttempts.AddOrUpdate(ip,
            _ => new VerifyAttemptEntry
            {
                WindowStart = DateTimeOffset.UtcNow,
                Count = 1
            },
            (_, existing) =>
            {
                existing.IncrementCount();
                return existing;
            });
    }

    /// <summary>
    /// Validates the token format without checking if it exists.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <returns><c>true</c> if the token format is valid (12 hex chars after normalization); otherwise, <c>false</c>.</returns>
    public bool IsValidTokenFormat(string token)
    {
        if (token.Length > MaxInputLength)
            return false;
        
        var digitCount = 0;
        foreach (var c in token)
        {
            if (c is '-' or ' ')
                continue;
            
            if (!char.IsAsciiHexDigit(c))
                return false;
            
            digitCount++;
        }
        
        return digitCount == TokenLength;
    }

    /// <summary>
    /// Checks if a token has exceeded its maximum failed attempts.
    /// </summary>
    /// <param name="normalizedToken">The normalized token.</param>
    /// <returns><c>true</c> if the token is locked out; otherwise, <c>false</c>.</returns>
    public bool IsTokenLockedOut(string normalizedToken)
    {
        return _tokenAttempts.TryGetValue(normalizedToken, out var entry) && entry.FailedCount >= MaxFailedAttemptsPerToken;
    }

    /// <summary>
    /// Records a failed attempt for a token.
    /// </summary>
    /// <param name="normalizedToken">The normalized token.</param>
    public void RecordFailedTokenAttempt(string normalizedToken)
    {
        _tokenAttempts.AddOrUpdate(normalizedToken,
            _ => new TokenAttemptEntry { LastAttempt = DateTimeOffset.UtcNow, FailedCount = 1 },
            (_, existing) =>
            {
                existing.LastAttempt = DateTimeOffset.UtcNow;
                existing.FailedCount++;
                return existing;
            });
    }

    /// <summary>
    /// Generates a new reset token for the specified username and IP.
    /// </summary>
    /// <param name="username">The username for which to generate the token.</param>
    /// <param name="ip">The client IP address.</param>
    /// <returns>The generated token string in formatted form (XXXX-XXXX-XXXX).</returns>
    public string Generate(string username, string ip)
    {
        // Generate 12-char hex token
        RawToken(out var rawToken, out var formattedToken);
        
        var entry = new TokenEntry
        {
            Token = rawToken, // Store raw uppercase version
            Username = username,
            IpAddress = ip,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow + TokenExpiry
        };
        _tokens[rawToken] = entry;
        return formattedToken;
    }

    /// <summary>
    /// Performs the same work as <see cref="Generate"/> without storing a token.
    /// This exists to prevent timing-based username enumeration — call this when the user
    /// doesn't exist so both code paths take indistinguishable time.
    /// </summary>
    public void GenerateDummy()
    {
        // Must match Generate() exactly — same entropy generation and formatting
        RawToken(out _, out _);
    }

    private static void RawToken(out string raw, out string formatted)
    {
        raw = RandomNumberGenerator.GetHexString(TokenLength, lowercase: false);
        formatted = $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}";
    }

    /// <summary>
    /// Verifies if a token is valid for the specified username and IP.
    /// </summary>
    /// <param name="username">The username to verify against.</param>
    /// <param name="token">The token to verify (can be formatted with dashes/spaces).</param>
    /// <param name="ip">The client IP address.</param>
    /// <param name="isValid">When this method returns, contains <c>true</c> if the token is valid; otherwise, <c>false</c>.</param>
    /// <returns><c>true</c> if the attempt was allowed; <c>false</c> if rate limited or token locked out.</returns>
    public bool TryVerify(string username, string token, string ip, out bool isValid)
    {
        isValid = false;

        var normalizedToken = NormalizeToken(token);
        if (normalizedToken is null)
            return false;

        // Check if token is locked out due to too many failed attempts
        if (IsTokenLockedOut(normalizedToken))
            return false;

        
        if (!_tokens.TryGetValue(normalizedToken, out var entry))
        {
            RecordFailedTokenAttempt(normalizedToken);
            return true; // Allowed attempt, but invalid
        }
        
        // Validate username (constant-time) and IP (normal comparison)
        if (!ConstantTimeEquals(entry.Username, username) || entry.IpAddress != ip)
        {
            RecordFailedTokenAttempt(normalizedToken);
            return true; // Allowed attempt, but invalid
        }
        
        isValid = !entry.IsConsumed;
        return true;
    }

    /// <summary>
    /// Consumes a token, marking it as used.
    /// </summary>
    /// <param name="username">The username to verify against.</param>
    /// <param name="token">The token to consume (can be formatted with dashes/spaces).</param>
    /// <param name="ip">The client IP address.</param>
    /// <param name="consumed">When this method returns, contains <c>true</c> if the token was consumed; otherwise, <c>false</c>.</param>
    /// <returns><c>true</c> if the attempt was allowed; <c>false</c> if rate limited or token locked out.</returns>
    public bool TryConsume(string username, string token, string ip, out bool consumed)
    {
        consumed = false;

        var normalizedToken = NormalizeToken(token);
        if (normalizedToken is null)
            return false;

        // Check if token is locked out due to too many failed attempts
        if (IsTokenLockedOut(normalizedToken))
            return false;

        
        if (!_tokens.TryGetValue(normalizedToken, out var entry))
        {
            RecordFailedTokenAttempt(normalizedToken);
            return true; // Allowed attempt, but invalid
        }
        
        // Validate username (constant-time) and IP (normal comparison)
        if (!ConstantTimeEquals(entry.Username, username) || entry.IpAddress != ip)
        {
            RecordFailedTokenAttempt(normalizedToken);
            return true; // Allowed attempt, but invalid
        }
        
        consumed = entry.TryConsume();
        return true;
    }

    /// <summary>
    /// Normalizes a token input by removing dashes and spaces, converting to uppercase,
    /// and validating length.
    /// </summary>
    /// <param name="token">The token input.</param>
    /// <returns>The normalized token, or null if invalid.</returns>
    private static string? NormalizeToken(string token)
    {
        if (token.Length > MaxInputLength)
            return null;
        
        // Remove dashes and spaces, convert to uppercase
        var sb = new StringBuilder(TokenLength);
        foreach (var c in token)
        {
            if (c is '-' or ' ')
                continue;
            
            if (!char.IsAsciiHexDigit(c))
                return null;
            
            sb.Append(char.ToUpperInvariant(c));
        }
        
        return sb.Length == TokenLength ? sb.ToString() : null;
    }

    /// <summary>
    /// Performs a constant-time comparison of two strings to prevent timing attacks.
    /// </summary>
    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
            return false;
        
        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }

    private void CleanupTokens()
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

    private void CleanupVerifyAttempts()
    {
        var cutoff = DateTimeOffset.UtcNow - VerifyAttemptWindow;
        var keysToRemove = _verifyAttempts
            .Where(kvp => kvp.Value.WindowStart < cutoff)
            .Select(kvp => kvp.Key)
            .ToArray();

        foreach (var key in keysToRemove)
        {
            _verifyAttempts.TryRemove(key, out _);
        }
    }

    private void CleanupTokenAttempts()
    {
        var cutoff = DateTimeOffset.UtcNow - TokenExpiry;
        var keysToRemove = _tokenAttempts
            .Where(kvp => kvp.Value.LastAttempt < cutoff)
            .Select(kvp => kvp.Key)
            .ToArray();

        foreach (var key in keysToRemove)
        {
            _tokenAttempts.TryRemove(key, out _);
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
        private int _count;

        public int Count
        {
            get => _count;
            set => _count = value;
        }

        public void IncrementCount()
        {
            Interlocked.Increment(ref _count);
        }

        private readonly ConcurrentDictionary<string, DateTimeOffset> _pendingUsernames = new();

        public bool TryGetPendingRequestTime(string username, out DateTimeOffset requestTime)
        {
            return _pendingUsernames.TryGetValue(username, out requestTime);
        }

        public void AddPendingUsername(string username)
        {
            _pendingUsernames[username] = DateTimeOffset.UtcNow;
        }

        public void RemovePendingUsername(string username)
        {
            _pendingUsernames.TryRemove(username, out _);
        }
    }

    private sealed class VerifyAttemptEntry
    {
        public DateTimeOffset WindowStart { get; set; }
        private int _count;

        public int Count
        {
            get => _count;
            set => _count = value;
        }

        public void IncrementCount()
        {
            Interlocked.Increment(ref _count);
        }
    }

    private sealed class TokenAttemptEntry
    {
        public DateTimeOffset LastAttempt { get; set; }
        public int FailedCount { get; set; }
    }
}
