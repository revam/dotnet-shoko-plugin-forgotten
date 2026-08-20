using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Shoko.Plugin.Forgotten.Services;

/// <summary>
/// Every reset token the plugin has issued, and every rate limit that
/// governs issuing and spending them.
/// </summary>
/// <remarks>
/// <para>
/// All mutable state here is guarded by one lock, and every operation the
/// controller can reach is a single call that both decides and records.
/// That is deliberate. The predecessor exposed each limit as a
/// <c>Can…</c> predicate followed by a separate <c>Record…</c>, so two
/// requests arriving together both passed a check neither had yet paid
/// for — and the predicates themselves rewrote the window, so one of them
/// silently discarded the other's increment. A limiter that can be raced
/// is not a limiter.
/// </para>
/// <para>
/// A lock rather than lock-free counters because the thing being protected
/// spans several fields — a window start, its count, and the live token —
/// and because the traffic this sees is measured in requests per day. There
/// is no throughput to trade away.
/// </para>
/// <para>
/// Tokens are keyed by <em>username</em>, not by token. Two consequences
/// follow, and both are wanted: a user has at most one live token, so
/// issuing a new one retires the old, and consuming one leaves nothing else
/// armed; and a failed guess is counted against the account it was aimed at
/// rather than against the string the guesser invented, which is what makes
/// the per-token ceiling bind at all and what stops the bookkeeping growing
/// on attacker-chosen keys.
/// </para>
/// </remarks>
public sealed class TokenStore : IDisposable
{
    /// <summary>How long an issued token stays spendable.</summary>
    public static readonly TimeSpan TokenExpiry = TimeSpan.FromMinutes(15);

    /// <summary>The global cooldown between username dumps.</summary>
    public static readonly TimeSpan UsernameRequestCooldown = TimeSpan.FromHours(24);

    /// <summary>The window over which reset requests are counted per address.</summary>
    public static readonly TimeSpan ResetRequestWindow = TimeSpan.FromDays(1);

    /// <summary>The window over which verify and reset attempts are counted per address.</summary>
    public static readonly TimeSpan VerifyAttemptWindow = TimeSpan.FromDays(1);

    /// <summary>Reset tokens one address may ask for per <see cref="ResetRequestWindow"/>.</summary>
    public const int MaxResetRequestsPerIp = 5;

    /// <summary>Token attempts one address may spend per <see cref="VerifyAttemptWindow"/>.</summary>
    public const int MaxVerifyAttemptsPerIp = 10;

    /// <summary>Wrong tokens an account will tolerate before its live token is retired.</summary>
    public const int MaxFailedAttemptsPerToken = 5;

    /// <summary>
    /// The longest password the host will accept. Shoko's user update
    /// rejects anything longer with a validation exception, so the check
    /// lives here too: it has to happen <em>before</em> a token is spent,
    /// or a typo-length paste costs the user their only token and returns
    /// them a 500.
    /// </summary>
    public const int MaxPasswordLength = 1024;

    /// <summary>
    /// The longest username accepted on the wire.
    ///
    /// The host imposes no limit of its own, so this one is this plugin's
    /// and is set generously: it exists to bound what gets written into a
    /// log line and used as a dictionary key, not to have an opinion about
    /// what a username may be.
    /// </summary>
    public const int MaxUsernameLength = 256;

    private const int TokenLength = 12;

    /// <summary>Twelve characters, plus room for the separators a person types.</summary>
    private const int MaxTokenInputLength = 23;

    /// <summary>
    /// Keyed the way the host resolves a username, so that the account the
    /// token was issued for and the account the submitter names are the same
    /// account under the same rule.
    /// </summary>
    private readonly Dictionary<string, TokenEntry> _tokens = new(StringComparer.InvariantCultureIgnoreCase);

    private readonly Dictionary<string, WindowEntry> _resetRequests = new(StringComparer.Ordinal);

    private readonly Dictionary<string, WindowEntry> _verifyAttempts = new(StringComparer.Ordinal);

    /// <summary>
    /// One entry per reset asked for from an address for an account, whether
    /// or not that account exists.
    /// </summary>
    /// <remarks>
    /// It is written on the miss as well as the hit on purpose. The
    /// one-request-at-a-time rule cannot be answered from
    /// <see cref="_tokens"/>, because a nonexistent account has no token —
    /// so a second request would be refused for a real user and allowed for
    /// an invented one, and the difference between 429 and 200 is a
    /// perfectly good way to enumerate accounts.
    /// </remarks>
    // Invariant-culture, case-insensitive, to agree with _tokens above. With
    // an ordinal comparer over a lowercased key these two disagreed about
    // characters ICU ignores - a zero-width joiner spelled a name that missed
    // the pending check here and hit the same account there, so one address
    // could displace an account's live token repeatedly.
    private readonly Dictionary<string, DateTimeOffset> _pendingRequests = new(StringComparer.InvariantCultureIgnoreCase);

    private readonly Lock _gate = new();

    private readonly TimeProvider _timeProvider;

    private readonly ITimer _cleanupTimer;

    private DateTimeOffset _lastUsernameRequest = DateTimeOffset.MinValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenStore"/> class and
    /// starts the background sweep.
    /// </summary>
    /// <param name="timeProvider">
    /// The clock. Every expiry and every window boundary is decided against
    /// this at read time rather than by the sweep, so the sweep is only ever
    /// reclaiming memory — if it stopped, nothing here would outlive its
    /// stated lifetime.
    /// </param>
    public TokenStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _cleanupTimer = _timeProvider.CreateTimer(_ => RunCleanup(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Disposes the background sweep timer.
    /// </summary>
    public void Dispose()
        => _cleanupTimer.Dispose();

    private DateTimeOffset Now => _timeProvider.GetUtcNow();

    /// <summary>
    /// Reduces a username to the form this plugin will store, compare and
    /// log, or <c>null</c> when it could not be a username.
    /// </summary>
    /// <remarks>
    /// Control characters are refused rather than stripped. The console log
    /// is this plugin's delivery channel for reset tokens and its layout is
    /// a plain one-line rendering of the message, so a username carrying a
    /// newline can write a second line that reads exactly like a token line
    /// for somebody else's account. Refusing is also the honest answer: a
    /// client sending one is not naming a user that could exist.
    /// </remarks>
    /// <param name="username">The username as submitted.</param>
    /// <returns>The trimmed username, or <c>null</c>.</returns>
    public static string? NormalizeUsername(string? username)
    {
        if (username is null)
            return null;

        var trimmed = username.Trim();
        if (trimmed.Length is 0 || trimmed.Length > MaxUsernameLength)
            return null;

        // char.IsControl is Cc only, which lets through the characters that
        // actually reorder a console line: bidi overrides and isolates
        // (U+202A-202E, U+2066-2069), the zero-width joiner, and the line and
        // paragraph separators. The console layout this ends up in is
        // unescaped, and it is how a reset token reaches its owner.
        return trimmed.Any(character => char.IsControl(character) || char.GetUnicodeCategory(character) is
            UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            ? null
            : trimmed;
    }

    /// <summary>
    /// Reduces a token to the form it is stored in — twelve uppercase hex
    /// characters — or <c>null</c> when it could not be one of ours.
    /// </summary>
    /// <remarks>
    /// This is the only statement of what a token may look like. It used to
    /// have a twin, <c>IsValidTokenFormat</c>, that restated the same rules
    /// for the controller's benefit; two copies of one rule set is one copy
    /// too many, so the controller now asks this and keeps the answer.
    /// </remarks>
    /// <param name="token">The token as submitted, with or without separators.</param>
    /// <returns>The normalized token, or <c>null</c>.</returns>
    public static string? NormalizeToken(string? token)
    {
        if (token is null || token.Length > MaxTokenInputLength)
            return null;

        var builder = new StringBuilder(TokenLength);
        foreach (var character in token)
        {
            if (character is '-' or ' ')
                continue;

            if (!char.IsAsciiHexDigit(character) || builder.Length == TokenLength)
                return null;

            builder.Append(char.ToUpperInvariant(character));
        }

        return builder.Length == TokenLength ? builder.ToString() : null;
    }

    /// <summary>
    /// Decides whether a password will be accepted before any token is
    /// spent on it.
    /// </summary>
    /// <remarks>
    /// Empty is valid. Shoko supports passwordless accounts on purpose and
    /// this endpoint is not the place to overrule that.
    /// </remarks>
    /// <param name="password">The proposed password.</param>
    /// <returns><c>true</c> when the host will accept it.</returns>
    public static bool IsAcceptablePassword(string? password)
        => password is not null && password.Length <= MaxPasswordLength;

    /// <summary>
    /// Takes the global username-dump budget, if it is there to take.
    /// </summary>
    /// <param name="nextAllowedAt">When refused, when the next dump is due.</param>
    /// <returns><c>true</c> when the caller may proceed.</returns>
    public bool TryRecordUsernameRequest(out DateTimeOffset? nextAllowedAt)
    {
        lock (_gate)
        {
            var now = Now;
            var nextAllowed = _lastUsernameRequest + UsernameRequestCooldown;
            if (now < nextAllowed)
            {
                nextAllowedAt = nextAllowed;
                return false;
            }

            _lastUsernameRequest = now;
            nextAllowedAt = null;
            return true;
        }
    }

    /// <summary>
    /// Reports whether an address has spent its whole attempt budget.
    /// </summary>
    /// <remarks>
    /// This reads without spending, and is used by the endpoints that are
    /// gated by the attempt budget without being attempts themselves. It is
    /// a check with no matching act, so there is nothing here to race.
    /// </remarks>
    /// <param name="ip">The client address.</param>
    /// <param name="nextAllowedAt">When exhausted, when the window rolls over.</param>
    /// <returns><c>true</c> when the address has nothing left to spend.</returns>
    public bool IsAttemptBudgetExhausted(string ip, out DateTimeOffset? nextAllowedAt)
    {
        lock (_gate)
            return !HasBudget(_verifyAttempts, ip, MaxVerifyAttemptsPerIp, VerifyAttemptWindow, Now, out nextAllowedAt);
    }

    /// <summary>
    /// Claims the right to ask for a reset token for an account.
    /// </summary>
    /// <remarks>
    /// The per-address daily budget is taken here, atomically, and only when
    /// the request is going to be allowed. The caller then asks the host
    /// whether the account exists and calls <see cref="Generate"/> or
    /// <see cref="GenerateDummy"/>; that lookup is a host round-trip and is
    /// deliberately not held under this lock. Two requests that slip between
    /// the claim and the mint can therefore both mint — but the second
    /// replaces the first, so the user still ends up with exactly one live
    /// token, and both paid for their slot.
    /// </remarks>
    /// <param name="username">The normalized username.</param>
    /// <param name="ip">The client address.</param>
    /// <param name="nextAllowedAt">When refused, when the caller may try again.</param>
    /// <returns>Why the request was refused, or <see cref="ResetRequestResult.Ok"/>.</returns>
    public ResetRequestResult TryStartReset(string username, string ip, out DateTimeOffset? nextAllowedAt)
    {
        lock (_gate)
        {
            var now = Now;

            // An address that has burned its attempt budget is not allowed to
            // mint fresh material either; this reads the budget without
            // spending it, because asking for a token is not an attempt.
            if (!HasBudget(_verifyAttempts, ip, MaxVerifyAttemptsPerIp, VerifyAttemptWindow, now, out nextAllowedAt))
                return ResetRequestResult.AttemptsExhausted;

            // One request per account and address at a time: a second while
            // the first is still good is far more likely to be a resend than
            // a person who lost the token.
            var pendingKey = PendingKey(ip, username);
            if (_pendingRequests.TryGetValue(pendingKey, out var pendingUntil) && now < pendingUntil)
            {
                nextAllowedAt = pendingUntil;
                return ResetRequestResult.AlreadyPending;
            }

            if (!TrySpend(_resetRequests, ip, MaxResetRequestsPerIp, ResetRequestWindow, now, out nextAllowedAt))
                return ResetRequestResult.RateLimited;

            _pendingRequests[pendingKey] = now + TokenExpiry;
            return ResetRequestResult.Ok;
        }
    }

    /// <summary>
    /// Issues a reset token for an account, retiring any token that account
    /// already held.
    /// </summary>
    /// <param name="username">The normalized username.</param>
    /// <param name="ip">The client address the token is bound to.</param>
    /// <returns>The token in the form it is shown, <c>XXXX-XXXX-XXXX</c>.</returns>
    public string Generate(string username, string ip)
    {
        RawToken(out var rawToken, out var formattedToken);

        lock (_gate)
        {
            var now = Now;
            _tokens[username] = new TokenEntry
            {
                Token = rawToken,
                Username = username,
                IpAddress = ip,
                ExpiresAt = now + TokenExpiry,
            };
        }

        return formattedToken;
    }

    /// <summary>
    /// Performs the same work as <see cref="Generate"/> without storing a
    /// token. This exists to prevent timing-based username enumeration —
    /// call it when the user does not exist so both paths cost the same.
    /// </summary>
    /// <remarks>
    /// It takes the lock it has no use for, because <see cref="Generate"/>
    /// takes it and the point of this method is to cost what that one costs.
    /// </remarks>
    /// <returns>
    /// The token it did not store, so the caller can pay for a log write of
    /// the same shape as the one the hit path makes. Never store or return
    /// this to anyone.
    /// </returns>
    public string GenerateDummy()
    {
        RawToken(out _, out var formatted);

        lock (_gate)
        {
        }

        return formatted;
    }

    private static void RawToken(out string raw, out string formatted)
    {
        raw = RandomNumberGenerator.GetHexString(TokenLength, lowercase: false);
        formatted = $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}";
    }

    /// <summary>
    /// Checks a token against an account without spending it.
    /// </summary>
    /// <param name="username">The username as submitted.</param>
    /// <param name="token">The token as submitted.</param>
    /// <param name="ip">The client address.</param>
    /// <param name="nextAllowedAt">When rate limited, when the window rolls over.</param>
    /// <returns>The outcome, in enough detail for the caller to answer honestly.</returns>
    public TokenAttemptResult TryVerify(string username, string token, string ip, out DateTimeOffset? nextAllowedAt)
    {
        lock (_gate)
        {
            var now = Now;
            if (!HasBudget(_verifyAttempts, ip, MaxVerifyAttemptsPerIp, VerifyAttemptWindow, now, out nextAllowedAt))
                return TokenAttemptResult.RateLimited;

            var result = Check(username, token, ip, out nextAllowedAt, out _);

            // A wrong answer costs the address one of its attempts; a right
            // one does not, so that verifying a token and then spending it
            // is one attempt rather than two. A locked one costs the same as
            // a wrong one - it is indistinguishable on the wire, and it must
            // be indistinguishable in what it costs too, or it is a probe
            // that can be repeated for ever.
            if (result is TokenAttemptResult.Invalid or TokenAttemptResult.LockedOut)
                TrySpend(_verifyAttempts, ip, MaxVerifyAttemptsPerIp, VerifyAttemptWindow, now, out _);

            return result;
        }
    }

    /// <summary>
    /// Checks a token against an account and, if it holds, spends it.
    /// </summary>
    /// <remarks>
    /// A spent token is not yet a finished reset: the host still has to
    /// accept the new password. The caller gets a <see cref="ResetTicket"/>
    /// and owes it either a <see cref="ResetTicket.Commit"/> — which retires
    /// the account's tokens for good — or a
    /// <see cref="ResetTicket.Restore"/>, which puts this one back because
    /// nothing was actually changed. Without that, a host that refuses the
    /// password leaves the user with no token and no reset.
    /// </remarks>
    /// <param name="username">The username as submitted.</param>
    /// <param name="token">The token as submitted.</param>
    /// <param name="ip">The client address.</param>
    /// <param name="ticket">The claim on the spent token, when the outcome is <see cref="TokenAttemptResult.Ok"/>.</param>
    /// <param name="nextAllowedAt">When rate limited, when the window rolls over.</param>
    /// <returns>The outcome.</returns>
    public TokenAttemptResult TryConsume(string username, string token, string ip, out ResetTicket? ticket, out DateTimeOffset? nextAllowedAt)
    {
        ticket = null;
        lock (_gate)
        {
            var now = Now;

            // Unlike verification, spending always costs an attempt: this is
            // the endpoint that changes something, and a caller that reaches
            // it has committed to a guess either way.
            if (!TrySpend(_verifyAttempts, ip, MaxVerifyAttemptsPerIp, VerifyAttemptWindow, now, out nextAllowedAt))
                return TokenAttemptResult.RateLimited;

            var result = Check(username, token, ip, out _, out var entry);
            if (result is not TokenAttemptResult.Ok)
                return result;

            entry!.IsConsumed = true;
            ticket = new ResetTicket(this, entry);
            return TokenAttemptResult.Ok;
        }
    }

    /// <summary>
    /// The single statement of what makes a submitted token good. Must be
    /// called under <see cref="_gate"/>.
    /// </summary>
    private TokenAttemptResult Check(string username, string token, string ip, out DateTimeOffset? nextAllowedAt, out TokenEntry? entry)
    {
        nextAllowedAt = null;
        entry = null;

        if (NormalizeUsername(username) is not { } normalizedUsername)
            return TokenAttemptResult.Malformed;

        if (NormalizeToken(token) is not { } normalizedToken)
            return TokenAttemptResult.Malformed;

        var now = Now;
        if (!_tokens.TryGetValue(normalizedUsername, out var candidate))
            return TokenAttemptResult.Invalid;

        // Expiry is decided here, not by the sweep. The sweep runs on a
        // timer nobody supervises; this runs on the request that would
        // otherwise benefit from it having failed.
        if (now >= candidate.ExpiresAt)
        {
            _tokens.Remove(normalizedUsername);
            return TokenAttemptResult.Invalid;
        }

        if (candidate.FailedAttempts >= MaxFailedAttemptsPerToken)
        {
            nextAllowedAt = candidate.ExpiresAt;
            return TokenAttemptResult.LockedOut;
        }

        // The token is the secret, so it is compared without leaking where
        // it first differed. The username is not a secret — the host itself
        // resolves it case-insensitively and this endpoint exists precisely
        // for people who are guessing at their own — so it is matched the
        // way the host matches it, by the dictionary above.
        if (!FixedTimeEquals(candidate.Token, normalizedToken) || !string.Equals(candidate.IpAddress, ip, StringComparison.Ordinal))
        {
            // Only the address the token is bound to can spend the account's
            // ceiling. A guess from anywhere else cannot succeed whatever it
            // contains - the binding above refuses it - so counting it bought
            // no protection and let a stranger burn a victim's five attempts
            // and deny them a reset for as long as the token lived. Guessing
            // from elsewhere is still bounded, by that address's own budget.
            if (string.Equals(candidate.IpAddress, ip, StringComparison.Ordinal))
                candidate.FailedAttempts++;
            return TokenAttemptResult.Invalid;
        }

        // Already spent is not a wrong guess, so it does not count against
        // the account's ceiling; it is just nothing left to spend.
        if (candidate.IsConsumed)
            return TokenAttemptResult.Invalid;

        entry = candidate;
        return TokenAttemptResult.Ok;
    }

    private void CommitTicket(TokenEntry entry)
    {
        lock (_gate)
        {
            // Unconditional, unlike Restore. The password has actually
            // changed by the time this runs, so every token the account had
            // outstanding is stale - including one issued from another
            // address during the host's write, which the reference guard
            // this used to carry would have left alive and spendable.
            _tokens.Remove(entry.Username);
        }
    }

    private void RestoreTicket(TokenEntry entry)
    {
        lock (_gate)
        {
            // Only the entry that is still the account's live token may be
            // put back. If a newer one has since been issued, the newer one
            // is the one the user is holding and this must not displace it.
            if (_tokens.TryGetValue(entry.Username, out var current) && ReferenceEquals(current, entry))
                entry.IsConsumed = false;
        }
    }

    private static string PendingKey(string ip, string username)
        => $"{ip}\n{username}";

    /// <summary>
    /// Whether a key has anything left in its window. Must be called under
    /// <see cref="_gate"/>.
    /// </summary>
    private static bool HasBudget(Dictionary<string, WindowEntry> counters, string key, int limit, TimeSpan window, DateTimeOffset now, out DateTimeOffset? nextAllowedAt)
    {
        nextAllowedAt = null;
        if (!counters.TryGetValue(key, out var entry) || now - entry.WindowStart >= window || entry.Count < limit)
            return true;

        nextAllowedAt = entry.WindowStart + window;
        return false;
    }

    /// <summary>
    /// Takes one from a key's window if there is one to take, and says so.
    /// Nothing is recorded when the answer is no. Must be called under
    /// <see cref="_gate"/>.
    /// </summary>
    private static bool TrySpend(Dictionary<string, WindowEntry> counters, string key, int limit, TimeSpan window, DateTimeOffset now, out DateTimeOffset? nextAllowedAt)
    {
        nextAllowedAt = null;

        if (!counters.TryGetValue(key, out var entry) || now - entry.WindowStart >= window)
        {
            counters[key] = new WindowEntry(now);
            return true;
        }

        if (entry.Count >= limit)
        {
            nextAllowedAt = entry.WindowStart + window;
            return false;
        }

        entry.Count++;
        return true;
    }

    /// <summary>
    /// Compares two equal-length strings without revealing where they first
    /// differ.
    /// </summary>
    private static bool FixedTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
            return false;

        var result = 0;
        for (var index = 0; index < a.Length; index++)
            result |= a[index] ^ b[index];

        return result == 0;
    }

    /// <summary>
    /// Drops state nothing can consult any more. Purely a memory sweep —
    /// every decision above is already made against the clock, so a sweep
    /// that never ran would cost memory and nothing else.
    /// </summary>
    internal void RunCleanup()
    {
        lock (_gate)
        {
            var now = Now;

            foreach (var key in _tokens.Where(pair => now >= pair.Value.ExpiresAt).Select(pair => pair.Key).ToArray())
                _tokens.Remove(key);

            foreach (var key in _resetRequests.Where(pair => now - pair.Value.WindowStart >= ResetRequestWindow).Select(pair => pair.Key).ToArray())
                _resetRequests.Remove(key);

            foreach (var key in _verifyAttempts.Where(pair => now - pair.Value.WindowStart >= VerifyAttemptWindow).Select(pair => pair.Key).ToArray())
                _verifyAttempts.Remove(key);

            foreach (var key in _pendingRequests.Where(pair => now >= pair.Value).Select(pair => pair.Key).ToArray())
                _pendingRequests.Remove(key);
        }
    }

    /// <summary>
    /// A claim on a token that has been spent but whose reset has not yet
    /// gone through.
    /// </summary>
    public sealed class ResetTicket
    {
        private readonly TokenStore _store;

        private readonly TokenEntry _entry;

        private int _settled;

        internal ResetTicket(TokenStore store, TokenEntry entry)
        {
            _store = store;
            _entry = entry;
        }

        /// <summary>
        /// The reset went through. Retires the account's token for good.
        /// </summary>
        public void Commit()
        {
            if (Interlocked.Exchange(ref _settled, 1) == 0)
                _store.CommitTicket(_entry);
        }

        /// <summary>
        /// The reset did not go through, so the token was not really spent.
        /// Puts it back, provided it is still the account's live token.
        /// </summary>
        public void Restore()
        {
            if (Interlocked.Exchange(ref _settled, 1) == 0)
                _store.RestoreTicket(_entry);
        }
    }

    internal sealed class TokenEntry
    {
        public required string Token { get; init; }

        public required string Username { get; init; }

        public required string IpAddress { get; init; }

        public required DateTimeOffset ExpiresAt { get; init; }

        public int FailedAttempts { get; set; }

        public bool IsConsumed { get; set; }
    }

    private sealed class WindowEntry(DateTimeOffset windowStart)
    {
        public DateTimeOffset WindowStart { get; } = windowStart;

        public int Count { get; set; } = 1;
    }
}
