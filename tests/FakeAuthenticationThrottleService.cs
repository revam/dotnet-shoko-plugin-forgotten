using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// A stand-in for the host's shared authentication throttle.
/// </summary>
/// <remarks>
/// Written out rather than mocked because these tests care less about
/// whether the service was called than about <em>which bucket</em> the
/// plugin wrote to, and <em>what</em> it named. A test sets the two
/// lockouts; the ledgers record what the plugin did with them.
/// </remarks>
internal sealed class FakeAuthenticationThrottleService : IAuthenticationThrottleService
{
    /// <summary>What a test wants the client to be locked out for, if at all.</summary>
    public TimeSpan? ClientLockout { get; set; }

    /// <summary>What a test wants the named username to be locked out for, if at all.</summary>
    public TimeSpan? UsernameLockout { get; set; }

    /// <summary>Failures registered against the client.</summary>
    public int ClientFailures { get; private set; }

    /// <summary>
    /// Failures registered against a user. Expected to stay at zero: a wrong
    /// reset code says nothing about the account's own credential, and the
    /// username is whatever the request claimed it was.
    /// </summary>
    public int UserFailures { get; private set; }

    /// <summary>Resets of the client.</summary>
    public int ClientResets { get; private set; }

    /// <summary>Resets of a user.</summary>
    public int UserResets { get; private set; }

    /// <summary>How often the plugin asked before acting.</summary>
    public int Checks { get; private set; }

    /// <summary>
    /// Every username the plugin has asked about. Expected to hold names the
    /// caller submitted, and never a reset code.
    /// </summary>
    public List<string> UsernamesChecked { get; } = [];

    public int MaxFailedAttempts => 10;

    public TimeSpan AttemptWindow => TimeSpan.FromMinutes(15);

    public TimeSpan InitialLockout => TimeSpan.FromMinutes(15);

    public TimeSpan MaxLockout => TimeSpan.FromDays(1);

    public StatusCodeResult? ThrottleAuthentication(HttpContext context, string username)
    {
        Checks++;
        UsernamesChecked.Add(username);

        var remaining = UsernameLockout is null
            ? ClientLockout
            : ClientLockout is null || UsernameLockout > ClientLockout
                ? UsernameLockout
                : ClientLockout;
        if (remaining is null)
            return null;

        // The real service writes this itself, and the plugin reads it back
        // out, so a fake that skipped it would not be exercising the path.
        context.Response.Headers.RetryAfter = ((int)Math.Ceiling(remaining.Value.TotalSeconds)).ToString();
        return new StatusCodeResult(StatusCodes.Status429TooManyRequests);
    }

    public TimeSpan? GetRemainingLockout(HttpContext context) => ClientLockout;

    public TimeSpan? GetRemainingLockout(HubCallerContext context) => ClientLockout;

    public TimeSpan? GetRemainingLockout(IUser user) => UsernameLockout;

    public void RegisterFailure(HttpContext context) => ClientFailures++;

    public void RegisterFailure(HubCallerContext context) => ClientFailures++;

    public void RegisterFailure(IUser user) => UserFailures++;

    public void Reset(HttpContext context) => ClientResets++;

    public void Reset(HubCallerContext context) => ClientResets++;

    public void Reset(IUser user) => UserResets++;
}
