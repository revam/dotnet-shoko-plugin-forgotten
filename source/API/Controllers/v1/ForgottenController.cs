using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Shoko.Abstractions.Config;
using Shoko.Abstractions.User;
using Shoko.Abstractions.User.Services;
using Shoko.Plugin.Forgotten.API.Models;
using Shoko.Plugin.Forgotten.Configuration;
using Shoko.Plugin.Forgotten.Services;

namespace Shoko.Plugin.Forgotten.API.Controllers.v1;

/// <summary>
/// API controller for handling forgotten password and username recovery operations.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="ForgottenController"/> class.
/// </remarks>
/// <param name="userService">The user service.</param>
/// <param name="tokenStore">The token store for managing reset tokens.</param>
/// <param name="throttleService">
/// The host's authentication throttle, shared with the core sign-in and with
/// every other plugin. See the <c>Throttling</c> region for what this plugin
/// asks of it and what it tells it.
/// </param>
/// <param name="configurationProvider">The configuration provider.</param>
/// <param name="logger">The logger instance.</param>
[ApiController]
[Route("/api/plugin/Forgotten/v1")]
public class ForgottenController(
    IUserService userService,
    TokenStore tokenStore,
    IAuthenticationThrottleService throttleService,
    ConfigurationProvider<ForgottenPluginConfiguration> configurationProvider,
    ILogger<ForgottenController> logger) : ControllerBase
{
    private readonly IUserService _userService = userService;

    private readonly TokenStore _tokenStore = tokenStore;

    private readonly IAuthenticationThrottleService _throttleService = throttleService;

    private readonly ILogger<ForgottenController> _logger = logger;

    private readonly ConfigurationProvider<ForgottenPluginConfiguration> _configurationProvider = configurationProvider;

    /// <summary>
    /// Requests a password reset token for the specified username.
    /// </summary>
    /// <param name="request">The request containing the username.</param>
    /// <returns>An action result containing the response.</returns>
    [HttpPost("RequestReset")]
    public ActionResult<ForgottenResponse> RequestReset([FromBody] RequestResetRequest request)
    {
        if (!TryGetClientIps(out var ips))
        {
            _logger.LogError("Password reset request denied — unable to determine client IP address");
            return StatusCode(400, Failure("Unable to determine client IP address."));
        }

        if (TokenStore.NormalizeUsername(request.Username) is not { } username)
            return StatusCode(400, Failure("Invalid username."));

        // Before the account is looked at, so a name the host has locked out
        // and a name it has never heard of are answered the same way. Nothing
        // is registered: asking for a reset code is not an attempt at one.
        if (IsLockedOut(username, out var lockedOutUntil))
            return RateLimited("Too many attempts. Please try again later.", lockedOutUntil);

        var outcome = _tokenStore.TryStartReset(username, ips, out var nextAllowedAt);
        if (outcome is not ResetRequestResult.Ok)
        {
            _logger.LogWarning("Password reset request denied for username {Username}: {Reason}. Client IPs: {IPs}", username, outcome, ips);
            return RateLimited(outcome is ResetRequestResult.AlreadyPending
                ? "A reset code has already been issued. Please use it or wait for it to expire."
                : "Rate limit exceeded. Please try again later.", nextAllowedAt);
        }

        // Logged identically whether or not the account exists, and before
        // the lookup that would tell us, so that raising the log level can
        // never leave the miss visible while hiding the hit.
        _logger.LogInformation("Password reset requested for username {Username}. Client IPs: {IPs}", username, ips);

        var user = _userService.GetUserByUsername(username);
        if (user is null)
        {
            // Dummy operation to prevent timing-based username enumeration.
            // Must match the cost of Generate below (cryptographic token).
            var discarded = _tokenStore.GenerateDummy();

            // And a matched log write, because the equalisation above is worth
            // little beside one. Shoko's file target runs with
            // KeepFileOpen = false, so every event is an open, a write and a
            // close on this thread before the response goes out; a hit that
            // wrote two lines against a miss that wrote one was a far larger
            // signal than the entropy either path generates. Same level, same
            // shape, same argument count - and the value is thrown away.
            _logger.LogWarning("No reset token issued for user {Username}: {Token}. Client IPs: {IPs}", username, discarded, ips);
        }
        else
        {
            var token = _tokenStore.Generate(username, ips);

            // The log is the delivery channel — there is no mail transport
            // here — so the token line has to survive an operator raising
            // the level, and it is genuinely worth a warning in its own
            // right: a credential is now sitting in plain text on a console.
            _logger.LogWarning("Reset token for user {Username}: {Token}. Client IPs: {IPs}", username, token, ips);
        }

        return Ok(new ForgottenResponse { Success = true, Message = "If the username exists, a reset code has been logged." });
    }

    /// <summary>
    /// Verifies if a reset token is valid for the specified username.
    /// </summary>
    /// <remarks>
    /// A token that does not check out answers 200 with <c>valid: false</c>
    /// rather than a status that says why. The address it was issued to,
    /// whether it has expired, and whether it was ever issued at all are all
    /// folded into the same answer on purpose: telling them apart would
    /// confirm a guessed token to whoever guessed it.
    /// </remarks>
    /// <param name="request">The request containing the username and token.</param>
    /// <returns>An action result containing the validation response.</returns>
    [HttpPost("VerifyToken")]
    public ActionResult<ForgottenResponse> VerifyToken([FromBody] VerifyTokenRequest request)
    {
        if (!TryGetClientIps(out var ips))
        {
            _logger.LogError("Token verification denied — unable to determine client IP address");
            return StatusCode(400, Failure("Unable to determine client IP address."));
        }

        if (TokenStore.NormalizeUsername(request.Username) is not { } username)
            return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

        if (IsLockedOut(username, out var lockedOutUntil))
            return RateLimited("Too many attempts. Please try again later.", lockedOutUntil);

        var result = _tokenStore.TryVerify(username, request.Token, ips);
        RegisterTokenOutcome(result);
        switch (result)
        {
            case TokenAttemptResult.Malformed:
                return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

            case TokenAttemptResult.LockedOut:
                // Answered exactly as an unknown token is. A lockout can only
                // exist for an account that has a live token, so reporting it
                // separately told a stranger the account exists and has a
                // reset in flight - which is the question every other line of
                // this endpoint is written to refuse.
                _logger.LogWarning("Token verification blocked — the token has taken too many failed attempts. Client IPs: {IPs}", ips);
                return Ok(new ForgottenResponse { Success = true, Valid = false });

            default:
                // Nothing is cleared on the way out, even when the token
                // holds. This endpoint answers a question rather than
                // performing a reset, and the same token answers it for
                // fifteen minutes - so clearing the host's ledger here would
                // hand whoever holds one token an unlimited supply of fresh
                // password guesses at every other door.
                return Ok(new ForgottenResponse { Success = true, Valid = result is TokenAttemptResult.Ok });
        }
    }

    /// <summary>
    /// Resets the password for a user using a valid reset token.
    /// </summary>
    /// <param name="request">The request containing the username, token, and new password.</param>
    /// <returns>A task representing the asynchronous operation with the action result.</returns>
    [HttpPost("ResetPassword")]
    public async Task<ActionResult<ForgottenResponse>> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!TryGetClientIps(out var ips))
        {
            _logger.LogError("Password reset denied — unable to determine client IP address");
            return StatusCode(400, Failure("Unable to determine client IP address."));
        }

        // Checked before the token is spent, not after. The host rejects a
        // password over its limit with a validation exception, and a token
        // spent on a request that was never going to succeed is a token the
        // user no longer has.
        //
        // Empty is not rejected: Shoko supports passwordless accounts and
        // this endpoint has no business overruling that.
        if (!TokenStore.IsAcceptablePassword(request.NewPassword))
            return StatusCode(400, Failure($"Password cannot be longer than {TokenStore.MaxPasswordLength} characters."));

        if (TokenStore.NormalizeUsername(request.Username) is not { } username)
            return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

        if (IsLockedOut(username, out var lockedOutUntil))
            return RateLimited("Too many attempts. Please try again later.", lockedOutUntil);

        var result = _tokenStore.TryConsume(username, request.Token, ips, out var ticket);
        RegisterTokenOutcome(result);
        switch (result)
        {
            case TokenAttemptResult.Malformed:
                return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

            case TokenAttemptResult.LockedOut:
                // Same answer as any other failure, for the reason in
                // VerifyToken above.
                _logger.LogWarning("Password reset blocked — the token has taken too many failed attempts. Client IPs: {IPs}", ips);
                return StatusCode(403, Failure("Invalid or expired token."));

            case not TokenAttemptResult.Ok:
                _logger.LogWarning("Password reset failed — invalid or expired token, or address mismatch. Client IPs: {IPs}", ips);
                return StatusCode(403, Failure("Invalid or expired token."));
        }

        // The normalized name, because the store trims and the host does
        // not: an untrimmed name verified here and 404'd there, costing an
        // attempt for input the previous call had just called valid.
        //
        // Guarded, because this is the one call between spending the token
        // and settling for it. An exception escaping here left the ticket
        // unsettled, and an unsettled ticket is a token marked spent that
        // nothing will ever hand back - the user loses their reset to a
        // fault that had nothing to do with them.
        IUser? user;
        try
        {
            user = _userService.GetUserByUsername(username);
        }
        catch (Exception ex)
        {
            ticket!.Restore();
            _logger.LogError(ex, "Password reset failed — the user lookup threw. Client IPs: {IPs}", ips);
            return StatusCode(500, Failure("The password could not be changed. The reset code is still valid; please try again."));
        }

        if (user is null)
        {
            // The account went away between the token being issued and being
            // spent. Nothing was changed, so the token goes back.
            ticket!.Restore();
            _logger.LogWarning("Password reset failed — the user no longer exists. Client IPs: {IPs}", ips);
            return StatusCode(403, Failure("Invalid or expired token."));
        }

        try
        {
            await _userService.ChangeUserPassword(user, request.NewPassword).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // The host refused. It is the only party that changes anything
            // here, so if it refused then nothing changed and the token has
            // not really been spent — hand it back rather than leaving the
            // user with neither a new password nor a way to set one.
            ticket!.Restore();
            _logger.LogError(ex, "Password reset failed — the host rejected the new password for user {Username}. Client IPs: {IPs}", user.Username, ips);
            return StatusCode(500, Failure("The password could not be changed. The reset code is still valid; please try again."));
        }

        // The password is changed, so the token really is spent — and with it
        // anything else the account had outstanding.
        ticket!.Commit();

        // Both dimensions are cleared here, and only here. This is the one
        // place where an account's credential has actually changed, so every
        // failure counted against the old one is stale — and the person this
        // plugin exists for is somebody the host has already locked out for
        // forgetting it. Leaving the lockout standing would let them complete
        // a reset and still not be able to sign in.
        _throttleService.Reset(HttpContext);
        _throttleService.Reset(user);
        _logger.LogWarning("Password reset successful for user {Username}. Client IPs: {IPs}", user.Username, ips);

        try
        {
            await _userService.InvalidateApiTokensForUser(user).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // The reset itself stands; say so, but do not claim the tokens
            // were revoked when they were not.
            _logger.LogError(ex, "Password was reset for user {Username}, but existing API tokens could not be revoked.", user.Username);
            return Ok(new ForgottenResponse { Success = true, Message = "Password has been reset, but existing API tokens could not be revoked." });
        }

        return Ok(new ForgottenResponse { Success = true, Message = "Password has been reset. All API tokens have been revoked." });
    }

    /// <summary>
    /// Checks if the plugin is installed and operational.
    /// </summary>
    /// <returns>An empty 200 OK response.</returns>
    [HttpGet("Status")]
    public IActionResult GetStatus()
        => Ok();

    /// <summary>
    /// Requests a list of all registered usernames (logged for security purposes).
    /// </summary>
    /// <returns>An action result containing the response with the request timestamp.</returns>
    [HttpPost("RequestUsernames")]
    public ActionResult<RequestUsernamesResponse> RequestUsernames()
    {
        if (!TryGetClientIps(out var ips))
        {
            _logger.LogError("Username recovery request denied — unable to determine client IP address");
            return StatusCode(400, new RequestUsernamesResponse
            {
                Message = "Unable to determine client IP address."
            });
        }

        // No username is named here, so only the client dimension can be
        // read — and only read. Handing out the list of accounts is not an
        // attempt at a credential, so nothing is registered; but a client the
        // host has shut out for guessing does not get to collect the names
        // either.
        if (IsClientLockedOut(out var lockedOutUntil))
        {
            _logger.LogWarning("Username recovery request denied — this client is locked out. Client IPs: {IPs}", ips);
            return RateLimited(new RequestUsernamesResponse
            {
                Message = "Too many attempts. Please try again later.",
                RetryAfter = lockedOutUntil,
            }, lockedOutUntil);
        }

        // Claiming the cooldown and dumping the names is one operation, so
        // two requests arriving together cannot both find the cooldown clear.
        if (!_tokenStore.TryRecordUsernameRequest(out var nextAllowedAt))
        {
            _logger.LogWarning("Username recovery request denied due to global rate limiting. Client IPs: {IPs}", ips);
            return RateLimited(new RequestUsernamesResponse
            {
                Message = "Username recovery can only be requested once every 24 hours.",
                RetryAfter = nextAllowedAt,
            }, nextAllowedAt);
        }

        _logger.LogWarning("Username recovery requested. Client IPs: {IPs}", ips);

        foreach (var user in _userService.GetUsers())
            _logger.LogWarning("Registered username: {Username}", user.Username);

        return Ok(new RequestUsernamesResponse
        {
            RequestedAt = DateTimeOffset.UtcNow,
            RetryAfter = DateTimeOffset.UtcNow.Add(TokenStore.UsernameRequestCooldown),
        });
    }

    #region Throttling

    /// <summary>
    /// Refuses a caller the host has locked out, either as a client or under
    /// the username it named.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A reset code is a credential, and a wrong one is a wrong credential,
    /// so the guessing is counted in the store the host counts wrong
    /// passwords in rather than in one this plugin keeps to itself. A client
    /// working through codes finds every door shut, and a client the core
    /// already shut out finds these ones closed too.
    /// </para>
    /// <para>
    /// The username passed is the one the caller named, never the code it
    /// submitted. The host files usernames and client addresses in separate
    /// namespaces, so a code in the username slot would land among the
    /// usernames, where one that read like a real account would share that
    /// account's lockout in both directions — and the host logs the username
    /// it was asked about at warning level, which would write a live reset
    /// code to the console for anyone to collect.
    /// </para>
    /// <para>
    /// Call this before the account is looked up. The host counts failures
    /// for any username it is given, existing or not, so a name it has locked
    /// out and a name it has never heard of are answered identically — which
    /// is the one property every other line of these endpoints is written to
    /// preserve.
    /// </para>
    /// </remarks>
    /// <param name="username">The normalized username the caller named.</param>
    /// <param name="lockedOutUntil">When locked out, when the caller may return.</param>
    /// <returns><c>true</c> when the caller is locked out.</returns>
    private bool IsLockedOut(string username, out DateTimeOffset? lockedOutUntil)
    {
        // Sets Retry-After and logs the throttled attempt itself. The status
        // result it hands back is dropped: these endpoints carry a body the
        // wizard reads a message and a retryAfter out of.
        if (_throttleService.ThrottleAuthentication(HttpContext, username) is null)
        {
            lockedOutUntil = null;
            return false;
        }

        lockedOutUntil = ThrottledUntil();
        return true;
    }

    /// <summary>
    /// Refuses a caller the host has locked out, where no username is named.
    /// </summary>
    /// <param name="lockedOutUntil">When locked out, when the caller may return.</param>
    /// <returns><c>true</c> when the client is locked out.</returns>
    private bool IsClientLockedOut(out DateTimeOffset? lockedOutUntil)
    {
        if (_throttleService.GetRemainingLockout(HttpContext) is not { } remaining)
        {
            lockedOutUntil = null;
            return false;
        }

        lockedOutUntil = DateTimeOffset.UtcNow + remaining;
        return true;
    }

    /// <summary>
    /// Counts a code that checked out against nothing as a failure by the
    /// client, and by the client alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the client dimension is written. Charging the account would let
    /// anyone who can name a username lock its owner out of signing in, which
    /// is a denial of service dressed as a security control — and here the
    /// username is whatever the request said it was, so it would be a
    /// particularly cheap one.
    /// </para>
    /// <para>
    /// <see cref="TokenAttemptResult.Malformed"/> is not charged: it is
    /// decided from the shape of the input alone, without consulting any
    /// account, and a string that could not be a code was never a guess at
    /// one. Neither is a correct code that the host then refused to act on —
    /// an overlong password, an account that went away, a host that threw —
    /// because nothing was guessed in any of those.
    /// </para>
    /// <para>
    /// <see cref="TokenAttemptResult.LockedOut"/> is charged exactly as
    /// <see cref="TokenAttemptResult.Invalid"/> is. The two are
    /// indistinguishable on the wire on purpose, and a difference in what
    /// they cost would be the same disclosure by another route.
    /// </para>
    /// </remarks>
    /// <param name="result">The outcome the store reported.</param>
    private void RegisterTokenOutcome(TokenAttemptResult result)
    {
        if (result is TokenAttemptResult.Invalid or TokenAttemptResult.LockedOut)
            _throttleService.RegisterFailure(HttpContext);
    }

    /// <summary>
    /// Reads back the instant the host's throttle just set, so this plugin's
    /// own response body can carry it.
    /// </summary>
    /// <remarks>
    /// Taken from the header rather than asked for directly, because it is
    /// the only way to see the username half of the lockout:
    /// <see cref="IAuthenticationThrottleService.GetRemainingLockout(IUser)"/>
    /// wants an <see cref="IUser"/>, and looking one up is precisely what
    /// must not happen before the throttle has spoken. The client half is the
    /// fallback, and understates rather than invents.
    /// </remarks>
    /// <returns>When the caller may return, or <c>null</c> when it cannot be told.</returns>
    private DateTimeOffset? ThrottledUntil()
    {
        if (int.TryParse(Response.Headers.RetryAfter.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) && seconds > 0)
            return DateTimeOffset.UtcNow.AddSeconds(seconds);

        return _throttleService.GetRemainingLockout(HttpContext) is { } remaining ? DateTimeOffset.UtcNow + remaining : null;
    }

    #endregion

    private static ForgottenResponse Failure(string message)
        => new() { Success = false, Message = message };

    private ActionResult<ForgottenResponse> RateLimited(string message, DateTimeOffset? nextAllowedAt)
        => RateLimited(new ForgottenResponse { Success = false, Message = message, RetryAfter = nextAllowedAt }, nextAllowedAt);

    private ActionResult<TResponse> RateLimited<TResponse>(TResponse response, DateTimeOffset? nextAllowedAt)
    {
        if (nextAllowedAt.HasValue)
        {
            // Rounded up, never down: a Retry-After of zero invites the very
            // next request to be another refusal.
            var retryAfterSeconds = (int)Math.Max(0, Math.Ceiling((nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds));
            Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        }

        return StatusCode(429, response);
    }

    /// <summary>
    /// The address every control here is keyed by: the rate limits, and the
    /// address a reset token is bound to.
    /// </summary>
    /// <remarks>
    /// Only the <em>rightmost</em> entry of <c>X-Forwarded-For</c> is taken,
    /// and only if it parses as an address. Proxies append, so that entry is
    /// the one our own proxy wrote and everything left of it is whatever the
    /// caller chose to send. Trusting the whole chain let a caller vary the
    /// prefix to mint a fresh rate-limit bucket per request — which here
    /// meant unlimited reset-token guessing — and grew the limiter's
    /// dictionaries on strings it had written itself.
    /// </remarks>
    private bool TryGetClientIps([NotNullWhen(true)] out string? ips)
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (remoteIp is not { Length: > 0 })
        {
            ips = null;
            return false;
        }

        ips = remoteIp;
        if (!_configurationProvider.Load().TrustProxy)
            return true;

        // LastOrDefault, then the last entry within it: the header may arrive
        // as several header lines as well as one comma-separated list.
        if (RightmostForwardedAddress(Request.Headers["X-Forwarded-For"].LastOrDefault()) is { } client)
            ips = $"{client} | direct: {remoteIp}";
        return true;
    }

    /// <summary>
    /// The address our own proxy reported, or <c>null</c> when the header
    /// carries nothing we are willing to believe.
    /// </summary>
    internal static string? RightmostForwardedAddress(string? headerValue)
    {
        if (string.IsNullOrEmpty(headerValue))
            return null;

        var rightmost = headerValue.AsSpan()[(headerValue.LastIndexOf(',') + 1)..].Trim();
        return IPAddress.TryParse(rightmost, out var client) ? client.ToString() : null;
    }
}
