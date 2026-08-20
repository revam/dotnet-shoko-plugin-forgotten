using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Shoko.Abstractions.Config;
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
/// <param name="configurationProvider">The configuration provider.</param>
/// <param name="logger">The logger instance.</param>
[ApiController]
[Route("/api/plugin/Forgotten/v1")]
public class ForgottenController(
    IUserService userService,
    TokenStore tokenStore,
    ConfigurationProvider<ForgottenPluginConfiguration> configurationProvider,
    ILogger<ForgottenController> logger) : ControllerBase
{
    private readonly IUserService _userService = userService;

    private readonly TokenStore _tokenStore = tokenStore;

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

        var outcome = _tokenStore.TryStartReset(username, ips, out var nextAllowedAt);
        if (outcome is not ResetRequestResult.Ok)
        {
            _logger.LogWarning("Password reset request denied for username {Username}: {Reason}. Client IPs: {IPs}", username, outcome, ips);
            return RateLimited(outcome switch
            {
                ResetRequestResult.AttemptsExhausted => "Too many failed attempts. Please try again later.",
                ResetRequestResult.AlreadyPending => "A reset code has already been issued. Please use it or wait for it to expire.",
                _ => "Rate limit exceeded. Please try again later.",
            }, nextAllowedAt);
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
            _tokenStore.GenerateDummy();
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

        var result = _tokenStore.TryVerify(request.Username, request.Token, ips, out var nextAllowedAt);
        switch (result)
        {
            case TokenAttemptResult.Malformed:
                return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

            case TokenAttemptResult.RateLimited:
                _logger.LogWarning("Token verification rate limited for IP: {IPs}", ips);
                return RateLimited("Too many attempts. Please try again later.", nextAllowedAt);

            case TokenAttemptResult.LockedOut:
                _logger.LogWarning("Token verification blocked — the token has taken too many failed attempts. Client IPs: {IPs}", ips);
                return StatusCode(403, Failure("Token has been locked due to too many failed attempts."));

            default:
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

        var result = _tokenStore.TryConsume(request.Username, request.Token, ips, out var ticket, out var nextAllowedAt);
        switch (result)
        {
            case TokenAttemptResult.Malformed:
                return StatusCode(400, Failure("Invalid username or token format. A token is 12 hexadecimal characters."));

            case TokenAttemptResult.RateLimited:
                _logger.LogWarning("Password reset rate limited for IP: {IPs}", ips);
                return RateLimited("Too many attempts. Please try again later.", nextAllowedAt);

            case TokenAttemptResult.LockedOut:
                _logger.LogWarning("Password reset blocked — the token has taken too many failed attempts. Client IPs: {IPs}", ips);
                return StatusCode(403, Failure("Token has been locked due to too many failed attempts."));

            case not TokenAttemptResult.Ok:
                _logger.LogWarning("Password reset failed — invalid or expired token, or address mismatch. Client IPs: {IPs}", ips);
                return StatusCode(403, Failure("Invalid or expired token."));
        }

        var user = _userService.GetUserByUsername(request.Username);
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

        if (_tokenStore.IsAttemptBudgetExhausted(ips, out var nextAllowedAt))
        {
            _logger.LogWarning("Username recovery request denied — IP locked out from too many failed attempts. Client IPs: {IPs}", ips);
            return RateLimited(new RequestUsernamesResponse
            {
                Message = "Too many failed attempts. Please try again later.",
                RetryAfter = nextAllowedAt,
            }, nextAllowedAt);
        }

        // Claiming the cooldown and dumping the names is one operation, so
        // two requests arriving together cannot both find the cooldown clear.
        if (!_tokenStore.TryRecordUsernameRequest(out nextAllowedAt))
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

    private static ForgottenResponse Failure(string message)
        => new() { Success = false, Message = message };

    private ActionResult<ForgottenResponse> RateLimited(string message, DateTimeOffset? nextAllowedAt)
        => RateLimited(new ForgottenResponse { Success = false, Message = message, RetryAfter = nextAllowedAt }, nextAllowedAt);

    private ActionResult<TResponse> RateLimited<TResponse>(TResponse response, DateTimeOffset? nextAllowedAt)
    {
        if (nextAllowedAt.HasValue)
        {
            var retryAfterSeconds = (int)Math.Max(0, (nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds);
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
