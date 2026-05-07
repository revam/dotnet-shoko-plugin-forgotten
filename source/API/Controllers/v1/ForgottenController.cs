using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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
            return StatusCode(400, new ForgottenResponse
            {
                Success = false,
                Message = "Unable to determine client IP address."
            });
        }

        // Check if IP has been locked out from excessive failed attempts
        if (!_tokenStore.CanAttemptVerify(ips, out var nextAllowedAt))
        {
            _logger.LogWarning("Password reset request denied for username: {Username} — IP locked out from too many failed attempts. Client IPs: {IPs}", request.Username, ips);
            var response = new ForgottenResponse
            {
                Success = false,
                Message = "Too many failed attempts. Please try again later."
            };
            if (nextAllowedAt.HasValue)
            {
                response.RetryAfter = nextAllowedAt.Value;
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        // Check rate limits
        if (!_tokenStore.CanRequestReset(ips, request.Username, out nextAllowedAt))
        {
            _logger.LogWarning("Password reset request denied for username: {Username} due to rate limiting. Client IPs: {IPs}", request.Username, ips);
            var response = new ForgottenResponse
            {
                Success = false,
                Message = "Rate limit exceeded. Please try again later."
            };
            if (nextAllowedAt.HasValue)
            {
                response.RetryAfter = nextAllowedAt.Value;
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        // Record the request for rate limiting
        _tokenStore.RecordResetRequest(ips, request.Username);

        var user = _userService.GetUserByUsername(request.Username);
        if (user is not null)
        {
            var token = _tokenStore.Generate(request.Username, ips);
            _logger.LogInformation("Reset token for user {Username}: {Token}. Client IPs: {IPs}", request.Username, token, ips);
        }
        else
        {
            // Dummy operation to prevent timing-based username enumeration
            // Must match the cost of Generate above (cryptographic token)
            _tokenStore.GenerateDummy();
            _logger.LogWarning("Password reset requested for username: {Username}. Client IPs: {IPs}", request.Username, ips);
        }

        return Ok(new ForgottenResponse { Message = "If the username exists, a reset code has been logged." });
    }

    /// <summary>
    /// Verifies if a reset token is valid for the specified username.
    /// </summary>
    /// <param name="request">The request containing the username and token.</param>
    /// <returns>An action result containing the validation response.</returns>
    [HttpPost("VerifyToken")]
    public ActionResult<ForgottenResponse> VerifyToken([FromBody] VerifyTokenRequest request)
    {
        if (!TryGetClientIps(out var ips))
        {
            _logger.LogError("Token verification denied — unable to determine client IP address");
            return StatusCode(400, new ForgottenResponse
            {
                Success = false,
                Message = "Unable to determine client IP address."
            });
        }

        if (!_tokenStore.IsValidTokenFormat(request.Token))
        {
            return StatusCode(400, new ForgottenResponse
            {
                Success = false,
                Message = "Invalid token format. Token must be 12 hexadecimal characters."
            });
        }

        // Check IP rate limiting
        if (!_tokenStore.CanAttemptVerify(ips, out var nextAllowedAt))
        {
            _logger.LogWarning("Token verification rate limited for IP: {IPs}", ips);
            var response = new ForgottenResponse
            {
                Success = false,
                Message = "Too many attempts. Please try again later."
            };
            if (nextAllowedAt.HasValue)
            {
                response.RetryAfter = nextAllowedAt.Value;
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        // Attempt verification (doesn't decrement attempts if valid)
        var allowed = _tokenStore.TryVerify(request.Username, request.Token, ips, out var isValid);
        if (!allowed)
        {
            _logger.LogWarning("Token verification blocked - token locked out for username: {Username}", request.Username);
            return StatusCode(403, new ForgottenResponse
            {
                Success = false,
                Message = "Token has been locked due to too many failed attempts."
            });
        }

        // Only record the attempt if the token was invalid
        // This preserves attempts for valid tokens to be used in ResetPassword
        if (!isValid)
        {
            _tokenStore.RecordVerifyAttempt(ips);
        }

        return Ok(new ForgottenResponse { Valid = isValid });
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
            return StatusCode(400, new ForgottenResponse
            {
                Success = false,
                Message = "Unable to determine client IP address."
            });
        }

        if (!_tokenStore.IsValidTokenFormat(request.Token))
        {
            return StatusCode(400, new ForgottenResponse
            {
                Success = false,
                Message = "Invalid token format. Token must be 12 hexadecimal characters."
            });
        }

        // Check IP rate limiting
        if (!_tokenStore.CanAttemptVerify(ips, out var nextAllowedAt))
        {
            _logger.LogWarning("Password reset rate limited for IP: {IPs}", ips);
            var response = new ForgottenResponse
            {
                Success = false,
                Message = "Too many attempts. Please try again later."
            };
            if (nextAllowedAt.HasValue)
            {
                response.RetryAfter = nextAllowedAt.Value;
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        _logger.LogWarning("Password reset attempt for username: {Username}. Client IPs: {IPs}", request.Username, ips);

        // Attempt to consume the token
        var allowed = _tokenStore.TryConsume(request.Username, request.Token, ips, out var consumed);
        if (!allowed)
        {
            _logger.LogWarning("Password reset blocked - token locked out for username: {Username}", request.Username);
            return StatusCode(403, new ForgottenResponse
            {
                Success = false,
                Message = "Token has been locked due to too many failed attempts."
            });
        }

        // Record the attempt regardless of outcome
        _tokenStore.RecordVerifyAttempt(ips);

        if (!consumed)
        {
            _logger.LogWarning("Password reset failed — invalid/expired token or IP mismatch for username: {Username}. Client IPs: {IPs}", request.Username, ips);
            return StatusCode(403, new ForgottenResponse { Success = false, Message = "Invalid or expired token." });
        }

        var user = _userService.GetUserByUsername(request.Username);
        if (user is null)
        {
            _logger.LogWarning("Password reset failed — user {Username} no longer exists after token verification. Client IPs: {IPs}", request.Username, ips);
            return StatusCode(403, new ForgottenResponse { Success = false, Message = "Invalid or expired token." });
        }

        await _userService.ChangeUserPassword(user, request.NewPassword);
        await _userService.InvalidateRestApiTokensForUser(user);

        _logger.LogWarning("Password reset successful for user: {Username}. Client IPs: {IPs}", request.Username, ips);

        return Ok(new ForgottenResponse { Success = true, Message = "Password has been reset. All API tokens have been revoked." });
    }

    /// <summary>
    /// Checks if the plugin is installed and operational.
    /// </summary>
    /// <returns>An empty 200 OK response.</returns>
    [HttpGet("Status")]
    public IActionResult GetStatus()
    {
        return Ok();
    }

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

        // Check if IP has been locked out from excessive failed attempts
        if (!_tokenStore.CanAttemptVerify(ips, out var nextAllowedAt))
        {
            _logger.LogWarning("Username recovery request denied — IP locked out from too many failed attempts. Client IPs: {IPs}", ips);
            var response = new RequestUsernamesResponse
            {
                Message = "Too many failed attempts. Please try again later.",
                RetryAfter = nextAllowedAt
            };
            if (nextAllowedAt.HasValue)
            {
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        // Check global rate limit (24h cooldown)
        if (!_tokenStore.CanRequestUsernames(out nextAllowedAt))
        {
            _logger.LogWarning("Username recovery request denied due to global rate limiting. Client IPs: {IPs}", ips);
            var response = new RequestUsernamesResponse
            {
                Message = "Username recovery can only be requested once every 24 hours.",
                RetryAfter = nextAllowedAt
            };
            if (nextAllowedAt.HasValue)
            {
                var retryAfterSeconds = (int)(nextAllowedAt.Value - DateTimeOffset.UtcNow).TotalSeconds;
                Response.Headers.RetryAfter = retryAfterSeconds.ToString();
            }
            return StatusCode(429, response);
        }

        _logger.LogWarning("Username recovery requested. Client IPs: {IPs}", ips);
        _tokenStore.RecordUsernameRequest();

        var users = _userService.GetUsers();
        foreach (var user in users)
            _logger.LogWarning("Registered username: {Username}", user.Username);

        return Ok(new RequestUsernamesResponse
        {
            RequestedAt = DateTimeOffset.UtcNow,
            RetryAfter = DateTimeOffset.UtcNow.AddDays(1)
        });
    }

    private bool TryGetClientIps([NotNullWhen(true)] out string? ips)
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (remoteIp is not { Length: > 0 })
        {
            ips = null;
            return false;
        }

        var forwardedFor = _configurationProvider.Load().TrustProxy
            ? Request.Headers["X-Forwarded-For"].FirstOrDefault()
            : null;
        if (!string.IsNullOrEmpty(forwardedFor))
            ips = $"{forwardedFor} | direct: {remoteIp ?? "unknown"}";
        else
            ips = remoteIp;
        return true;
    }
}
