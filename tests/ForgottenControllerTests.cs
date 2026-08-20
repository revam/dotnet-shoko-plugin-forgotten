using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Shoko.Abstractions.Config;
using Shoko.Plugin.Forgotten.API.Controllers.v1;
using Shoko.Plugin.Forgotten.API.Models;
using Shoko.Plugin.Forgotten.Configuration;
using Shoko.Plugin.Forgotten.Services;
using Xunit;

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// The contract the endpoints actually present: which status codes, which
/// flags, and — the expensive one — what a request has cost the caller by
/// the time it is refused.
/// </summary>
public class ForgottenControllerTests
{
    private const string Ip = "203.0.113.7";

    private sealed record Harness(ForgottenController Controller, FakeUserService Users, TokenStore Store, TestTimeProvider Clock);

    private static Harness NewHarness(string ip = Ip)
    {
        var clock = new TestTimeProvider();
        var store = new TokenStore(clock);
        var users = new FakeUserService();
        var provider = new ConfigurationProvider<ForgottenPluginConfiguration>(new FakeConfigurationService(new ForgottenPluginConfiguration()));
        var controller = new ForgottenController(users, store, provider, NullLogger<ForgottenController>.Instance)
        {
            ControllerContext = new()
            {
                HttpContext = new DefaultHttpContext
                {
                    Connection = { RemoteIpAddress = IPAddress.Parse(ip) },
                },
            },
        };

        return new(controller, users, store, clock);
    }

    private static int StatusOf<T>(ActionResult<T> result)
        => result.Result switch
        {
            ObjectResult objectResult => objectResult.StatusCode ?? 200,
            StatusCodeResult statusResult => statusResult.StatusCode,
            _ => 200,
        };

    private static T BodyOf<T>(ActionResult<T> result)
        => (T)((ObjectResult)result.Result!).Value!;

    private static string TokenFor(Harness harness, string username)
    {
        Assert.Equal(ResetRequestResult.Ok, harness.Store.TryStartReset(username, Ip, out _));
        return harness.Store.Generate(username, Ip);
    }

    /// <summary>
    /// The happy paths returned 200 with <c>success: false</c>, because the
    /// flag defaults to false and nobody set it.
    /// </summary>
    [Fact]
    public void A_reset_request_that_worked_says_so()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");

        var result = harness.Controller.RequestReset(new() { Username = "admin" });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Success);
    }

    [Fact]
    public void A_verification_that_worked_says_so()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = harness.Controller.VerifyToken(new() { Username = "admin", Token = token });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Success);
        Assert.True(BodyOf(result).Valid);
    }

    /// <summary>
    /// A token that does not check out is a 200 saying so, not a status that
    /// distinguishes why. See the endpoint's own remarks — and the README,
    /// which used to claim otherwise.
    /// </summary>
    [Fact]
    public void A_verification_that_did_not_work_is_still_a_successful_answer()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        var result = harness.Controller.VerifyToken(new() { Username = "admin", Token = "0000-0000-0001" });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Success);
        Assert.False(BodyOf(result).Valid);
    }

    [Fact]
    public async Task A_reset_that_did_not_work_is_refused_outright()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = "0000-0000-0001", NewPassword = "hunter2" });

        Assert.Equal(403, StatusOf(result));
        Assert.False(BodyOf(result).Success);
        Assert.Equal(0, harness.Users.PasswordChanges);
    }

    [Fact]
    public async Task A_reset_that_worked_reports_success_and_revokes_the_keys()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Success);
        Assert.Equal("hunter2", harness.Users.LastPasswordSet);
        Assert.Equal(1, harness.Users.TokenRevocations);
    }

    /// <summary>
    /// Shoko supports passwordless accounts on purpose, so this endpoint has
    /// no business refusing one.
    /// </summary>
    [Fact]
    public async Task An_empty_password_is_a_password()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = string.Empty });

        Assert.Equal(200, StatusOf(result));
        Assert.Equal(string.Empty, harness.Users.LastPasswordSet);
    }

    /// <summary>
    /// The expensive bug: the token was spent, and only then was the password
    /// handed to a host that rejects anything over 1024 characters with an
    /// uncaught validation exception. The caller got a 500 and no longer had
    /// a token to try again with.
    /// </summary>
    [Fact]
    public async Task An_overlong_password_is_refused_without_costing_the_token()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new()
        {
            Username = "admin",
            Token = token,
            NewPassword = new string('x', TokenStore.MaxPasswordLength + 1),
        });

        Assert.Equal(400, StatusOf(result));
        Assert.False(BodyOf(result).Success);
        Assert.Equal(0, harness.Users.PasswordChanges);

        // And the token is still there, which is the half that used to be lost.
        var retry = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });
        Assert.Equal(200, StatusOf(retry));
        Assert.Equal("hunter2", harness.Users.LastPasswordSet);
    }

    /// <summary>
    /// The same property, for a failure this plugin cannot predict: if the
    /// host refuses for any reason, nothing changed, so the token was not
    /// really spent.
    /// </summary>
    [Fact]
    public async Task A_host_that_refuses_does_not_cost_the_token_either()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");
        harness.Users.PasswordChangeFailure = () => new InvalidOperationException("the host said no");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });
        Assert.Equal(500, StatusOf(result));

        harness.Users.PasswordChangeFailure = null;
        var retry = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });
        Assert.Equal(200, StatusOf(retry));
    }

    /// <summary>
    /// If the keys could not be revoked the password change still stands, so
    /// the answer is a success — but it must not claim the revocation
    /// happened.
    /// </summary>
    [Fact]
    public async Task A_reset_whose_keys_survived_says_which_half_worked()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");
        harness.Users.TokenRevocationFailure = () => new InvalidOperationException("the host said no");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Success);
        Assert.Contains("could not be revoked", BodyOf(result).Message, StringComparison.Ordinal);
        Assert.Equal(1, harness.Users.PasswordChanges);
    }

    /// <summary>
    /// The host resolves a username with <c>InvariantCultureIgnoreCase</c>,
    /// so a token issued to <c>Admin</c> has to answer to <c>ADMIN</c>. It
    /// used to be compared ordinally, which turned a capitalisation the host
    /// would have accepted into a failed attempt against the real token.
    /// </summary>
    [Fact]
    public void The_host_resolves_usernames_case_insensitively_and_so_does_this()
    {
        var harness = NewHarness();
        harness.Users.Add("Admin");
        var token = TokenFor(harness, "Admin");

        var result = harness.Controller.VerifyToken(new() { Username = "ADMIN", Token = token });

        Assert.Equal(200, StatusOf(result));
        Assert.True(BodyOf(result).Valid);
    }

    /// <summary>
    /// A username carrying a newline could write a second console line that
    /// reads exactly like a token line for somebody else's account, and the
    /// console is where tokens are delivered.
    /// </summary>
    [Theory]
    [InlineData("admin\nReset token for user root: AAAA-BBBB-CCCC")]
    [InlineData("")]
    public void A_username_that_is_not_a_username_never_reaches_a_log_line(string username)
    {
        var harness = NewHarness();
        var result = harness.Controller.RequestReset(new() { Username = username });

        Assert.Equal(400, StatusOf(result));
        Assert.False(BodyOf(result).Success);
    }

    [Fact]
    public async Task A_malformed_token_is_a_bad_request_and_not_a_lockout()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");

        var verify = harness.Controller.VerifyToken(new() { Username = "admin", Token = "not-a-token" });
        Assert.Equal(400, StatusOf(verify));

        var reset = await harness.Controller.ResetPassword(new() { Username = "admin", Token = "not-a-token", NewPassword = "hunter2" });
        Assert.Equal(400, StatusOf(reset));
    }

    [Fact]
    public void An_address_out_of_attempts_gets_a_429_and_a_retry_after_header()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp; attempt++)
            harness.Controller.VerifyToken(new() { Username = $"ghost{attempt}", Token = attempt.ToString("X12") });

        var result = harness.Controller.VerifyToken(new() { Username = "admin", Token = "0000-0000-0001" });

        Assert.Equal(429, StatusOf(result));
        Assert.NotNull(BodyOf(result).RetryAfter);
        Assert.False(string.IsNullOrEmpty(harness.Controller.Response.Headers.RetryAfter));
    }

    [Fact]
    public void The_username_dump_is_offered_once_and_then_refused()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Users.Add("root");

        Assert.Equal(200, StatusOf(harness.Controller.RequestUsernames()));
        var second = harness.Controller.RequestUsernames();
        Assert.Equal(429, StatusOf(second));
        Assert.NotNull(BodyOf(second).RetryAfter);
    }

}
