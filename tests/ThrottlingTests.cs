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
/// Which bucket a reset attempt is counted in, who is shut out when one
/// fills up, and what the host is told the attempt was for.
/// </summary>
/// <remarks>
/// <para>
/// The guessing counter is the host's, shared with the core sign-in and with
/// every other plugin, so the properties worth pinning down are the ones a
/// shared store makes easy to get wrong: that a wrong code is charged to the
/// client and never to the account it named, that the host is asked about a
/// username and never about a code, that the question is asked before the
/// account is looked up, and that a lockout earned anywhere is honoured here.
/// </para>
/// <para>
/// The last of those is the whole point of adopting it. Locking a client out
/// of guessing reset codes is worth little if the same client can go on
/// guessing passwords at the front door.
/// </para>
/// </remarks>
public class ThrottlingTests
{
    private const string Ip = "203.0.113.7";

    private sealed record Harness(
        ForgottenController Controller,
        FakeUserService Users,
        TokenStore Store,
        FakeAuthenticationThrottleService Throttle);

    private static Harness NewHarness()
    {
        var store = new TokenStore(new TestTimeProvider());
        var users = new FakeUserService();
        var throttle = new FakeAuthenticationThrottleService();
        var provider = new ConfigurationProvider<ForgottenPluginConfiguration>(new FakeConfigurationService(new ForgottenPluginConfiguration()));
        var controller = new ForgottenController(users, store, throttle, provider, NullLogger<ForgottenController>.Instance)
        {
            ControllerContext = new()
            {
                HttpContext = new DefaultHttpContext
                {
                    Connection = { RemoteIpAddress = IPAddress.Parse(Ip) },
                },
            },
        };

        return new(controller, users, store, throttle);
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

    #region A code that checked out against nothing

    [Fact]
    public void A_wrong_code_is_charged_to_the_client()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        var result = harness.Controller.VerifyToken(new() { Username = "admin", Token = "0000-0000-0001" });

        Assert.Equal(200, StatusOf(result));
        Assert.False(BodyOf(result).Valid);
        Assert.Equal(1, harness.Throttle.ClientFailures);
    }

    [Fact]
    public async Task A_wrong_code_spent_on_a_reset_is_charged_to_the_client()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = "0000-0000-0001", NewPassword = "hunter2" });

        Assert.Equal(403, StatusOf(result));
        Assert.Equal(1, harness.Throttle.ClientFailures);
    }

    /// <summary>
    /// The account's own credential was never in question, and the username
    /// here is whatever the request said it was — so charging it would let
    /// anyone who can spell a name lock its owner out of signing in.
    /// </summary>
    [Fact]
    public void A_wrong_code_is_never_charged_to_the_account()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        for (var attempt = 0; attempt < 20; attempt++)
            harness.Controller.VerifyToken(new() { Username = "admin", Token = attempt.ToString("X12") });

        Assert.Equal(20, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
    }

    /// <summary>
    /// The host files usernames and client addresses in separate namespaces
    /// and logs the username it was asked about at warning level, so a code
    /// in that slot would both share a real account's lockout and write a
    /// live secret to the console.
    /// </summary>
    [Fact]
    public async Task The_host_is_asked_about_the_username_and_never_about_the_code()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        harness.Controller.RequestReset(new() { Username = "admin" });
        harness.Controller.VerifyToken(new() { Username = "admin", Token = token });
        await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(3, harness.Throttle.Checks);
        Assert.All(harness.Throttle.UsernamesChecked, username => Assert.Equal("admin", username));
    }

    /// <summary>
    /// The trimmed name, not the one off the wire: the host matches names the
    /// way this plugin does, and an untrimmed one would open a bucket of its
    /// own that no other endpoint would ever consult.
    /// </summary>
    [Fact]
    public void The_host_is_asked_about_the_name_this_plugin_would_use()
    {
        var harness = NewHarness();

        harness.Controller.RequestReset(new() { Username = "  admin  " });

        Assert.Equal(["admin"], harness.Throttle.UsernamesChecked);
    }

    /// <summary>
    /// A lockout can only exist for an account with a live token, so an
    /// answer of "locked" is an answer of "this account exists and has a
    /// reset in flight". It has to cost what a wrong guess costs, or the
    /// difference is the same disclosure by another route.
    /// </summary>
    [Fact]
    public void A_locked_code_costs_the_client_what_a_wrong_one_costs()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        for (var attempt = 0; attempt < TokenStore.MaxFailedAttemptsPerToken; attempt++)
            harness.Controller.VerifyToken(new() { Username = "admin", Token = attempt.ToString("X12") });

        var charged = harness.Throttle.ClientFailures;
        harness.Controller.VerifyToken(new() { Username = "admin", Token = "0000-0000-0099" });

        Assert.Equal(charged + 1, harness.Throttle.ClientFailures);
    }

    #endregion

    #region A code the caller was given

    [Fact]
    public void A_code_that_holds_is_charged_to_nobody()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = harness.Controller.VerifyToken(new() { Username = "admin", Token = token });

        Assert.True(BodyOf(result).Valid);
        Assert.Equal(0, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
    }

    /// <summary>
    /// Verification answers a question rather than performing a reset, and
    /// the same code answers it for as long as it lives — so clearing the
    /// host's ledger here would hand whoever holds one code an unlimited
    /// supply of fresh password guesses at every other door.
    /// </summary>
    [Fact]
    public void A_verification_that_holds_clears_nothing()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        for (var attempt = 0; attempt < 5; attempt++)
            harness.Controller.VerifyToken(new() { Username = "admin", Token = token });

        Assert.Equal(0, harness.Throttle.ClientResets);
        Assert.Equal(0, harness.Throttle.UserResets);
    }

    /// <summary>
    /// A string that could not be a code was never a guess at one: it is
    /// decided from its shape alone, without an account being consulted.
    /// </summary>
    [Fact]
    public async Task A_malformed_code_is_charged_to_nobody()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        TokenFor(harness, "admin");

        Assert.Equal(400, StatusOf(harness.Controller.VerifyToken(new() { Username = "admin", Token = "not-a-token" })));
        Assert.Equal(400, StatusOf(await harness.Controller.ResetPassword(new() { Username = "admin", Token = "not-a-token", NewPassword = "hunter2" })));

        Assert.Equal(0, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
    }

    /// <summary>
    /// A correct code the host then refused to act on is nobody's wrong
    /// guess. The caller held the secret; something else went wrong.
    /// </summary>
    [Fact]
    public async Task A_reset_the_host_refused_is_charged_to_nobody()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");
        harness.Users.PasswordChangeFailure = () => new InvalidOperationException("the host said no");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(500, StatusOf(result));
        Assert.Equal(0, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
    }

    /// <summary>
    /// The same, for the account that went away between the code being issued
    /// and being spent. The 403 is indistinguishable from a wrong code on the
    /// wire, but the caller did not guess anything.
    /// </summary>
    [Fact]
    public async Task A_reset_for_an_account_that_went_away_is_charged_to_nobody()
    {
        var harness = NewHarness();
        var token = TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(403, StatusOf(result));
        Assert.Equal(0, harness.Throttle.ClientFailures);
    }

    /// <summary>
    /// The one place an account's credential actually changes. Every failure
    /// counted against the old one is stale, and the person this plugin
    /// exists for is somebody the host has already locked out for forgetting
    /// it — leaving the lockout standing would let them complete a reset and
    /// still not be able to sign in.
    /// </summary>
    [Fact]
    public async Task A_completed_reset_clears_both_the_client_and_the_account()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" });

        Assert.Equal(200, StatusOf(result));
        Assert.Equal(1, harness.Throttle.ClientResets);
        Assert.Equal(1, harness.Throttle.UserResets);
    }

    #endregion

    #region A lockout earned elsewhere

    [Fact]
    public void A_locked_out_client_cannot_ask_for_a_code()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.ClientLockout = TimeSpan.FromMinutes(15);

        var result = harness.Controller.RequestReset(new() { Username = "admin" });

        Assert.Equal(429, StatusOf(result));
        Assert.False(BodyOf(result).Success);
    }

    /// <summary>
    /// A refusal must not cost the caller the slot it was refused, or a
    /// client that waits out its lockout finds a reset already pending for a
    /// request it never got to make.
    /// </summary>
    [Fact]
    public void A_refused_request_leaves_the_reset_slot_untouched()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.ClientLockout = TimeSpan.FromMinutes(15);

        Assert.Equal(429, StatusOf(harness.Controller.RequestReset(new() { Username = "admin" })));

        harness.Throttle.ClientLockout = null;
        Assert.Equal(200, StatusOf(harness.Controller.RequestReset(new() { Username = "admin" })));
    }

    /// <summary>
    /// The account dimension is read as well as the client one, so a name the
    /// host has shut out cannot be driven through this plugin either.
    /// </summary>
    [Fact]
    public void A_locked_out_account_cannot_be_driven_through_a_reset_request()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.UsernameLockout = TimeSpan.FromMinutes(15);

        Assert.Equal(429, StatusOf(harness.Controller.RequestReset(new() { Username = "admin" })));
    }

    /// <summary>
    /// The throttle is asked before the account is looked up, so a name the
    /// host has locked out and a name it has never heard of answer the same
    /// way. The host counts failures for any username it is given, existing
    /// or not, which is what makes that answer say nothing.
    /// </summary>
    [Fact]
    public void A_name_the_host_never_heard_of_is_refused_exactly_as_a_real_one_is()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.UsernameLockout = TimeSpan.FromMinutes(15);

        var known = harness.Controller.RequestReset(new() { Username = "admin" });
        var unknown = harness.Controller.RequestReset(new() { Username = "ghost" });

        Assert.Equal(StatusOf(known), StatusOf(unknown));
        Assert.Equal(BodyOf(known).Message, BodyOf(unknown).Message);
        Assert.Equal(0, harness.Users.PasswordChanges);
    }

    /// <summary>
    /// Asking for a code is not an attempt at one, so a refusal here is
    /// honoured but never counted.
    /// </summary>
    [Fact]
    public void Asking_for_a_code_is_charged_to_nobody()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.ClientLockout = TimeSpan.FromMinutes(15);

        harness.Controller.RequestReset(new() { Username = "admin" });
        harness.Throttle.ClientLockout = null;
        harness.Controller.RequestReset(new() { Username = "admin" });

        Assert.Equal(0, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
    }

    [Fact]
    public void A_locked_out_client_cannot_collect_the_usernames()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.ClientLockout = TimeSpan.FromMinutes(15);

        var result = harness.Controller.RequestUsernames();

        Assert.Equal(429, StatusOf(result));
        Assert.NotNull(BodyOf(result).RetryAfter);

        // And the daily cooldown was not spent on a request that was refused.
        harness.Throttle.ClientLockout = null;
        Assert.Equal(200, StatusOf(harness.Controller.RequestUsernames()));
    }

    [Fact]
    public void Collecting_the_usernames_is_charged_to_nobody()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");

        harness.Controller.RequestUsernames();
        harness.Controller.RequestUsernames();

        Assert.Equal(0, harness.Throttle.ClientFailures);
        Assert.Equal(0, harness.Throttle.UserFailures);
        Assert.Equal(0, harness.Throttle.Checks);
    }

    /// <summary>
    /// The host writes <c>Retry-After</c> itself; this plugin's own body
    /// carries the same instant, because the wizard reads it from there.
    /// </summary>
    [Fact]
    public async Task A_locked_out_caller_is_told_when_it_may_return()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        harness.Throttle.UsernameLockout = TimeSpan.FromMinutes(30);

        var result = await harness.Controller.ResetPassword(new() { Username = "admin", Token = "0000-0000-0001", NewPassword = "hunter2" });

        Assert.Equal(429, StatusOf(result));
        var retryAfter = BodyOf(result).RetryAfter;
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(29), TimeSpan.FromMinutes(31));
        Assert.Equal("1800", harness.Controller.Response.Headers.RetryAfter.ToString());
    }

    /// <summary>
    /// A caller refused by the lockout has not reached the store, so it has
    /// not spent a code either.
    /// </summary>
    [Fact]
    public async Task A_refused_reset_does_not_spend_the_code()
    {
        var harness = NewHarness();
        harness.Users.Add("admin");
        var token = TokenFor(harness, "admin");
        harness.Throttle.ClientLockout = TimeSpan.FromMinutes(15);

        Assert.Equal(429, StatusOf(await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" })));

        harness.Throttle.ClientLockout = null;
        Assert.Equal(200, StatusOf(await harness.Controller.ResetPassword(new() { Username = "admin", Token = token, NewPassword = "hunter2" })));
        Assert.Equal("hunter2", harness.Users.LastPasswordSet);
    }

    #endregion
}
