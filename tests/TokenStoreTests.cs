using Shoko.Plugin.Forgotten.Services;
using Xunit;

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// What a token is worth, for how long, and to whom.
/// </summary>
public class TokenStoreTests
{
    private const string Ip = "203.0.113.7";

    private const string OtherIp = "198.51.100.4";

    private static (TokenStore Store, TestTimeProvider Clock) NewStore()
    {
        var clock = new TestTimeProvider();
        return (new TokenStore(clock), clock);
    }

    private static string Issue(TokenStore store, string username, string ip = Ip)
    {
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset(username, ip, out _));
        return store.Generate(username, ip);
    }

    [Fact]
    public void A_freshly_issued_token_verifies()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", token, Ip, out _));
    }

    [Fact]
    public void A_token_is_bound_to_the_address_that_asked_for_it()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", token, OtherIp, out _));
    }

    /// <summary>
    /// Expiry has to be decided by the request, not by the sweep. The clock
    /// here moves past the lifetime while the sweep — see
    /// <see cref="TestTimeProvider"/> — never runs at all, which is exactly
    /// the situation the old code got wrong: <c>ExpiresAt</c> was written and
    /// never read, so a token lived until something else happened to notice.
    /// </summary>
    [Fact]
    public void A_token_expires_on_its_own_schedule_and_not_the_sweeps()
    {
        var (store, clock) = NewStore();
        var token = Issue(store, "admin");

        clock.Advance(TokenStore.TokenExpiry - TimeSpan.FromSeconds(1));
        Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", token, Ip, out _));

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", token, Ip, out _));
    }

    [Fact]
    public void An_expired_token_cannot_be_spent_either()
    {
        var (store, clock) = NewStore();
        var token = Issue(store, "admin");

        clock.Advance(TokenStore.TokenExpiry);
        Assert.Equal(TokenAttemptResult.Invalid, store.TryConsume("admin", token, Ip, out var ticket, out _));
        Assert.Null(ticket);
    }

    /// <summary>
    /// The host resolves usernames with <c>InvariantCultureIgnoreCase</c>, so
    /// <c>Admin</c> and <c>admin</c> are one account. The store used to
    /// compare ordinally, which meant a capitalisation the host would have
    /// accepted was not merely rejected but <em>counted as a failed
    /// attempt</em> — five of them and the account's real token was gone.
    /// </summary>
    [Theory]
    [InlineData("admin", "Admin")]
    [InlineData("Admin", "admin")]
    [InlineData("AdMiN", "aDmInX")]
    public void A_username_matches_the_way_the_host_matches_it(string issuedTo, string submittedAs)
    {
        var (store, _) = NewStore();
        var token = Issue(store, issuedTo);

        var expected = string.Equals(issuedTo, submittedAs, StringComparison.InvariantCultureIgnoreCase)
            ? TokenAttemptResult.Ok
            : TokenAttemptResult.Invalid;
        Assert.Equal(expected, store.TryVerify(submittedAs, token, Ip, out _));
    }

    [Fact]
    public void Getting_the_capitalisation_wrong_costs_nothing()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "Admin");

        for (var attempt = 0; attempt < TokenStore.MaxFailedAttemptsPerToken * 2; attempt++)
            Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", token, Ip, out _));
    }

    /// <summary>
    /// The ceiling used to be keyed on the token the guesser submitted, so
    /// every wrong guess opened a fresh counter at one and nothing ever
    /// reached five. Keyed on the account instead, guessing actually stops.
    /// </summary>
    [Fact]
    public void Guessing_at_an_account_is_bounded_however_the_guesses_are_spelled()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        for (var attempt = 0; attempt < TokenStore.MaxFailedAttemptsPerToken; attempt++)
            Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", Guess(attempt), Ip, out _));

        Assert.Equal(TokenAttemptResult.LockedOut, store.TryVerify("admin", Guess(99), Ip, out _));

        // And the real token is gone with it, which is the point of a ceiling.
        Assert.Equal(TokenAttemptResult.LockedOut, store.TryVerify("admin", token, Ip, out _));
    }

    /// <summary>
    /// Guessing against an account that has no live token creates no state at
    /// all. The old bookkeeping grew one entry per attacker-chosen string.
    /// </summary>
    [Fact]
    public void Guessing_at_an_account_with_no_token_records_nothing_about_the_guess()
    {
        var (store, _) = NewStore();

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp; attempt++)
            Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify($"ghost{attempt}", Guess(attempt), Ip, out _));

        // The address is what ran out, not memory.
        Assert.Equal(TokenAttemptResult.RateLimited, store.TryVerify("ghost", Guess(0), Ip, out _));
    }

    /// <summary>
    /// A user could previously hold several live tokens, and a reset with one
    /// left the rest armed.
    /// </summary>
    [Fact]
    public void Issuing_a_token_retires_the_one_it_replaces()
    {
        var (store, _) = NewStore();
        var first = store.Generate("admin", Ip);
        var second = store.Generate("admin", Ip);

        Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", second, Ip, out _));
        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", first, Ip, out _));
    }

    [Fact]
    public void Spending_a_token_retires_it_for_good()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        Assert.Equal(TokenAttemptResult.Ok, store.TryConsume("admin", token, Ip, out var ticket, out _));
        ticket!.Commit();

        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", token, Ip, out _));
        Assert.Equal(TokenAttemptResult.Invalid, store.TryConsume("admin", token, Ip, out _, out _));
    }

    /// <summary>
    /// The whole reason a spend is a two-step claim: if the host refuses the
    /// new password, nothing was changed, so the user must not have lost
    /// their token over it.
    /// </summary>
    [Fact]
    public void A_spend_that_changed_nothing_gives_the_token_back()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        Assert.Equal(TokenAttemptResult.Ok, store.TryConsume("admin", token, Ip, out var ticket, out _));
        ticket!.Restore();

        Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", token, Ip, out _));
    }

    /// <summary>
    /// Restoring must not resurrect a token the account has already moved on
    /// from — a newer request is the one the user is holding.
    /// </summary>
    [Fact]
    public void Restoring_never_displaces_a_newer_token()
    {
        var (store, _) = NewStore();
        var first = store.Generate("admin", Ip);
        Assert.Equal(TokenAttemptResult.Ok, store.TryConsume("admin", first, Ip, out var ticket, out _));

        var second = store.Generate("admin", Ip);
        ticket!.Restore();

        Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", second, Ip, out _));
        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", first, Ip, out _));
    }

    [Fact]
    public void A_ticket_settles_once()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");
        Assert.Equal(TokenAttemptResult.Ok, store.TryConsume("admin", token, Ip, out var ticket, out _));

        ticket!.Commit();
        ticket.Restore();

        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", token, Ip, out _));
    }

    [Fact]
    public void A_verification_that_holds_costs_the_address_nothing()
    {
        var (store, _) = NewStore();
        var token = Issue(store, "admin");

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp * 3; attempt++)
            Assert.Equal(TokenAttemptResult.Ok, store.TryVerify("admin", token, Ip, out _));

        Assert.False(store.IsAttemptBudgetExhausted(Ip, out _));
    }

    [Fact]
    public void An_address_that_has_run_out_of_attempts_is_told_when_it_may_return()
    {
        var (store, _) = NewStore();

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp; attempt++)
            store.TryVerify($"ghost{attempt}", Guess(attempt), Ip, out _);

        Assert.Equal(TokenAttemptResult.RateLimited, store.TryVerify("ghost", Guess(0), Ip, out var nextAllowedAt));
        Assert.NotNull(nextAllowedAt);
        Assert.False(store.IsAttemptBudgetExhausted(OtherIp, out _));
    }

    [Fact]
    public void An_attempt_window_rolls_over()
    {
        var (store, clock) = NewStore();

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp; attempt++)
            store.TryVerify($"ghost{attempt}", Guess(attempt), Ip, out _);

        Assert.True(store.IsAttemptBudgetExhausted(Ip, out _));
        clock.Advance(TokenStore.VerifyAttemptWindow);
        Assert.False(store.IsAttemptBudgetExhausted(Ip, out _));
    }

    [Fact]
    public void A_second_request_for_the_same_account_from_the_same_address_waits_for_the_first_to_lapse()
    {
        var (store, clock) = NewStore();
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("admin", Ip, out _));
        Assert.Equal(ResetRequestResult.AlreadyPending, store.TryStartReset("admin", Ip, out var nextAllowedAt));
        Assert.NotNull(nextAllowedAt);

        clock.Advance(TokenStore.TokenExpiry);
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("admin", Ip, out _));
    }

    /// <summary>
    /// The one-at-a-time rule has to apply to accounts that do not exist too.
    /// If it were derived from the tokens actually issued, a repeat request
    /// would be refused for a real account and allowed for an invented one —
    /// and 429-versus-200 is a perfectly serviceable account enumerator.
    /// </summary>
    [Fact]
    public void The_one_at_a_time_rule_does_not_reveal_whether_an_account_exists()
    {
        var (store, _) = NewStore();

        // No Generate call: this is the path taken when the user is unknown.
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("ghost", Ip, out _));
        Assert.Equal(ResetRequestResult.AlreadyPending, store.TryStartReset("ghost", Ip, out _));
    }

    [Fact]
    public void The_one_at_a_time_rule_ignores_capitalisation()
    {
        var (store, _) = NewStore();
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("admin", Ip, out _));
        Assert.Equal(ResetRequestResult.AlreadyPending, store.TryStartReset("ADMIN", Ip, out _));
    }

    [Fact]
    public void A_refused_request_does_not_cost_the_address_a_slot()
    {
        var (store, _) = NewStore();

        for (var attempt = 0; attempt < TokenStore.MaxResetRequestsPerIp - 1; attempt++)
            Assert.Equal(ResetRequestResult.Ok, store.TryStartReset($"user{attempt}", Ip, out _));

        // A refusal must not be charged for, so the last slot has to survive it.
        Assert.Equal(ResetRequestResult.AlreadyPending, store.TryStartReset("user0", Ip, out _));

        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("last", Ip, out _));
        Assert.Equal(ResetRequestResult.RateLimited, store.TryStartReset("overflow", Ip, out _));
    }

    [Fact]
    public void An_address_that_has_burned_its_attempts_may_not_mint_either()
    {
        var (store, _) = NewStore();

        for (var attempt = 0; attempt < TokenStore.MaxVerifyAttemptsPerIp; attempt++)
            store.TryVerify($"ghost{attempt}", Guess(attempt), Ip, out _);

        Assert.Equal(ResetRequestResult.AttemptsExhausted, store.TryStartReset("admin", Ip, out _));
    }

    [Fact]
    public void The_username_dump_is_offered_once_a_day()
    {
        var (store, clock) = NewStore();

        Assert.True(store.TryRecordUsernameRequest(out _));
        Assert.False(store.TryRecordUsernameRequest(out var nextAllowedAt));
        Assert.NotNull(nextAllowedAt);

        clock.Advance(TokenStore.UsernameRequestCooldown);
        Assert.True(store.TryRecordUsernameRequest(out _));
    }

    /// <summary>
    /// The sweep is a memory sweep and nothing else — everything above
    /// already expires by the clock. This is here so that a future change
    /// which quietly makes the sweep load-bearing again shows up.
    /// </summary>
    [Fact]
    public void The_sweep_changes_no_answer_it_is_not_already_giving()
    {
        var (store, clock) = NewStore();
        var token = Issue(store, "admin");

        clock.Advance(TokenStore.TokenExpiry);
        store.RunCleanup();

        Assert.Equal(TokenAttemptResult.Invalid, store.TryVerify("admin", token, Ip, out _));
        Assert.Equal(ResetRequestResult.Ok, store.TryStartReset("admin", Ip, out _));
    }

    private static string Guess(int seed)
        => seed.ToString("X12", System.Globalization.CultureInfo.InvariantCulture);
}
