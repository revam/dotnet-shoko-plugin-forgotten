using System.Collections.Concurrent;
using Shoko.Plugin.Forgotten.Services;
using Xunit;

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// A rate limit is only a rate limit if it holds when requests arrive
/// together.
/// </summary>
/// <remarks>
/// <para>
/// Every limit here used to be a <c>Can…</c> predicate the controller called,
/// followed by a separate <c>Record…</c> it called afterwards. Between those
/// two calls the budget was unclaimed, so any number of requests that got
/// there at once all read the same "yes". Worse, two of the predicates
/// rewrote the window entry when they judged it stale, which threw away
/// whatever a concurrent <c>Record…</c> had just counted.
/// </para>
/// <para>
/// These tests fail against that shape and pass against a limiter that
/// decides and records in one operation. They are the reason the store took
/// a lock: the property being asserted is not "the counter is atomic" but
/// "the decision and the counter cannot disagree".
/// </para>
/// </remarks>
public class RateLimitConcurrencyTests
{
    private const string Ip = "203.0.113.7";

    private const int Racers = 64;

    /// <summary>
    /// Runs <paramref name="work"/> on many threads at once, released
    /// together so they genuinely contend.
    /// </summary>
    private static IReadOnlyList<T> RaceEveryone<T>(Func<int, T> work)
    {
        var results = new ConcurrentBag<T>();
        using var gate = new Barrier(Racers);
        var threads = Enumerable.Range(0, Racers)
            .Select(index => new Thread(() =>
            {
                gate.SignalAndWait();
                results.Add(work(index));
            }))
            .ToArray();

        foreach (var thread in threads)
            thread.Start();
        foreach (var thread in threads)
            thread.Join();

        return [.. results];
    }

    [Fact]
    public void An_address_gets_its_daily_tokens_and_no_more_however_they_arrive()
    {
        using var store = new TokenStore(new TestTimeProvider());

        var results = RaceEveryone(index => store.TryStartReset($"user{index}", Ip, out _));

        Assert.Equal(TokenStore.MaxResetRequestsPerIp, results.Count(result => result is ResetRequestResult.Ok));
    }

    [Fact]
    public void An_address_gets_its_daily_attempts_and_no_more_however_they_arrive()
    {
        using var store = new TokenStore(new TestTimeProvider());

        // Distinct accounts, so nothing is stopped early by an account's own
        // ceiling and the address budget is the only thing being tested.
        var results = RaceEveryone(index => store.TryVerify($"ghost{index}", index.ToString("X12"), Ip, out _));

        Assert.Equal(TokenStore.MaxVerifyAttemptsPerIp, results.Count(result => result is TokenAttemptResult.Invalid));
        Assert.Equal(Racers - TokenStore.MaxVerifyAttemptsPerIp, results.Count(result => result is TokenAttemptResult.RateLimited));
    }

    [Fact]
    public void An_account_takes_its_ceiling_of_wrong_guesses_and_no_more()
    {
        var clock = new TestTimeProvider();
        using var store = new TokenStore(clock);
        store.Generate("admin", Ip);

        // Address budget out of the way: this is about the per-account
        // ceiling, which is the smaller of the two.
        var results = RaceEveryone(index => store.TryVerify("admin", index.ToString("X12"), Ip, out _));

        Assert.Equal(TokenStore.MaxFailedAttemptsPerToken, results.Count(result => result is TokenAttemptResult.Invalid));
        Assert.All(results, result => Assert.True(result is TokenAttemptResult.Invalid or TokenAttemptResult.LockedOut or TokenAttemptResult.RateLimited));
    }

    /// <summary>
    /// The cooldown was the one limit with no dictionary behind it: a bare
    /// <c>DateTimeOffset</c> field, wider than a word, written and read from
    /// whichever request threads happened to be in flight. Two requests
    /// arriving together both saw the old value and both dumped the list.
    /// </summary>
    [Fact]
    public void The_username_dump_happens_once_however_many_ask_at_once()
    {
        using var store = new TokenStore(new TestTimeProvider());

        var results = RaceEveryone(index => store.TryRecordUsernameRequest(out _));

        Assert.Equal(1, results.Count(allowed => allowed));
    }

    /// <summary>
    /// One token, many spenders, one winner — and the losers must be told
    /// they lost rather than each being handed a claim on the same reset.
    /// </summary>
    [Fact]
    public void A_token_is_spent_once_however_many_try_at_once()
    {
        var clock = new TestTimeProvider();
        using var store = new TokenStore(clock);
        var token = store.Generate("admin", Ip);

        var tickets = new ConcurrentBag<TokenStore.ResetTicket>();
        var results = RaceEveryone(index =>
        {
            var result = store.TryConsume("admin", token, Ip, out var ticket, out _);
            if (ticket is not null)
                tickets.Add(ticket);
            return result;
        });

        Assert.Equal(1, results.Count(result => result is TokenAttemptResult.Ok));
        Assert.Single(tickets);
    }
}
