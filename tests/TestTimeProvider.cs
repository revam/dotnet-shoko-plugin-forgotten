namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// A clock a test can move, and a timer that never fires.
/// </summary>
/// <remarks>
/// Both halves matter. The store now decides every expiry and every window
/// boundary by comparing against this at read time, which is what lets a
/// fifteen-minute token lifetime and a one-day rate-limit window be tested
/// in a millisecond. The dead timer is what proves it: if the store were
/// still relying on its background sweep to expire anything, none of these
/// tests would pass, because nothing here ever sweeps.
/// </remarks>
internal sealed class TestTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public TestTimeProvider()
        : this(new DateTimeOffset(2026, 8, 20, 12, 0, 0, TimeSpan.Zero))
    {
    }

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        => new DeadTimer();

    private sealed class DeadTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
