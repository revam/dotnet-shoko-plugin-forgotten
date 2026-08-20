namespace Shoko.Plugin.Forgotten.Services;

/// <summary>
/// Why a token attempt ended the way it did.
/// </summary>
/// <remarks>
/// The store used to answer with a bare <c>false</c> for "rate limited",
/// "locked out" and "that is not even shaped like a token" alike, and the
/// controller had no choice but to render all three as a 403 claiming the
/// token was locked. The caller needs to be able to tell those apart to
/// answer honestly — which is not the same as telling the <em>client</em>
/// apart, and deliberately so: <see cref="Invalid"/> covers an unknown
/// token, a wrong one, an expired one, one already spent and one presented
/// from the wrong address, because distinguishing those to a caller would
/// confirm a guess.
/// </remarks>
public enum TokenAttemptResult
{
    /// <summary>The token is good and, where asked for, has been spent.</summary>
    Ok,

    /// <summary>The username or token could not be one this plugin issued.</summary>
    Malformed,

    /// <summary>The address has spent its attempt budget for the window.</summary>
    RateLimited,

    /// <summary>The account's live token has taken too many wrong guesses.</summary>
    LockedOut,

    /// <summary>No token here matches — for any of several reasons the caller is not told.</summary>
    Invalid,
}

/// <summary>
/// Why a request for a reset token ended the way it did.
/// </summary>
public enum ResetRequestResult
{
    /// <summary>The caller may mint a token.</summary>
    Ok,

    /// <summary>The address has spent its attempt budget, so it may not mint either.</summary>
    AttemptsExhausted,

    /// <summary>The address has asked for as many tokens today as it may.</summary>
    RateLimited,

    /// <summary>This address already asked for this account recently, and that request is still good.</summary>
    AlreadyPending,
}
