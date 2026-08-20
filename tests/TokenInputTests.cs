using Shoko.Plugin.Forgotten.Services;
using Xunit;

namespace Shoko.Plugin.Forgotten.Tests;

/// <summary>
/// What the store will accept off the wire, before any of it is trusted.
/// </summary>
public class TokenInputTests
{
    [Theory]
    [InlineData("ABCDEF012345", "ABCDEF012345")]
    [InlineData("abcdef012345", "ABCDEF012345")]
    [InlineData("ABCD-EF01-2345", "ABCDEF012345")]
    [InlineData("ABCD EF01 2345", "ABCDEF012345")]
    [InlineData("abcd-ef01 2345", "ABCDEF012345")]
    public void A_token_is_read_the_way_a_person_would_type_it(string input, string expected)
        => Assert.Equal(expected, TokenStore.NormalizeToken(input));

    [Theory]
    [InlineData("")]
    [InlineData("ABCDEF01234")]
    [InlineData("ABCDEF0123456")]
    [InlineData("ABCDEF01234G")]
    [InlineData("ABCD_EF01_2345")]
    // Longer than any separator arrangement of twelve characters could be,
    // so it is refused before a single character is looked at.
    [InlineData("------------------------------------")]
    public void A_token_that_could_not_be_ours_is_refused(string input)
        => Assert.Null(TokenStore.NormalizeToken(input));

    [Fact]
    public void A_null_token_is_refused()
        => Assert.Null(TokenStore.NormalizeToken(null));

    [Theory]
    [InlineData("admin", "admin")]
    [InlineData("  admin  ", "admin")]
    [InlineData("Ada Lovelace", "Ada Lovelace")]
    public void A_username_is_trimmed_and_otherwise_kept_as_written(string input, string expected)
        => Assert.Equal(expected, TokenStore.NormalizeUsername(input));

    /// <summary>
    /// The console layout renders the message into a plain single line with
    /// no escaping, and the console is where reset tokens are delivered — so
    /// a username that can start a new line can write something that reads
    /// exactly like a token line for an account that is not theirs.
    /// </summary>
    [Theory]
    [InlineData("admin\nReset token for user root: AAAA-BBBB-CCCC")]
    [InlineData("admin\r\nanything")]
    [InlineData("ad\tmin")]
    [InlineData("admin\u001b[2K")]
    [InlineData("admin\u0000")]
    public void A_username_that_could_forge_a_log_line_is_refused(string input)
        => Assert.Null(TokenStore.NormalizeUsername(input));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_username_is_refused(string input)
        => Assert.Null(TokenStore.NormalizeUsername(input));

    [Fact]
    public void A_null_username_is_refused()
        => Assert.Null(TokenStore.NormalizeUsername(null));

    [Fact]
    public void An_unbounded_username_is_refused()
        => Assert.Null(TokenStore.NormalizeUsername(new string('a', TokenStore.MaxUsernameLength + 1)));

    [Fact]
    public void A_username_at_the_limit_is_accepted()
        => Assert.NotNull(TokenStore.NormalizeUsername(new string('a', TokenStore.MaxUsernameLength)));

    /// <summary>
    /// Shoko supports passwordless accounts deliberately, so an empty
    /// password is a password.
    /// </summary>
    [Fact]
    public void An_empty_password_is_acceptable()
        => Assert.True(TokenStore.IsAcceptablePassword(string.Empty));

    [Fact]
    public void A_password_at_the_hosts_limit_is_acceptable()
        => Assert.True(TokenStore.IsAcceptablePassword(new string('x', TokenStore.MaxPasswordLength)));

    /// <summary>
    /// One character over is what the host rejects with a validation
    /// exception, which is why it has to be caught before a token is spent.
    /// </summary>
    [Fact]
    public void A_password_past_the_hosts_limit_is_not()
        => Assert.False(TokenStore.IsAcceptablePassword(new string('x', TokenStore.MaxPasswordLength + 1)));
}
