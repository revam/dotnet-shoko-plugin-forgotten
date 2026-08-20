# Shoko Forgotten Plugin

A [Shoko](https://shokoanime.com/) plugin that handles password reset and username recovery.

## Features

- **Forgot Password** — 4-step wizard flow: username entry, token verification, new password, confirmation.
- **Forgot Username** — Logs all registered usernames to the server console on request.
- **Token-based Auth** — Crypto-random 12-char hex reset tokens with 15-minute expiry, stored in memory, displayed in XXXX-XXXX-XXXX format.
- **Audit Logging** — Every reset request and attempt is logged with full client IP chain (X-Forwarded-For).
- **Rate Limiting** — Prevents abuse with strict request limits, each applied as one atomic check-and-record.
- **IP Security** — Tokens are bound to the requesting IP address.

## Installation

### GUI (Recommended)

1. Open the Shoko Web UI and navigate to **Settings → Plugins → Repositories**.
2. Add the manifest URL:
   ```
   https://raw.githubusercontent.com/revam/dotnet-shoko-plugin-forgotten/stable/manifest.json
   ```
3. Go to **Settings → Plugins → Browse** and find **Forgotten**.
4. Click **Install** on the desired version.
5. Restart Shoko.

### Manual

1. Download the latest `Shoko.Plugin.Forgotten-<version>-any.zip` from the [Releases](../../releases) page.
2. Extract the ZIP and place `Shoko.Plugin.Forgotten.dll` into your Shoko **Plugins** folder.
3. Restart Shoko.

## Configuration

The plugin supports the following configuration options in your Shoko settings:

| Option | Default | Description |
|--------|---------|-------------|
| `TrustProxy` | `false` | When `true`, the plugin will read the `X-Forwarded-For` header to determine client IPs. Enable this only if Shoko is behind a trusted reverse proxy. When `false`, only the direct connection IP is used. Only the rightmost entry is believed, and only if it parses as an address, so a caller cannot vary the chain to escape rate limiting. |

## Rate Limits

To prevent abuse, the following limits are enforced. Each is a single
check-and-record operation, so requests that arrive together cannot all pass
a check none of them has yet paid for.

| Limit | Scope | Applies to |
|-------|-------|------------|
| 1 per 24 hours | Global (all IPs) | `RequestUsernames` |
| 5 per day | Per IP address | `RequestReset` |
| 1 outstanding request | Per username + IP address | `RequestReset` |
| 10 attempts per day | Per IP address | `VerifyToken`, `ResetPassword` |
| 5 failed attempts | Per account | `VerifyToken`, `ResetPassword` |

The 10-attempts-per-day budget is spent by `VerifyToken` and `ResetPassword`,
but it also **gates** `RequestReset` and `RequestUsernames`: an address that
has burned through its attempts cannot mint fresh material either. A
verification that succeeds costs nothing, so checking a token and then
spending it is one attempt rather than two.

The per-account ceiling is keyed on the account being reset, not on the token
submitted, so wrong guesses accumulate however they are spelled. Reaching it
retires that account's outstanding token; requesting a new reset starts over.

When a limit is exceeded the API returns **429 Too Many Requests** with a
`Retry-After` header and a `retryAfter` field in the response body indicating
when the client can retry.

## Tokens

- A token is 12 crypto-random hex characters, displayed as `XXXX-XXXX-XXXX`,
  and accepted with or without dashes or spaces and in any case.
- A token is spendable for **15 minutes**, and expiry is decided on every
  request rather than by a background sweep.
- An account has **at most one** outstanding token. Requesting a new one
  retires the previous one, and spending one retires it for good.
- Tokens are bound to the IP address that requested them.

## Validation

| Field | Rule |
|-------|------|
| `username` | Trimmed; must be non-empty, at most 256 characters, and free of control characters. Matched case-insensitively, the way Shoko itself resolves usernames. |
| `token` | 12 hexadecimal characters after dashes and spaces are removed. |
| `newPassword` | At most 1024 characters, which is the host's own limit. **May be empty** — Shoko supports passwordless accounts. |

A username is refused rather than sanitised because the server console — which
is where reset tokens are delivered — renders log messages into a plain,
unescaped, single-line layout, so a username carrying a newline could write a
line that reads exactly like a token line for another account.

Anything that fails validation returns **400 Bad Request**.

## IP Address Requirements

All endpoints require a determinable client IP address. If the IP cannot be
determined (e.g. missing connection info), the API returns **400 Bad Request**.

Reset tokens are bound to the IP address that requested them. A token
presented from a different address does not check out — and is reported
exactly the same way as a token that never existed, has expired, or has
already been spent. Those cases are deliberately indistinguishable to the
caller, because telling them apart would confirm a guessed token to whoever
guessed it:

- `VerifyToken` answers **200 OK** with `{"valid": false}`. It is a question,
  and that is the answer to it.
- `ResetPassword` answers **403 Forbidden**. It is an action, and it was
  refused.

A token that has taken too many failed attempts is reported separately, as
**403 Forbidden**, by both endpoints — that state is already public to anyone
who caused it.

## API Endpoints

All endpoints are unauthenticated and served under `/api/plugin/Forgotten/v1/`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `Status` | Check if the plugin is installed (returns 200 OK) |
| `POST` | `RequestReset` | Submit username, get token logged to server console |
| `POST` | `VerifyToken` | Check if a token is valid |
| `POST` | `ResetPassword` | Consume token and set new password |
| `POST` | `RequestUsernames` | Log all usernames to server console |

The full Swagger documentation is available at `http[s]://<shoko host>/swagger/index.html?urls.primaryName=Forgotten V1`.

## Building from Source

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```bash
dotnet restore
dotnet build --configuration Release
dotnet test
```

The compiled assembly will be located at `source/bin/Release/net10.0/Shoko.Plugin.Forgotten.dll`.

## License

This project is licensed under the MIT License.
