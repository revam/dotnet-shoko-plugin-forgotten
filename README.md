# Shoko Forgotten Plugin

A [Shoko](https://shokoanime.com/) plugin that handles password reset and username recovery.

## Features

- **Forgot Password** — 4-step wizard flow: username entry, token verification, new password, confirmation.
- **Forgot Username** — Logs all registered usernames to the server console on request.
- **Token-based Auth** — Crypto-random 12-char hex reset tokens with 15-minute expiry, stored in memory, displayed in XXXX-XXXX-XXXX format.
- **Audit Logging** — Every reset request and attempt is logged with full client IP chain (X-Forwarded-For).
- **Shared Lockout** — Wrong reset codes are counted in Shoko's own authentication throttle, so a client guessing them is shut out of signing in too, and a client Shoko has already shut out finds these endpoints closed.
- **Rate Limiting** — Bounds what one address can ask for, each limit applied as one atomic check-and-record.
- **IP Security** — Tokens are bound to the requesting IP address.

## Installation

### GUI (Recommended)

1. Open the Shoko Web UI and navigate to **Settings → Plugins → Repositories**.
2. Add the manifest URL:
   ```
   https://raw.githubusercontent.com/revam/dotnet-shoko-plugin-forgotten/metadata/manifest.json
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
| `TrustProxy` | `false` | When `true`, the plugin will read the `X-Forwarded-For` header to determine client IPs. Enable this only if Shoko is behind a trusted reverse proxy. When `false`, only the direct connection IP is used. Only the rightmost entry is believed, and only if it parses as an address, so a caller cannot vary the chain to escape rate limiting. This governs the plugin's own limits and the address a token is bound to; Shoko's shared lockout always keys on the connection address. |

## Guessing a Reset Code

A reset code is a credential, so a wrong one is counted in Shoko's own
authentication throttle rather than in a ledger this plugin keeps to itself.
That store is shared with the core sign-in and with every other plugin, which
cuts both ways and is meant to: a client working through codes here is shut
out of signing in as well, and a client Shoko has already shut out finds
these endpoints closed. The admin configures the thresholds under the
server's authentication throttle settings; this plugin reads them and never
restates them.

Every endpoint asks the throttle **before** the account is looked up, passing
the username the request named and never the code it submitted. Shoko counts
failures for any username it is given, existing or not, so a name it has
locked out and a name it has never heard of are refused identically.

What is written back:

| Outcome | Charged to |
|---------|------------|
| A code that checked out against nothing, or against an account whose code is locked | The client |
| A code that was never shaped like one (**400**) | Nobody |
| A code that held, but which Shoko then refused to act on | Nobody |
| Asking for a code, or for the username list | Nobody |
| A completed password reset | Cleared, for both the client and the account |

The account dimension is only ever read or cleared, never charged. The
username on a reset request is whatever the caller claimed it was, so
counting a wrong code against it would let anyone who can spell a name lock
its owner out of signing in.

`VerifyToken` clears nothing even when the code holds. It answers a question
rather than performing a reset, and the same code answers it for as long as
it lives, so clearing the shared ledger there would hand whoever holds one
code an unlimited supply of fresh password guesses at every other door. A
completed `ResetPassword` does clear it, for both dimensions: the account's
credential has actually changed at that point, and the person this plugin
exists for is somebody who was locked out for forgetting it.

Shoko keys its client lockout on the connection address, so `TrustProxy`
does not apply to it — behind a reverse proxy every client shares one
bucket there. It still applies to the limits below, which are this
plugin's own.

## Rate Limits

To bound what one address can ask this plugin to hold and to log, the
following limits are enforced. Each is a single check-and-record operation,
so requests that arrive together cannot all pass a check none of them has yet
paid for. None of them is a failure counter.

| Limit | Scope | Applies to |
|-------|-------|------------|
| 1 per 24 hours | Global (all IPs) | `RequestUsernames` |
| 5 per day | Per IP address | `RequestReset` |
| 1 outstanding request | Per username + IP address | `RequestReset` |
| 5 failed attempts | Per account | `VerifyToken`, `ResetPassword` |

The per-account ceiling is keyed on the account being reset, not on the token
submitted, so wrong guesses accumulate however they are spelled. It retires
that account's outstanding token rather than locking the account out of
anything; requesting a new reset starts over.

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

A token that has taken too many failed attempts is **not** reported
separately. It answers exactly as an unknown token does, and costs the caller
the same. A lockout can only exist for an account that has a live token, so a
distinct answer would have said "this account exists and has a reset in
flight" — the one question every other line here is written to refuse — and a
difference in what it cost would be the same disclosure by another route.

Only the address a token is bound to can spend that token's per-account
ceiling. A guess from anywhere else cannot succeed whatever it contains, so
counting it would only have let a stranger exhaust the ceiling and deny the
real user their reset. It is still charged to the guesser's own client
lockout.

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
