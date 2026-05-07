# Shoko Forgotten Plugin

A [Shoko](https://shokoanime.com/) plugin that handles password reset and username recovery.

## Features

- **Forgot Password** — 4-step wizard flow: username entry, token verification, new password, confirmation.
- **Forgot Username** — Logs all registered usernames to the server console on request.
- **Token-based Auth** — Crypto-random 32-char reset tokens with 15-minute expiry, stored in memory.
- **Audit Logging** — Every reset request and attempt is logged with full client IP chain (X-Forwarded-For).
- **Rate Limiting** — Prevents abuse with strict request limits.
- **IP Security** — Tokens are bound to the requesting IP address.

## Installation

### GUI (Recommended)

1. Open the Shoko Web UI and navigate to **Settings → Plugins → Repositories**.
2. Add the manifest URL:
   ```
   https://raw.githubusercontent.com/revam/dotnet-shoko-plugin-forgotten/stable/manifest.json
   ```
3. Go to **Server → Plugins → Browse** and find **Forgotten**.
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
| `TrustProxy` | `false` | When `true`, the plugin will read the `X-Forwarded-For` header to determine client IPs. Enable this only if Shoko is behind a trusted reverse proxy. When `false`, only the direct connection IP is used. |

## Rate Limits

To prevent abuse, the following rate limits are enforced:

| Endpoint | Limit | Scope |
|----------|-------|-------|
| `RequestUsernames` | 1 per 24 hours | Global (all IPs) |
| `RequestReset` | 5 per day | Per IP address |
| `RequestReset` | 1 concurrent | Per username + IP combination |

When a rate limit is exceeded, the API returns **429 Too Many Requests** with a `Retry-After` header and a `retryAfter` field in the response body indicating when the client can retry.

## IP Address Requirements

All endpoints require a determinable client IP address. If the IP cannot be determined (e.g., missing connection info), the API returns **400 Bad Request**.

Reset tokens are bound to the IP address that requested them. Verification and consumption will fail if the IP doesn't match, returning **403 Forbidden**.

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
```

The compiled assembly will be located at `source/bin/Release/net10.0/Shoko.Plugin.Forgotten.dll`.

## License

This project is licensed under the MIT License.
