# CasaOS-UserService

> **Not affiliated with IceWhale.** An independent, community-maintained distribution of CasaOS, not produced or endorsed by Shanghai IceWhale Technology Limited. CASAOS is their trademark, used here only to say what this is a release of. The original project is [IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS); report problems with this distribution at [ReCasaOS/CasaOS/issues](https://github.com/ReCasaOS/CasaOS/issues).

The account service of CasaOS. It owns the single administrator account, issues and refreshes the JWTs the other services trust, and serves the avatar and per-user settings the dashboard reads. This repository is part of **ReCasaOS**, a maintained release of the project after upstream [IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS) stopped shipping in 2025, and it descends from [alvins82's fork](https://github.com/alvins82/CasaOS-UserService).

## What it does

The service listens on a random loopback port and registers `/v1/users`, `/v2/users`, its API documentation and `/.well-known/jwks.json` with [CasaOS-Gateway](https://github.com/ReCasaOS/CasaOS-Gateway), which is what a browser actually reaches. Its own address is written to `/var/run/casaos/user-service.url` for the other services.

At startup it generates an ECDSA key pair in memory and never writes it anywhere. The private key signs access and refresh tokens; the public key is published as a JWKS document, so the other services verify a token without calling this one. Restarting the service invalidates every token it has issued.

Three things about it are easy to get wrong.

- **There is one account.** `POST /v1/users/register` creates a user with the role `admin`, and it is the only code path that creates a user at all.
- **Registration is gated by a one-shot key.** `GET /v1/users/status` returns a fresh UUID as `key` only while the user count is zero. Register must present that key, and it is deleted on success. The keys live in a map in memory, so a restart discards any that were handed out and not used.
- **`GET /v1/users/image` is deliberately reachable without a token,** because the login page shows the avatar before anyone has one. It is confined instead: the cleaned absolute path must contain the configured user data path and match `^/var/lib/casaos/\d`.

Everything else under `/v1/users` sits behind JWT middleware, which skips the check for requests from `127.0.0.1` or `::1` — upstream behaviour, unchanged here. Login, token refresh and the username list are open by necessity. The `/v2/users` API has nothing to do with accounts: it lists and deletes the events shown in the dashboard's notification list. The events themselves arrive over a websocket subscription to CasaOS-MessageBus (`route/event_listen.go`), not through this API.

Configuration is `/etc/casaos/user-service.conf`, written from an embedded sample on first run. It points at the SQLite database `/var/lib/casaos/db/user.db`, at per-user files under `/var/lib/casaos/<user id>/`, and at the log `/var/log/casaos/user-service.log`. The binary is installed as `/usr/bin/casaos-user-service` and runs under `casaos-user-service.service`. Run it as `casaos-user-service -ru -user <name>` to reset a forgotten password to a random one, which it prints.

## Two-factor authentication

A user can protect the account with a TOTP authenticator (RFC 6238, SHA-1, six digits, 30 s period, one step of skew) plus eight single-use recovery codes. Everything lives on `/v1/users`, next to `/login`; the v2 OpenAPI document is not extended, because every path it declares is generated under `/v2/users` behind the JWT middleware and `/2fa/verify` must be reachable without an access token. Responses use the usual `{success, message, data}` envelope.

| Route | Auth | Body | Result |
|---|---|---|---|
| `POST /v1/users/login` | none | `{username, password}` | unchanged when 2FA is off. When it is on: `success` **10014**, `data = {pre_auth_token, expires_at}`; no access token is issued. |
| `POST /v1/users/2fa/verify` | none | `{pre_auth_token, code}` or `{pre_auth_token, recovery_code}` | `200` with the same `data` as a login (`token` + `user`). `400` with 20006 (pre-auth token invalid or expired), 4000 (neither or both of `code` and `recovery_code`), 10015 (wrong code or recovery code), 10017 (2FA not enabled). `429` with 10012 after five attempts in a minute for that user, correct codes included; the service-wide budget of `/login` does not apply here. |
| `POST /v1/users/2fa/setup` | access token | `{password}` | `data = {secret, otpauth_url}`; the secret is pending until `enable` confirms it. `400` with 4000 (no password), 10015 (wrong password), 10016 (already enabled: an enabled secret is never rotated without a factor). |
| `POST /v1/users/2fa/enable` | access token | `{code}` | `data = {recovery_codes: [8 × "xxxxx-xxxxx"]}`, shown once and never retrievable. `400` with 10015 (wrong code), 10016 (already enabled), 10017 (no pending setup). |
| `POST /v1/users/2fa/disable` | access token | `{code}` or `{password}` | `200`. `400` with 4000 (neither field, or both), 10015 (wrong code or password), 10017 (not enabled). |
| `GET /v1/users/current` | access token | — | unchanged, `data` gains `totp_enabled`. |

The pre-auth token is an ES256 JWT with `iss: "2fa"` and a five-minute lifetime, signed by a second key pair that is never published in the JWKS, so no other service — and no other route here — accepts it as an access token. `/2fa/verify` checks the signature against that key, then the issuer and expiry. It sits outside the service-wide login budget on purpose: without a pre-auth token, which only a correct password on the limited `/login` produces, a request costs one signature check and nothing else, and with one the attempts are bounded by the per-user budget and the token's five minutes, so a global budget there would only let anyone starve `/login` with garbage. Every factor or password check on `/2fa/*` costs one token of a per-user budget of five a minute, correct answers included; the token is taken before the check, so concurrent attempts cannot share one. A code is accepted for the current 30 s step and its two neighbours, and each step is accepted once: the last accepted step is stored, so a captured code cannot be replayed within its window. The step is recorded with a conditional update (`totp_last_step < step`), and a recovery code is removed with the same compare-and-set on the stored list, so two requests carrying one captured code cannot both pass. Every other write the routes make to the four 2FA columns is keyed the same way on the row as it was read: `setup` stores its secret only while 2FA is still off, `enable` and the clearing on login only while that pending secret is still there, `disable` only against the enrolment the code or password was checked on; a `2fa/*` write that changes no row is refused (10016 or 10017), a login whose clear changes no row re-reads the row and goes by what it finds: it stops at the factor if 2FA was enabled in between, and issues a full session if the pending secret was already gone, and a statement that fails is logged and counts as no row, never as done. That guard is monotonic: it assumes the clock only moves forward, so keep it NTP-synced. If the clock is set back — a dead RTC, a manual change — every code is refused until the clock passes the last accepted step again, and the recovery codes are the way in meanwhile; a clock jumped forward simply invalidates the codes of the skipped steps. Recovery codes are ten characters of `a-z2-7` (fifty bits), case-insensitive, hyphen optional, stored as bcrypt hashes and removed as they are used; to get a new set, disable and enable again. The TOTP seed itself cannot be hashed — the server recomputes codes from it — so it sits in clear in `user.db` next to the MD5 password hash.

Enrolment needs the password on top of the session, as disabling needs a code or the password: the JWT middleware accepts a refresh token as an access token, so a stolen token alone must not be able to add an authenticator and lock the owner out. A password login clears a pending, never-enabled secret, so an abandoned setup leaves nothing in `user.db` (and a login between `setup` and `enable` means starting the setup again). Enabling or disabling 2FA does not revoke tokens already issued; a refresh token keeps renewing a session obtained before the change. If both the authenticator and the recovery codes are lost, `casaos-user-service -ru -user <name>` resets the password and clears 2FA together, which is the only way back in short of editing `user.db`.

## Install

Components are not installed individually. The whole distribution is installed and upgraded with one command:

```sh
curl -fsSL https://github.com/ReCasaOS/CasaOS-Install/releases/latest/download/install.sh | sudo bash
```

What a release contains, and how it is built, is described in [CasaOS-Install](https://github.com/ReCasaOS/CasaOS-Install#readme).

## What this fork changed

One feature, and the two commits that got it built and installed.

- **Two-factor authentication** (this distribution). TOTP enrolment, verification and recovery codes on `/v1/users/2fa/*`, described above. Upstream never had a second factor on the admin account.

- **Ubuntu 26 setup fallback** (alvins82). The setup script chose its per-distribution script by `pushd`-ing `${ID}/${VERSION_CODENAME}`, then `${ID}`, then each entry of `${ID_LIKE}`, and the chain fell through on a release with no directory of its own. It now builds the candidate list from `/etc/os-release` and takes the first candidate that actually contains a `setup-user-service.sh`.
- **No geo-IP at install time.** `build/scripts/migration/script.d` ran `__get_download_domain` at top level, curling `ipconfig.io/country` and then `ifconfig.io/country_code` to pick a download mirror by country. `install.sh` runs every script in that directory on every install and every upgrade, so both services were contacted each time, before the script had even decided whether a migration was due — which, on anything but a pre-0.4 box, it never is. The migration tools now come from GitHub unconditionally, and the domain is a constant: it is not an environment knob either, because what it points at is downloaded and run as root without verification.
- **Release pipeline** (this distribution). The goreleaser config still published to `IceWhaleTech/CasaOS-UserService`, which returns 403 from a fork, and the release workflow called IceWhale's shared workflow with secrets no fork has, so no tag had ever produced a release here. The workflow now runs `go generate` and `go test`, cross-compiles for amd64, arm64 and arm/v7, and publishes the tarballs and the `checksums.txt` that the installer verifies. Three workflows that could only ever run at IceWhale were removed: npm publish to the `@icewhale` scope, a push to their test server, and an OpenAPI sync from their organisation.
- **Module path** (this distribution). The module is `github.com/ReCasaOS/CasaOS-UserService` and depends on `github.com/ReCasaOS/CasaOS-Common v0.4.22`, so the import paths naming IceWhale in every log line, stack trace and `go version -m` on the shipped binary now name this distribution instead.

## Development

```sh
go generate
go build ./...
go test ./...
```

`codegen/` is not committed — it is in `.gitignore` — so `go generate` has to run first, on a fresh clone as much as here. It writes `codegen/user_service` from `api/user-service/openapi.yaml` and `codegen/message_bus` from CasaOS-MessageBus's published OpenAPI document fetched over HTTP, so it needs network access. The release workflow does the same before it builds.

The module targets Go 1.21 — raised from 1.20 by CasaOS-Common v0.4.22 — and builds without cgo. The test suite covers the two-factor path: `service/totp_test.go` (step window, replay guard, recovery codes, and four of the conditional writes — step, recovery code, enable, clear — refusing on a closed database), `pkg/sqlite/migrate_test.go` (an existing `o_users` row survives the column additions) and `route/v1_2fa_test.go`, which drives the real router over an in-memory database through enrolment, login, verification, recovery, rate limiting and disable, plus the races: one captured code or one recovery code sent four times at once passes once, and a stale `setup`, `enable`, login or `disable` cannot overwrite the row another request changed since it read it. Every other package still reports no test files.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE), which is the stock text with the copyright placeholder left unfilled; the per-file IceWhale copyright notices in the source are kept, as the licence requires.

CasaOS is the work of IceWhale and its contributors. The Ubuntu 26 setup fix is [alvins82](https://github.com/alvins82/CasaOS-UserService)'s. CasaOS is a mark of IceWhale; this distribution uses the name to say what it is a release of, and nothing more.
