# CasaOS-UserService

The account service of CasaOS. It owns the single administrator account, issues and refreshes the JWTs the other services trust, and serves the avatar and per-user settings the dashboard reads. This repository is part of the **inkly distribution of CasaOS**, a maintained release of the project after upstream [IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS) stopped shipping in 2025, and it descends from [alvins82's fork](https://github.com/alvins82/CasaOS-UserService).

## What it does

The service listens on a random loopback port and registers `/v1/users`, `/v2/users`, its API documentation and `/.well-known/jwks.json` with [CasaOS-Gateway](https://github.com/inkly/CasaOS-Gateway), which is what a browser actually reaches. Its own address is written to `/var/run/casaos/user-service.url` for the other services.

At startup it generates an ECDSA key pair in memory and never writes it anywhere. The private key signs access and refresh tokens; the public key is published as a JWKS document, so the other services verify a token without calling this one. Restarting the service invalidates every token it has issued.

Three things about it are easy to get wrong.

- **There is one account.** `POST /v1/users/register` creates a user with the role `admin`, and it is the only code path that creates a user at all.
- **Registration is gated by a one-shot key.** `GET /v1/users/status` returns a fresh UUID as `key` only while the user count is zero. Register must present that key, and it is deleted on success. The keys live in a map in memory, so a restart discards any that were handed out and not used.
- **`GET /v1/users/image` is deliberately reachable without a token,** because the login page shows the avatar before anyone has one. It is confined instead: the cleaned absolute path must contain the configured user data path and match `^/var/lib/casaos/\d`.

Everything else under `/v1/users` sits behind JWT middleware, which skips the check for requests from `127.0.0.1` or `::1` — upstream behaviour, unchanged here. Login, token refresh and the username list are open by necessity. The `/v2/users` API has nothing to do with accounts: it lists and deletes the events shown in the dashboard's notification list. The events themselves arrive over a websocket subscription to CasaOS-MessageBus (`route/event_listen.go`), not through this API.

Configuration is `/etc/casaos/user-service.conf`, written from an embedded sample on first run. It points at the SQLite database `/var/lib/casaos/db/user.db`, at per-user files under `/var/lib/casaos/<user id>/`, and at the log `/var/log/casaos/user-service.log`. The binary is installed as `/usr/bin/casaos-user-service` and runs under `casaos-user-service.service`. Run it as `casaos-user-service -ru -user <name>` to reset a forgotten password to a random one, which it prints.

## Install

Components are not installed individually. The whole distribution is installed and upgraded with one command:

```sh
curl -fsSL https://github.com/inkly/CasaOS-Install/releases/latest/download/install.sh | sudo bash
```

What a release contains, and how it is built, is described in [CasaOS-Install](https://github.com/inkly/CasaOS-Install#readme).

## What this fork changed

Nothing in the service itself. The Go code here is upstream's; the two commits this distribution carries are about getting it built and installed.

- **Ubuntu 26 setup fallback** (alvins82). The setup script chose its per-distribution script by `pushd`-ing `${ID}/${VERSION_CODENAME}`, then `${ID}`, then each entry of `${ID_LIKE}`, and the chain fell through on a release with no directory of its own. It now builds the candidate list from `/etc/os-release` and takes the first candidate that actually contains a `setup-user-service.sh`.
- **Release pipeline** (this distribution). The goreleaser config still published to `IceWhaleTech/CasaOS-UserService`, which returns 403 from a fork, and the release workflow called IceWhale's shared workflow with secrets no fork has, so no tag had ever produced a release here. The workflow now runs `go generate` and `go test`, cross-compiles for amd64, arm64 and arm/v7, and publishes the tarballs and the `checksums.txt` that the installer verifies. Three workflows that could only ever run at IceWhale were removed: npm publish to the `@icewhale` scope, a push to their test server, and an OpenAPI sync from their organisation.

## Development

```sh
go generate
go build ./...
go test ./...
```

`codegen/` is not committed — it is in `.gitignore` — so `go generate` has to run first, on a fresh clone as much as here. It writes `codegen/user_service` from `api/user-service/openapi.yaml` and `codegen/message_bus` from CasaOS-MessageBus's published OpenAPI document fetched over HTTP, so it needs network access. The release workflow does the same before it builds.

The module targets Go 1.20 and builds without cgo. `go test ./...` reports no test files in every package: this repository has no test suite, and the command passing means only that everything compiles.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE), which is the stock text with the copyright placeholder left unfilled; the per-file IceWhale copyright notices in the source are kept, as the licence requires.

CasaOS is the work of IceWhale and its contributors. The Ubuntu 26 setup fix is [alvins82](https://github.com/alvins82/CasaOS-UserService)'s. CasaOS is a mark of IceWhale; this distribution uses the name to say what it is a release of, and nothing more.
