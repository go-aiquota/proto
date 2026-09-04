<p align="center"><img src="https://raw.githubusercontent.com/go-aiquota/brand/main/social/go-aiquota.png" alt="go-aiquota/proto" width="720"></p>

# go-aiquota / proto

[![CI](https://github.com/go-aiquota/proto/actions/workflows/ci.yml/badge.svg)](https://github.com/go-aiquota/proto/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-aiquota/proto.svg)](https://pkg.go.dev/github.com/go-aiquota/proto)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

The shared contract between `go-aiquota/tray` (the host) and every AI-quota
provider plugin (`go-aiquota/plugin-claude`, and others to come): a
[`hashicorp/go-plugin`](https://github.com/hashicorp/go-plugin) gRPC service,
plus the credential-safety types every side of that contract is built on.

## What's here

- **`quotapb`** — the generated `QuotaProvider` gRPC service
  (`quota.proto`): `Describe` (provider identity + where the host's embedded
  onboarding browser should log an account in) and `FetchQuota` (one
  account's current session/weekly quota).
- **`plugin`** — the go-plugin wiring both the host and every provider
  register through: the handshake, the `GRPCPlugin` adapter, and the
  `ClientConfig` the host launches a provider subprocess with (gRPC only,
  `AutoMTLS` so a credential never crosses the loopback socket in the clear).
- **`secret`** — a `Secret` type wrapping a credential value so that `%v`,
  `%+v`, a wrapped error, or an accidental JSON-encode can never print it.
  The only way to read it back is `Secret.Reveal(func(string))`.
- **`redact`** — shape-based text scrubbing, a second line of defense over
  raw text (subprocess stderr, an upstream error message) that isn't already
  `Secret`-wrapped.

## Why a credential is `map<string,string>`, not a single opaque string

A `FetchQuotaRequest.credential` is a cookie-jar snapshot (cookie name to
value, for whatever domain the provider declared in `Describe`), not one
string. That's what lets `go-aiquota/tray`'s onboarding window stay
provider-agnostic: it drives an isolated embedded browser to
`ProviderInfo.login_url`, captures whatever the jar holds for
`ProviderInfo.cookie_domain` once login completes, and hands the whole map
to the plugin. Adding a new provider is a new plugin declaring its own
login URL and cookie domain — the host's onboarding flow doesn't change.

## Adding a provider

1. Implement `quotapb.QuotaProviderServer` (`Describe` + `FetchQuota`).
2. Serve it with `hcplugin.Serve(&hcplugin.ServeConfig{HandshakeConfig:
   plugin.Handshake, Plugins: plugin.Map(yourImpl), GRPCServer:
   hcplugin.DefaultGRPCServer})`.
3. Never format a raw credential value into a log line or error string —
   wrap it in `secret.Secret` the moment you have it, and reveal it only at
   the single call site that needs the raw value (e.g. building an HTTP
   request). See `go-aiquota/plugin-claude` for the reference
   implementation.

## Regenerating `quotapb`

```console
$ protoc --go_out=. --go_opt=paths=source_relative \
         --go-grpc_out=. --go-grpc_opt=paths=source_relative \
         quotapb/quota.proto
```
