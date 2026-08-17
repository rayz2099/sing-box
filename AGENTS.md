# Repository Guidelines

sing-box is a Go universal proxy platform (`github.com/sagernet/sing-box`). The CLI entry is `./cmd/sing-box`. Public docs live at https://sing-box.sagernet.org.

## Project Structure & Module Organization

- `cmd/sing-box/`: CLI (`run`, `check`, `format`, geo, rule-set, subscription).
- `adapter/`, `protocol/`, `route/`, `dns/`, `transport/`: inbound/outbound adapters, protocols, routing, DNS, and transports.
- `option/`, `constant/`, `common/`, `service/`, `log/`: JSON options, constants, shared helpers, services, logging.
- `experimental/`: Clash/V2Ray APIs and `libbox` mobile FFI.
- `clients/`: Apple and Android wrappers.
- `test/`: integration tests (own `go.mod`, Docker-backed cases).
- `docs/`, `mkdocs.yml`: MkDocs site. `include/` holds build tags.

## Build, Test, and Development Commands

Requires Go 1.26.1. Default tags: `with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,...`.

- `make build` or `just build`: current-platform binary `./sing-box`.
- `make install` or `just install`: install into `$(go env GOPATH)/bin`.
- `make fmt`: `gofumpt`, `gofmt -s`, `gci` (standard, `github.com/sagernet/`, default).
- `make lint`: `golangci-lint` across linux/android/windows/darwin/freebsd.
- `make test`: unit tests plus `test/` integration suite.
- `make docs` / `make docs_install`: local MkDocs after venv setup.

Example: `./sing-box check -c config.json` then `./sing-box run -c config.json`.

## Coding Style & Naming Conventions

Go defaults: tabs, exported `CamelCase`, unexported `camelCase`. Files are `snake` or short package names (`cmd_run.go`, `route.go`). Enable `.golangci.yml` linters (`govet`, `staticcheck`, `ineffassign`, `paralleltest`). Do not edit generated or `transport/simple-obfs` without cause.

## Testing Guidelines

- Unit tests sit beside packages as `*_test.go`.
- Integration tests in `test/` use `*_test.go` named by protocol (`vmess_test.go`, `trojan_test.go`). Many need Docker.
- `make test_stdio` forces stdio for CI-like runs. No published coverage gate; keep new protocol paths covered.

## Commit & Pull Request Guidelines

History is mixed Conventional Commits and short fixes: `feat: add mitm`, `fix(subscription): persist active...`, `tun: Fix nftablesCreateLocalAddressSets`. Prefer `type(scope): summary` (50–72 chars). PRs should state intent, config or CLI impact, linked issue, and test evidence (`make test` / protocol case). Target `dev-next` / `main-next` / `stable-next`. Lint runs on those branches.

## Security & Configuration Tips

Do not commit live configs, `cache.db`, or MITM CA material (`mitm-ca.crt` / `mitm-ca.key`). Use `CONTEXT.md` terms (Engine, Scope, Client Leg, Origin Leg) when changing capture/MITM code.

## Agent-Specific Instructions

- Do not flip `include/` tags or default `TAGS` unless a new `with_*` flag is required; keep `Makefile`, `justfile`, and `.golangci.yml` aligned.
- Leave generated code, proto output, and `transport/simple-obfs` alone unless the task names them.
- Do not commit `cache.db`, local `*.json` configs, MITM CA files, or the `sing-box` binary.
- Capture/MITM changes must use `CONTEXT.md` terms. Do not add a MITM inbound.
- Use `make`/`just` recipes; run `make fmt` before commit. Do not bump the Go toolchain or CI branches unless asked.
