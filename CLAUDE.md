# CLAUDE.md

Guidance for Claude Code and other contributors. `README.md` is the user documentation. Copy the closest existing endpoint: this file lists only what the code doesn't show.

## Commands

- Build: `make build`. Tests: `go test -race ./...`.
- Lint: `bash scripts/build/ci/build_lint.sh`, the same command CI runs. `scripts/lint/lint.sh` only defines functions, so running it alone does nothing.

## Checks that only fail in CI or review

- Coverage must stay at 100% (mocks excluded; `scripts/build/ci/build_test.sh`). Mark only truly unreachable lines with a trailing `// notest`.
- Every interface method needs its mock in `descope/tests/mocks/` (`<Method>Assert`, `<Method>Response`, `<Method>Error`), or the build breaks.
- Every public method needs a snippet in the matching `README.md` section; a new management area also needs an accessor on `Management` that calls `ensureManagementKey()`, an entry in `MockManagement` (`descope/tests/mocks/mgmt/managementmock.go`), and a README table-of-contents entry.
- New example apps under `examples/` have their own `go.mod` and must be added to `scripts/build/ci/build_go.sh`.

## Rules

- On the auth client, the key after the JWT in `Authorization` is the optional auth management key (`Config.AuthManagementKey` / `DESCOPE_AUTH_MANAGEMENT_KEY`). It lets callers use auth methods whose public access is disabled. New auth methods send requests through `DoXRequest`; never build the header yourself.
- Partial updates send only the fields the caller set.
- Reuse the error codes in `descope/errors.go`; don't add new ones for single endpoints.
- PR titles and commits use Conventional Commits with a lowercase subject (`.commitlint.yaml`); release-please builds `CHANGELOG.md`, so never edit it by hand.
