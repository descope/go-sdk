# CLAUDE.md

Guidance for Claude Code and other contributors working in this repository. `README.md` is the user documentation.

## Commands

- Build: `make build` (`go mod tidy && go build ./...`).
- Tests: `go test -race ./...`. CI runs `scripts/build/ci/build_test.sh` and requires 100% coverage, excluding mocks.
- Lint: `bash scripts/lint/lint.sh` (the file is not executable; golangci-lint with `scripts/lint/.golangci.yml`, plus gitleaks). The `.hooks/pre-commit` hook runs it.

## Adding an endpoint

Paths are under `descope/`. For a method on an existing area:

1. `api/client.go`: three entries per route.
   - The path in `Routes` (`mgmtEndpoints` or `authEndpoints`), without `v1/`.
   - The struct field.
   - The accessor, e.g. `func (e *endpoints) ManagementFamilyCreate() string { return path.Join(e.version, e.mgmt.familyCreate) }`. Use `e.versionV2` for `/v2/` routes.
2. `types.go`: request and response types with camelCase JSON tags.
3. `sdk/mgmt.go` or `sdk/auth.go`: interface method with a doc comment.
4. `internal/mgmt/<area>.go` or `internal/auth/<method>.go`: implementation.
5. `internal/mgmt/<area>_test.go` or `internal/auth/<method>_test.go`: tests.
6. `tests/mocks/mgmt/managementmock.go` or `tests/mocks/auth/authenticationmock.go`: `<Method>Assert`, `<Method>Response` and `<Method>Error` fields plus the method. Required: the mocks must implement the `sdk` interfaces, or the build breaks.
7. `README.md` (repo root): snippet in the matching `### Manage X` section.

A new management area also needs wiring in `internal/mgmt/mgmt.go` (field, init, and an accessor that calls `ensureManagementKey()`), a method on the `Management` interface, an entry in `MockManagement`, and a README table-of-contents entry. New example apps under `examples/` have their own `go.mod` and must be added to `scripts/build/ci/build_go.sh`.

## Conventions

- Required arguments: `return utils.NewInvalidArgumentError("<name>")`.
- Requests: `client.DoPostRequest` / `DoPutRequest` / `DoPatchRequest(ctx, api.Routes.<Route>(), body, options, pswd)`, or `client.DoGetRequest` / `DoDeleteRequest(ctx, api.Routes.<Route>(), options, pswd)` with no body. The header becomes `Authorization: Bearer <projectID>[:<pswd>][:<managementKey>]`.
  - Management calls pass `pswd = ""`; the management key is added automatically.
  - Auth calls acting for a user pass the refresh JWT as `pswd`, from `auth.getValidRefreshToken(r)` or a token parameter.
- Partial updates send only the fields the caller set.
- Errors: reuse the codes in `errors.go`; do not add new ones for single endpoints.

## Tests

- Use testify `require`, the package-local `newTestMgmt` (`internal/mgmt/mgmt_test.go`) / `newTestAuth` (`internal/auth/auth_test.go`), and `helpers.DoOkWithBody` / `helpers.ReadBody` from `tests/helpers`.
- Assert the route, the `Authorization` header, the request body, the parsed response, and one invalid-argument case per required argument.
- Cover every new branch. Mark only truly unreachable lines with a trailing `// notest`, as existing code does.

## Pull requests

PR titles and commits use Conventional Commits with a lowercase subject (`.commitlint.yaml`). release-please builds `CHANGELOG.md` from them, so never edit it by hand.
