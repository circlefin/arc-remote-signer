# Testing

Describes how to run tests locally, which checks block merges, and the conventions new tests must follow.

For the contribution workflow that wraps these commands, see [development.md](development.md).

## Test Matrix

| Command | Scope | Notes |
|---------|-------|-------|
| `make test` | Unit tests + lint | — |
| `make test-it` | Unit + integration | Starts localstack via `make up` |
| `make smoke` | Smoke (end-to-end) | Starts localstack and launches `bin/app` automatically (via `scripts/smoke.sh`) |
| `make test-all` | All of the above | Combines the above |

Test files are co-located with source and use build tags to control scope:

- Integration tests: `//go:build integration` (files named `integration_test.go`)
- Smoke tests: `//go:build smoke`, located in `internal/smoke/`

## Conventions

### Framework

- `testify/require` by default; use `require` for preconditions and dependency checks (`NoError`, `NotNil`, etc.).
- `testify/assert` only when intentionally collecting multiple independent failures in one run.
- `testify/suite` only when shared setup/teardown across many tests is genuinely needed.
- The `no-go-testing` pre-commit hook forbids raw `testing` assertions — use `testify`.

### Naming

- Single-scenario tests: `Test<FunctionOrMethod>_<Scenario>`.
- Multi-scenario tests: `Test<FunctionOrMethod>` with scenarios in `t.Run("...")`.
- `<Scenario>` is PascalCase and behavior-oriented.
- Subtest names are concise lowercase phrases describing one behavior.

### Structure

- Prefer table-driven tests when setup shape is similar and only input/output varies.
- Prefer scenario-style subtests when setup differs materially (filesystem, env, working directory, lifecycle).
- Related scenarios should be merged into one top-level test with subtests.
- Table variable is `tests`; loop variable is `tt` (or `tc` when nested).
- Expected fields use `want*`; actual values use `got*`. `expected*`/`actual*` is acceptable where it improves clarity — do not mix styles within the same file.

### Parallelism

- `t.Parallel()` is allowed only for fully isolated tests.
- Do not parallelize tests with shared mutable state, `os.Chdir`, or overlapping `t.Setenv` keys.
- In parallel subtest loops, capture the loop variable (`tt := tt`) before `t.Run`.

### Helpers, Fixtures, Mocks

- Shared helper functions call `t.Helper()` as their first statement.
- Helper/factory names are verb-oriented (`new*`, `build*`, `generate*`).
- Reused fixtures go through helper/factory functions rather than duplicated inline literals.
- Mocking uses `gomock` via `mockgen` (v1.6.0) from `github.com/golang/mock`. Mocks live as `*_mock.go` files co-located with interfaces — do not edit generated mocks.
- Avoid `gomock.Any()` when the expected argument is known or computable. Reserve it for values that are genuinely unpredictable at setup time (e.g., runtime-generated ciphertext).

### Assertions

- Prefer `require.ErrorIs` / `require.ErrorAs` over error-string equality.
- Do not assert full error text unless the message itself is the behavior under test.
- Assert intentional panics with `require.Panics` / `require.NotPanics`.
- Each subtest validates one behavior; split unrelated assertions into separate subtests.

### Determinism

- Tests must be deterministic and reproducible.
- Avoid real wall clock, real network, and external services in unit tests.
- For async coordination, use channels, context deadlines, or bounded polling — never fixed `time.Sleep`.

### State Safety

- Any test mutating global/package state must restore it with `t.Cleanup`, registered immediately after the mutation.
- `t.Cleanup` must not call `t.FailNow` / `t.Fatal` or `require.*`; use `t.Errorf` / `t.Logf` instead.
- Filesystem writes use `t.TempDir()` unless intentionally testing a fixed path.

### Coverage

- Keep coverage for changed code at or above 80%.
- Do not remove meaningful edge-case coverage during style-only refactors.
- Do not add trivial tests that only verify struct field assignment or setter/getter round-trips.

## Verification

After substantive test changes:

1. Run `make test` and fix all lint findings (`golangci-lint run` or the project equivalent).
2. If the change includes `//go:build integration` files, run `make test-it`.
3. If it includes `//go:build smoke` files, run `make test-all`.
