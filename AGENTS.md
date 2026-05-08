# Repository guide for AI agents

## What this is

pago is a command-line password manager written in Go.
The store is a directory of [age](https://github.com/FiloSottile/age)-encrypted files versioned in Git.
A long-running agent caches identities so the master password is entered once per session.

`cmd/pago` is the CLI.
`cmd/pago-agent` is the agent process.
Shared packages are `pago` (root, utility code), `crypto`, `agent`, `editor`, `git`, `input`, and `tree`.
End-to-end tests live in `test/` and drive the built binaries through expect-style consoles.
The project requires Go 1.24 or later.

## Toolchain

Use [Task](https://taskfile.dev) when it is available:

```shell
task build
task test
task lint
```

If Task is not installed, the equivalents are:

```shell
go build -trimpath ./cmd/pago
go build -trimpath ./cmd/pago-agent
go test ./...
golangci-lint run ./...
```

`go test ./test/` needs the binaries to exist at `cmd/pago/pago` and `cmd/pago-agent/pago-agent`.
Build them first if you skip Task.

The `.golangci.toml` enables `modernize`, which requires a recent golangci-lint.
If the system version errors with `unknown linters: 'modernize'`, upgrade:

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

Then call it as `$(go env GOPATH)/bin/golangci-lint`.

Pre-existing lint findings live in `script/release.go` and `cmd/pago/main.go` (a `prealloc` warning on `quoteKeyPath`).
New code should not introduce findings.
The pre-existing ones are out of scope.

## Layout

- `cmd/pago/main.go` is the only Go file in the CLI package.
  It contains every command type and `Run` method.
  Add new commands and helpers here unless they are reusable across packages.
- `cmd/pago/main_test.go` holds unit tests for unexported helpers.
- `pago.EntryFile` is the single chokepoint for resolving entry names to paths.
  Do not build paths directly.
- `pago.WriteFileAtomic` is the single chokepoint for writing sensitive files.
- `pago.Duration` is a `time.Duration` wrapper that accepts a bare integer as seconds.
  Use it for any user-supplied duration so `30` and `30s` both work.
- Sentinel errors (`pago.ErrEntryNotFound`, `pago.ErrDecryption`, `pago.ErrAgent`) live in `util.go` and drive distinct exit codes from `main`.

## Commit messages

Format: `type(scope): lowercase imperative subject`.
Examples:

- `feat(add): add -t/--trim to strip trailing newlines`
- `fix(*): write sensitive files atomically`
- `refactor(crypto): drop duplicate EntryFile`
- `docs(readme): note that show -K decrypts the entry`

Scope is the affected component (`add`, `clip`, `crypto`, `agent`, `git`, `log`, `readme`, ...) or `*` for cross-cutting changes.
Use backticks around code and identifiers in both the subject and the body.
Keep the subject short; details go in the body.

## Style

- Plain prose, no contractions in user-facing text (`do not`, not `don't`).
- One sentence per line in Markdown.
- Capitalize `Git` in user-facing help strings and the README.
  Lowercase `git` in Go error strings (staticcheck ST1005 forbids leading capitals).
- `kong` field tags align by column.
  Run `gofmt` on edited files.
- Default to writing no comments.
  Add one only when the *why* is non-obvious.

## Tests

- Each behavior change ships with a test that exercises the new path.
- Each bug fix ships with a test that demonstrably fails *without* the fix.
  Verify by reverting the fix, running the test, restoring the fix.
  Mention that you verified in the response.
- Tests that need a TTY use `expect.Console`.
  Tests that do not, use `runCommandEnv`.
- Skip rather than fail when an external dependency is missing:

  ```go
  if _, err := exec.LookPath("git"); err != nil {
      t.Skip("git not installed")
  }
  ```

- Run the full `go test ./test/` after a batch of changes.
  The suite takes about a minute.

## Sharp edges

These are recurring failure shapes in this codebase.
Walk the checklist when adding code that resembles them.

**Atomic file writes.**
Anything that overwrites a sensitive file (identities, entry, recipients) goes through `pago.WriteFileAtomic`.
A crash between `os.Create` and the final write would otherwise leave the file truncated and unrecoverable.

**Signal handling.**
When entering a wait that may need a clean shutdown, register the handler *before* announcing the wait.
There must be no observable line of output between the print and `signal.Notify`.
A signal arriving in that window beats the cleanup.

**Error wrapping for exit codes.**
Leaf failures wrap sentinel errors so `main` can pick a distinct exit code via `errors.Is`.
New error sites that fall into one of the categories below should wrap accordingly.

| Sentinel | Exit | When |
|---|---|---|
| `ErrEntryNotFound` | 4 | The entry does not exist |
| `ErrDecryption` | 5 | Wrong master password or no matching identity |
| `ErrAgent` | 6 | The agent could not be reached or started |

**Path traversal.**
`pago.EntryFile` rejects names matching `NameInvalidChars` (`[\p{Cc}]`, all Unicode control characters) and verifies the resolved path is inside the store.
Resolve every user-supplied entry name through it.

**Symlinks.**
`os.Stat` follows symlinks.
Use `os.Lstat` when verifying ownership or mode of a path that should not be a symlink.
`agent.checkDirSecurity` is the existing pattern.

**TTY assumptions.**
Anything that prompts must check `input.IsTerminal()` and either fall back to a non-interactive path or abort with a clear message.
`term.MakeRaw` on a non-TTY produces an obscure ioctl error.

**Agent staleness.**
`rekey` and `rewrap` push fresh identities to a running agent via `pushIdentitiesToAgent`.
Any future operation that mutates the identities file must do the same, otherwise the agent silently runs with stale keys.

**Threat model.**
pago does not protect against an attacker running code as the same UID.
It does try to protect against co-resident users on a shared system: data dir, agent socket, and socket dir are `0o700`.
Do not add features that widen the latter without flagging it.

## When to ask before designing

For internal refactoring, just do it.
For user-visible changes, ask first when there is more than one defensible answer:

- Output formats and shapes (JSON wrapping, log layout, exit codes).
- Env var names and CLI flag names, especially renames.
- New top-level commands.
- Anything that changes existing exit codes, prompts, or files on disk.

Use `AskUserQuestion` with two to four labelled options and short descriptions.
Do not ask about purely internal choices.

## Working in batches

For large batches (more than five or six independent items), split into phases of four to six commits each.
Push and pause between phases.
A regression in an early commit can otherwise cost a lot of unwinding.
