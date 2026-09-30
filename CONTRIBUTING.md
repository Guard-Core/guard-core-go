# Contributing to Guard Core Go

Thanks for considering a contribution to Guard Core Go, part of the Guard ecosystem (guard-core-go follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- Go 1.25 or newer
- Docker (Redis runs as a CI service locally too, via `docker run -p 6379:6379 redis:7-alpine`)

```bash
go mod download
go build ./...
go test ./...
go test -tags integration ./...   # needs Redis on 127.0.0.1:6379
```

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
gofmt -l .            # must print nothing
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@latest && staticcheck ./...
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
