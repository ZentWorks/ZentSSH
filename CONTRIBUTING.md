# Contributing

Keep changes focused and do not commit credentials, database files, master keys or other secrets. New dependencies must use licenses compatible with MIT distribution and should be justified by the change that introduces them.

## Toolchain

Use the versions selected by the repository build: Go 1.27.x and Node.js 24.x. Docker/Compose is required for the final container build. The frontend dependency graph is locked by `frontend/package-lock.json`; use `npm ci`, not `npm install`, for verification and CI-equivalent builds.

## Checks

Before opening a pull request, run:

```bash
make static
make test
make security
make build
```

`make test` includes Go unit tests, the race detector, `go vet`, frontend syntax validation and the production frontend build. `make security` expects `govulncheck` to be installed. GitHub Actions runs the same backend/frontend checks and a clean Docker build.

When intentionally changing Go dependencies, update `backend/go.mod` with the normal Go tooling and review the resulting module graph. Do not run dependency-changing commands from the Dockerfile. When intentionally changing npm dependencies, regenerate and commit `frontend/package-lock.json`.
