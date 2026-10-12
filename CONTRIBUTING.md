# Contributing

1. Keep changes aligned with [GOAL.md](GOAL.md).
2. `gofmt` everything; `go test -race ./...` must pass.
3. Add a fixture under `testdata/` for every new detection pattern.
4. Design language for the site is locked in `site/DESIGN.md` and `/workspace/oss-factory/design/registry.md` — do not drift toward generic SaaS tropes.
