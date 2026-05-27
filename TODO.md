# TODO

1. Split `dnssec.validateLevel` in `internal/checks/dnssec/dnssec.go` into `validateRootLevel` and `validateSignedLevel`.
2. Simplify `cmd.buildReport` in `cmd/root.go` to return `(check.Report, int)` instead of `(check.Report, int, error)`.
3. Replace the long `runWithResolver` parameter list in `cmd/root.go` with a small injected-dependencies struct.
4. Unify repeated DNS response parsing helpers across `internal/dnsutil/dnsutil.go`, `internal/checks/ttl/ttl.go`, `internal/checks/dnssec/dnssec.go`, and `internal/checks/consistency/consistency.go`.
5. Factor common `check.Result` construction patterns in the check packages.
6. Extract shared authoritative-server traversal logic used across `delegation`, `consistency`, and `trace`.
7. Remove or implement currently unused CLI flags and config fields in `cmd/root.go`, especially `Verbose` and `CheckUpdate`.
8. Normalize naming around resolver abstractions such as `RecursiveClient`, `AuthoritativeClient`, `Client`, `runResolver`, and `fallbackReporter`.
9. Move command runtime helpers like `stripPorts`, `fallbackMessage`, and report summarization logic out of `cmd/root.go` into a more focused file.
10. Add short explanatory comments for subtle helpers like `v4v6Split`, `reportFromResults`, and `fallbackMessage`.
