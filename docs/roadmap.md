# Roadmap and known gaps

This port tracks the Python `guard-core` engine. Behavior that is implemented
differently, or deferred, is listed here (see `KNOWN_GAPS.md` in the repository
for the detailed per-milestone notes).

## Deferred

- **Redaction gate** - the Python engine's generative log-redaction fuzz
  harness (the CI redaction-gate workflow) is not ported. The config surface
  exists (`LogSensitiveHeaders`, `LogSensitiveParams`,
  `LogSensitiveBodyFields`), but no Go harness generates adversarial payloads
  and asserts redaction, so that CI gate is omitted rather than faked.

## Intentional differences

- `cloud_ip_refresh_interval` is clamped to `[60, 86400]` instead of rejecting
  out-of-range values.
- The custom-validators block hook fires with the validator's status code
  (spec 03 prose semantics).
- Cloud range refreshes use an injectable clock (`nowFunc`) for testability.

## Notes

- Ban expiry strings may differ in trailing digits from Python at epoch-scale
  doubles while remaining wire-equivalent.
- IPv6 `::ffff:`-mapped network CIDRs may render dotted-quad in Go.
- `reset` operations use Redis `KEYS` (spec-permitted); fine for admin
  tooling, avoid in hot paths.
