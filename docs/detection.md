# Detection

## Standalone API

```go
result := guardcore.Detect(content, ip, context)
```

`Detect` runs the full detector (preprocessing, encoding normalization, pattern
matching, semantic analysis) over a string. `context` labels where the content
came from (e.g. `query`, `body`, `header`).

```go
type DetectResult struct {
    IsThreat        bool
    ThreatScore     float64
    Threats         []map[string]any
    OriginalLength  int
    ProcessedLength int
    DetectionMethod string
}
```

## Categories

`AllDetectionCategories`:

```text
xss, sqli, dir_traversal, path_traversal, cmd_injection, file_inclusion,
ldap, xml, ssrf, nosql, file_upload, template, http_split, sensitive_file,
cms_probing, recon, proto_pollution, code_injection, deserialization
```

By default every category is enabled. Restrict them with
`EnabledDetectionCategories`; exclude noisy sources with
`ExcludedDetectionHeaders`, `ExcludedDetectionParams`, and
`ExcludedDetectionBodyFields`. `ExcludedSemanticDetectionHeaders` is an opt-in set of header
names whose values skip the semantic analyzer only, while regex scanning
still runs on them.

The `Cookie` header is scanned one `name=value` pair at a time (split on
`;`, spaces around a pair trimmed, empty pairs skipped), each pair through the
same header path and counted against the scan value budget, so the semicolons
between ordinary cookies do not add up to a semantic hit.

## Tuning

The nested `guardcore.Config` controls detector internals:

| Field | Default | Notes |
|---|---|---|
| `CompilerTimeout` | `2s` | Regex compile guard |
| `MaxContentLength` | `10000` | Characters inspected per field |
| `PreserveAttackPatterns` | `true` | Keep raw patterns in results |
| `MaxBodyInspectBytes` | `262144` | Body bytes scanned |
| `SemanticThreshold` | `0.7` | Semantic model threshold |
| `ThreatScoreThreshold` | `1.0` | Regex anomaly (summed pattern weights) a value needs to count as a threat (valid range 0 to 10, zero means the default); semantic hits always count |
| `MaxScanSeconds` | `10.0` | Per-request regex scan time budget in seconds (valid range 0.1 to 60) |

`MaxScanSeconds` caps the regex scan time of one request, summed across every field and every pattern. It counts the CPU time of the scanning thread on linux, darwin and freebsd, so a busy or CPU-starved host does not spend it; on other platforms it counts wall time. Once spent, the remaining patterns and values are not scanned and the request gets a weighted `pattern_timeout` threat named `scan_time_budget_exhausted`, which blocks it the same way a per-pattern timeout does, and a one-time warning names the client IP. A bare `Detect` call outside a request has no budget. Only regex pattern time is counted, not decoding or semantic analysis.

## Threat-based bans

Detection verdicts feed the ban manager through `ThreatBanConfig`, keyed by
category:

```go
cfg.ThreatBanConfig = map[string]guardcore.ThreatBanEntry{
    "sqli": {Threshold: 3, Duration: 1800},
    "xss":  {Threshold: 5, Duration: 600},
}
```

An IP that trips a category more than `Threshold` times is banned for
`Duration` seconds.
