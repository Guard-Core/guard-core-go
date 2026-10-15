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

## Tuning

The nested `guardcore.Config` controls detector internals:

| Field | Default | Notes |
|---|---|---|
| `CompilerTimeout` | `2s` | Regex compile guard |
| `MaxContentLength` | `10000` | Characters inspected per field |
| `PreserveAttackPatterns` | `true` | Keep raw patterns in results |
| `MaxBodyInspectBytes` | `262144` | Body bytes scanned |
| `SemanticThreshold` | `0.7` | Semantic model threshold |
| `ThreatScoreThreshold` | `1.0` | Score above which content is a threat |

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
