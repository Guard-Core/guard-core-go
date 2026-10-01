package guardcore

import (
	"testing"
	"time"
)

// The redis interop corpus pins the last-known snapshot bytes against the
// reference dump (specs/08 byte equality): a rules struct built from a
// minimal agent delivery must serialize with the pydantic model's
// collection defaults, never nulls.
func TestDumpLastKnownRulesSnapshotByteParity(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := DumpLastKnownRulesSnapshot(DynamicRules{
		RuleID:    "rio-rules",
		Version:   3,
		Timestamp: ts,
	})
	want := `{"schema_version":1,"rules":{"rule_id":"rio-rules","version":3,"timestamp":"2026-01-01T00:00:00Z","expires_at":null,"ttl":300,"ip_blacklist":[],"ip_whitelist":[],"ip_ban_duration":3600,"blocked_countries":[],"whitelist_countries":[],"global_rate_limit":null,"global_rate_window":null,"endpoint_rate_limits":{},"blocked_cloud_providers":[],"blocked_user_agents":[],"suspicious_patterns":[],"enable_penetration_detection":null,"enable_ip_banning":null,"enable_rate_limiting":null,"auto_ban_threshold":null,"auto_ban_duration":null,"enable_rate_limit_auto_ban":null,"emergency_mode":false,"emergency_whitelist":[]}}`
	if got != want {
		t.Fatalf("snapshot bytes drifted:\n got %s\nwant %s", got, want)
	}
}
