package guardcore

// Unit tests for the built-in GeoIPManager (the port of the reference
// IPInfoManager lookup half, guard_core/handlers/ipinfo_handler.py) and for
// the country-rule config validation (the reference coerce_country_set and
// _resolve_geo_ip_handler in guard_core/_security_config_geo_validators.py).
// The MMDB fixture is generated in-test, mirroring the reference suite where
// the reader is faked instead of shipping a MaxMind database.

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestMMDB writes a minimal MMDB database (record size 24, IPv4) into a
// temp file, mapping the given prefixes to ISO country codes, and returns
// the path. Only top-level "country" string records are written, the ipinfo
// country_asn.mmdb layout the reference get_country reads.
func buildTestMMDB(t *testing.T, entries map[string]string) string {
	t.Helper()

	type mmdbNode struct {
		left, right *mmdbNode
		country     string
	}
	root := &mmdbNode{}
	for prefix, code := range entries {
		p := netip.MustParsePrefix(prefix)
		raw := p.Addr().As4()
		cur := root
		for i := 0; i < p.Bits(); i++ {
			bit := (raw[i/8] >> (7 - i%8)) & 1
			next := &cur.left
			if bit == 1 {
				next = &cur.right
			}
			if *next == nil {
				*next = &mmdbNode{}
			}
			cur = *next
		}
		cur.country = code
	}

	// Data section first: one {"country": code} map per unique code, so the
	// leaf records can point at stable offsets.
	countryOffsets := map[string]uint32{}
	var dataSection []byte
	for _, code := range entries {
		if _, ok := countryOffsets[code]; ok {
			continue
		}
		countryOffsets[code] = uint32(len(dataSection))
		if code == "-" {
			// The "-" sentinel writes a record without a country field,
			// exercising the country-less lookup path.
			record := []byte{0xE1} // map, 1 entry
			record = append(record, 0x40|4)
			record = append(record, "lang"...)
			record = append(record, 0x40|2)
			record = append(record, "en"...)
			dataSection = append(dataSection, record...)
			continue
		}
		record := []byte{0xE1} // map, 1 entry
		record = append(record, 0x40|7)
		record = append(record, "country"...)
		record = append(record, byte(0x40|len(code)))
		record = append(record, code...)
		dataSection = append(dataSection, record...)
	}

	// BFS index assignment over the internal nodes (node 0 is the root);
	// country-carrying slots emit data pointers instead of node indexes.
	index := map[*mmdbNode]int{root: 0}
	queue := []*mmdbNode{root}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, child := range []*mmdbNode{n.left, n.right} {
			if child == nil || child.country != "" {
				continue
			}
			index[child] = len(index)
			queue = append(queue, child)
		}
	}
	nodeCount := len(index)
	ordered := make([]*mmdbNode, nodeCount)
	for n, i := range index {
		ordered[i] = n
	}

	emitRecord := func(child *mmdbNode) []byte {
		var value uint32
		switch {
		case child == nil:
			value = 0
		case child.country != "":
			// Data section pointers are measured from the separator start,
			// so the record carries the 16 separator bytes as well.
			value = uint32(nodeCount) + 16 + countryOffsets[child.country]
		default:
			value = uint32(index[child])
		}
		return []byte{byte(value >> 16), byte(value >> 8), byte(value)}
	}
	var tree []byte
	for _, n := range ordered {
		tree = append(tree, emitRecord(n.left)...)
		tree = append(tree, emitRecord(n.right)...)
	}

	metadata := metadataSection(nodeCount)
	out := append([]byte{}, tree...)
	out = append(out, make([]byte, 16)...) // data section separator
	out = append(out, dataSection...)
	out = append(out, []byte("\xAB\xCD\xEFMaxMind.com")...)
	out = append(out, metadata...)

	path := filepath.Join(t.TempDir(), "country_asn.mmdb")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write mmdb fixture: %v", err)
	}
	return path
}

// metadataSection encodes the MMDB metadata map the maxminddb reader
// requires (record size 24, IPv4).
func metadataSection(nodeCount int) []byte {
	mmdbString := func(s string) []byte {
		// Fixture strings stay under the 29 byte inline size cap.
		return append([]byte{0x40 | byte(len(s))}, s...)
	}
	mmdbUint16 := func(v uint16) []byte { return []byte{0xA2, byte(v >> 8), byte(v)} }
	mmdbUint32 := func(v uint32) []byte { return []byte{0xC4, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

	var meta []byte
	meta = append(meta, 0xE0|9) // map, 9 entries
	meta = append(meta, mmdbString("node_count")...)
	meta = append(meta, mmdbUint32(uint32(nodeCount))...)
	meta = append(meta, mmdbString("record_size")...)
	meta = append(meta, mmdbUint16(24)...)
	meta = append(meta, mmdbString("ip_version")...)
	meta = append(meta, mmdbUint16(4)...)
	meta = append(meta, mmdbString("database_type")...)
	meta = append(meta, mmdbString("GuardCore-Test-Country")...)
	meta = append(meta, mmdbString("languages")...)
	// Array is extended type 11: a type-0 control byte (size 1) followed by
	// the extended type marker 11-7, then the single "en" element.
	meta = append(meta, 0x01, 0x04)
	meta = append(meta, mmdbString("en")...)
	meta = append(meta, mmdbString("binary_format_major_version")...)
	meta = append(meta, mmdbUint16(2)...)
	meta = append(meta, mmdbString("binary_format_minor_version")...)
	meta = append(meta, mmdbUint16(0)...)
	meta = append(meta, mmdbString("build_epoch")...)
	meta = append(meta, mmdbUint32(1700000000)...)
	meta = append(meta, mmdbString("description")...)
	meta = append(meta, 0xE1) // map, 1 entry
	meta = append(meta, mmdbString("en")...)
	meta = append(meta, mmdbString("GuardCore test database")...)
	return meta
}

func TestGeoIPManagerResolvesMMDBCountries(t *testing.T) {
	path := buildTestMMDB(t, map[string]string{
		"192.0.2.0/24":    "US",
		"198.51.100.0/32": "BR", // a host route
	})
	manager := NewGeoIPManager(path)
	defer func() { _ = manager.Close() }()

	cases := []struct {
		ip      string
		country string
		ok      bool
	}{
		{"192.0.2.7", "US", true},
		{"192.0.2.200", "US", true},
		{"198.51.100.0", "BR", true},
		{"198.51.100.1", "", false}, // outside every fixture prefix
		{"not-an-ip", "", false},    // unparseable addresses miss
	}
	for _, tc := range cases {
		country, ok := manager.GetCountry(tc.ip)
		if ok != tc.ok || country != tc.country {
			t.Fatalf("GetCountry(%q) = (%q, %v), want (%q, %v)", tc.ip, country, ok, tc.country, tc.ok)
		}
	}
}

func TestGeoIPManagerMissingDatabaseFailsSoft(t *testing.T) {
	manager := NewGeoIPManager(filepath.Join(t.TempDir(), "missing.mmdb"))
	if country, ok := manager.GetCountry("192.0.2.7"); ok || country != "" {
		t.Fatalf("lookups against a missing database must miss, got (%q, %v)", country, ok)
	}
}

func TestGeoIPManagerCorruptDatabaseFailsSoft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.mmdb")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	manager := NewGeoIPManager(path)
	if country, ok := manager.GetCountry("192.0.2.7"); ok || country != "" {
		t.Fatalf("lookups against a corrupted database must miss, got (%q, %v)", country, ok)
	}
}

func TestCountryListsNormalizeToUpper(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockedCountries = []string{"us", "Br", "US"}
		c.GeoIPHandler = fakeCountryResolver{}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if got := cfg.BlockedCountries; strings.Join(got, ",") != "US,BR" {
		t.Fatalf("blocked_countries must uppercase and dedupe, got %v", got)
	}
}

func TestCountryRulesRequireGeoResolver(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SecurityConfig)
	}{
		{"blocked_countries", func(c *SecurityConfig) { c.BlockedCountries = []string{"CN"} }},
		{"whitelist_countries", func(c *SecurityConfig) { c.WhitelistCountries = []string{"US"} }},
	}
	for _, tc := range cases {
		_, err := NewSecurityConfig(tc.mutate)
		if err == nil {
			t.Fatalf("%s without a resolver must fail config construction", tc.name)
		}
		if !strings.Contains(err.Error(), "geo_ip_handler is required") {
			t.Fatalf("%s error must mirror the reference message, got %v", tc.name, err)
		}
	}
}

func TestGeoIPDBPathBuildsBuiltinResolver(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockedCountries = []string{"CN"}
		c.GeoIPDBPath = filepath.Join(t.TempDir(), "country_asn.mmdb")
	})
	if err != nil {
		t.Fatalf("config with GeoIPDBPath must validate: %v", err)
	}
	if cfg.GeoIPHandler == nil {
		t.Fatalf("GeoIPDBPath must resolve to a built-in GeoIPManager")
	}
	if _, ok := cfg.GeoIPHandler.(*GeoIPManager); !ok {
		t.Fatalf("built-in resolver must be a *GeoIPManager, got %T", cfg.GeoIPHandler)
	}
}

func TestInjectedResolverSatisfiesGeoRequirement(t *testing.T) {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.BlockedCountries = []string{"CN"}
		c.GeoIPHandler = fakeCountryResolver{"192.0.2.7": "CN"}
	})
	if err != nil {
		t.Fatalf("config with an injected resolver must validate: %v", err)
	}
	if country, ok := cfg.GeoIPHandler.GetCountry("192.0.2.7"); !ok || country != "CN" {
		t.Fatalf("injected resolver must survive validation, got (%q, %v)", country, ok)
	}
}

func TestCountryAllowlistShadowBlocklistStillValid(t *testing.T) {
	// The reference warns instead of failing: the allowlist merely shadows
	// the blocklist.
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.WhitelistCountries = []string{"US"}
		c.BlockedCountries = []string{"CN"}
		c.GeoIPHandler = fakeCountryResolver{}
	})
	if err != nil {
		t.Fatalf("both country lists must stay valid, got %v", err)
	}
	if len(cfg.WhitelistCountries) != 1 || len(cfg.BlockedCountries) != 1 {
		t.Fatalf("both lists must be kept for the shadow warning, got %v / %v", cfg.WhitelistCountries, cfg.BlockedCountries)
	}
}
