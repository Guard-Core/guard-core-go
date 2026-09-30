package guardcore

import (
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	LOCAL_CACHE_TTL_CAP_SECONDS = 3600
	localCacheMaxSize           = 10000
	evictionWarnInterval        = 100
)

type localBanEntry struct {
	expiry     float64
	insertTime time.Time
}

type networkBanEntry struct {
	network netip.Prefix
	expiry  float64
}

type IPBanManager struct {
	mu             sync.Mutex
	bannedIPs      map[string]localBanEntry
	lruOrder       []string
	bannedNetworks []networkBanEntry
	redis          RedisHandler
	admin          RedisAdmin
	trustedProxies []netip.Prefix
	evictions      int
	logger         *log.Logger
	eventBus       *SecurityEventBus
}

func NewIPBanManager(redisHandler RedisHandler, trustedProxies []string) *IPBanManager {
	m := &IPBanManager{
		bannedIPs: make(map[string]localBanEntry),
		logger:    log.Default(),
	}
	if redisHandler != nil {
		m.redis = redisHandler
		if admin, ok := redisHandler.(RedisAdmin); ok {
			m.admin = admin
		}
	}
	for _, entry := range trustedProxies {
		prefix, err := parseNetwork(entry)
		if err != nil {
			continue
		}
		m.trustedProxies = append(m.trustedProxies, prefix)
	}
	return m
}

func parseNetwork(value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(CanonicalizeIP(value))
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func formatExpiry(expiry float64) string {
	return strconv.FormatFloat(expiry, 'f', -1, 64)
}

func (m *IPBanManager) assertPositiveDuration(duration int) error {
	if duration <= 0 {
		return &GuardRedisError{StatusCode: 400, Message: "ban duration must be positive"}
	}
	return nil
}

func (m *IPBanManager) targetNetwork(ip string) (netip.Prefix, error) {
	return parseNetwork(ip)
}

func (m *IPBanManager) selfDoSRefusalReason(ip string) string {
	target, err := m.targetNetwork(ip)
	if err != nil {
		return ""
	}
	loopbackNetworks := []string{"127.0.0.0/8", "::1/128"}
	for _, entry := range loopbackNetworks {
		network, _ := parseNetwork(entry)
		if sameFamily(target, network) && target.Overlaps(network) {
			return "loopback"
		}
	}
	for _, network := range m.trustedProxies {
		if sameFamily(target, network) && target.Overlaps(network) {
			return "trusted_proxy"
		}
	}
	return ""
}

func sameFamily(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && a.Addr().BitLen() == b.Addr().BitLen()
}

func (m *IPBanManager) clampToLocalCap(duration int, cause string) int {
	if duration <= LOCAL_CACHE_TTL_CAP_SECONDS {
		return duration
	}
	m.logger.Printf("Redis unavailable (%s): ban shortened from %ds to %ds so protection still applies", cause, duration, LOCAL_CACHE_TTL_CAP_SECONDS)
	return LOCAL_CACHE_TTL_CAP_SECONDS
}

func (m *IPBanManager) localSet(ip string, expiry float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.bannedIPs[ip]; !exists && len(m.bannedIPs) >= localCacheMaxSize {
		victim := m.lruOrder[0]
		m.lruOrder = m.lruOrder[1:]
		delete(m.bannedIPs, victim)
		m.evictions++
		if m.evictions%evictionWarnInterval == 0 {
			m.logger.Printf("IP ban cache full; %d entries evicted (silent overflow)", m.evictions)
		}
	}
	if _, exists := m.bannedIPs[ip]; !exists {
		m.lruOrder = append(m.lruOrder, ip)
	}
	m.bannedIPs[ip] = localBanEntry{expiry: expiry, insertTime: time.Now()}
}

func (m *IPBanManager) localPurge(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.bannedIPs[ip]; exists {
		delete(m.bannedIPs, ip)
		for i, key := range m.lruOrder {
			if key == ip {
				m.lruOrder = append(m.lruOrder[:i], m.lruOrder[i+1:]...)
				break
			}
		}
	}
}

func (m *IPBanManager) localGet(ip string, now float64) (float64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.bannedIPs[ip]
	if !exists {
		return 0, false
	}
	if now > entry.expiry || now > float64(entry.insertTime.UnixMilli())/1000+LOCAL_CACHE_TTL_CAP_SECONDS {
		delete(m.bannedIPs, ip)
		for i, key := range m.lruOrder {
			if key == ip {
				m.lruOrder = append(m.lruOrder[:i], m.lruOrder[i+1:]...)
				break
			}
		}
		return 0, false
	}
	return entry.expiry, true
}

func (m *IPBanManager) Ban(ip string, duration int, reason string) (bool, error) {
	ip = CanonicalizeIP(ip)
	if err := m.assertPositiveDuration(duration); err != nil {
		return false, err
	}
	if refusal := m.selfDoSRefusalReason(ip); refusal != "" {
		space := "a configured trusted proxy"
		if refusal == "loopback" {
			space = "loopback"
		}
		m.logger.Printf("Refused to ban %s: overlaps %s space and would self-DoS this deployment", ip, space)
		return false, nil
	}
	if strings.Contains(ip, "/") {
		if err := m.banNetwork(ip, duration); err != nil {
			return false, err
		}
	} else {
		if err := m.banExact(ip, duration, reason); err != nil {
			return false, err
		}
	}
	// Reference _ipban_events.py: ip_banned, handler ip_ban, metadata
	// carrying the ban duration.
	m.mu.Lock()
	bus := m.eventBus
	m.mu.Unlock()
	if bus != nil {
		bus.SendHandlerEvent(EventIPBanned, IPBanHandlerName, ip, "banned", reason,
			map[string]any{"duration": duration})
	}
	return true, nil
}

func (m *IPBanManager) banExact(ip string, duration int, reason string) error {
	if _, err := netip.ParseAddr(ip); err != nil {
		return &GuardRedisError{StatusCode: 400, Message: "Invalid IP address " + ip}
	}
	now := float64(time.Now().UnixNano()) / 1e9
	clamped := duration
	redisConfigured := m.redis != nil
	if redisConfigured && !m.redis.Enabled() {
		redisConfigured = false
	}
	if !redisConfigured {
		clamped = m.clampToLocalCap(duration, "not configured")
	}
	expDelta := float64(clamped)
	if redisConfigured {
		expDelta = float64(duration)
	}
	expiry := now + expDelta
	m.localSet(ip, expiry)
	if redisConfigured {
		ttl := duration
		if err := m.redis.SetKey("banned_ips", ip, formatExpiry(expiry), &ttl); err != nil {
			clamped = m.clampToLocalCap(duration, "request failed")
			m.localSet(ip, now+float64(clamped))
		}
	}
	return nil
}

func (m *IPBanManager) banNetwork(ip string, duration int) error {
	network, err := netip.ParsePrefix(ip)
	if err != nil {
		return &GuardRedisError{StatusCode: 400, Message: "Invalid CIDR network " + ip}
	}
	network = network.Masked()
	now := float64(time.Now().UnixNano()) / 1e9
	redisUsable := m.redis != nil && m.redis.Enabled()
	if redisUsable {
		ttl := duration
		err := m.redis.SetKey("banned_networks", network.String(), formatExpiry(now+float64(duration)), &ttl)
		if err == nil {
			return nil
		}
	}
	clamped := m.clampToLocalCap(duration, map[bool]string{true: "request failed", false: "not configured"}[redisUsable])
	m.mu.Lock()
	m.bannedNetworks = append(m.bannedNetworks, networkBanEntry{network: network, expiry: now + float64(clamped)})
	m.mu.Unlock()
	return nil
}

func (m *IPBanManager) IsIPBanned(ip string) bool {
	ip = CanonicalizeIP(ip)
	now := float64(time.Now().UnixNano()) / 1e9
	if _, hit := m.localGet(ip, now); hit {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if m.checkNetworkCache(addr, now) {
		return true
	}
	if m.redis == nil || !m.redis.Enabled() {
		return false
	}
	return m.checkRedisExact(ip, now)
}

func (m *IPBanManager) checkNetworkCache(addr netip.Addr, now float64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := m.bannedNetworks[:0]
	hit := false
	for _, entry := range m.bannedNetworks {
		if entry.expiry <= now {
			continue
		}
		active = append(active, entry)
		if !hit && entry.network.Addr().BitLen() == addr.BitLen() && entry.network.Contains(addr) {
			hit = true
		}
	}
	m.bannedNetworks = active
	return hit
}

func (m *IPBanManager) checkRedisExact(ip string, now float64) bool {
	value, err := m.redis.GetKey("banned_ips", ip)
	if err != nil || value == "" {
		return false
	}
	expiry, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	if now <= expiry {
		m.localSet(ip, expiry)
		return true
	}
	_, _ = m.redis.Delete("banned_ips", ip)
	return false
}

func (m *IPBanManager) Unban(ip string) error {
	ip = CanonicalizeIP(ip)
	m.localPurge(ip)
	if m.redis != nil && m.redis.Enabled() {
		if _, err := m.redis.Delete("banned_ips", ip); err != nil {
			return err
		}
	}
	// Reference _ipban_events.py: ip_unbanned with the fixed
	// dynamic_rule_whitelist reason and the unban action.
	m.mu.Lock()
	bus := m.eventBus
	m.mu.Unlock()
	if bus != nil {
		bus.SendHandlerEvent(EventIPUnbanned, IPBanHandlerName, ip, "unbanned", "dynamic_rule_whitelist",
			map[string]any{"action": "unban"})
	}
	return nil
}

// SetEventBus attaches the agent event stream so the manager emits the
// reference ip_ban handler events. Safe for concurrent use.
func (m *IPBanManager) SetEventBus(bus *SecurityEventBus) {
	m.mu.Lock()
	m.eventBus = bus
	m.mu.Unlock()
}

func (m *IPBanManager) Reset() error {
	m.mu.Lock()
	m.bannedIPs = make(map[string]localBanEntry)
	m.lruOrder = nil
	m.bannedNetworks = nil
	m.mu.Unlock()
	if m.redis != nil && m.redis.Enabled() {
		_, err := m.redis.DeletePattern("banned_ips:*")
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *IPBanManager) InitializeRedis(redisHandler RedisHandler) error {
	m.redis = redisHandler
	if admin, ok := redisHandler.(RedisAdmin); ok {
		m.admin = admin
	}
	m.migrateLegacyBanKeys()
	return nil
}

func (m *IPBanManager) migrateLegacyBanKeys() {
	if m.redis == nil || !m.redis.Enabled() || m.admin == nil {
		return
	}
	prefix := m.redis.Prefix() + "banned_ips:"
	keys, err := m.admin.ScanMatch(prefix + "*")
	if err != nil {
		m.logger.Printf("Legacy ban-key migration skipped: %v", err)
		return
	}
	for _, key := range keys {
		if err := m.migrateOneBanKey(key, prefix); err != nil {
			m.logger.Printf("Legacy ban-key migration skipped: %v", err)
		}
	}
}

func (m *IPBanManager) migrateOneBanKey(key, prefix string) error {
	rawIP := key[len(prefix):]
	canonicalIP := CanonicalizeIP(rawIP)
	if canonicalIP == rawIP {
		return nil
	}
	value, err := m.redis.GetKey("banned_ips", rawIP)
	if err != nil {
		return err
	}
	oldPTTL, err := m.admin.PTTL(key)
	if err != nil {
		return err
	}
	if oldPTTL <= 0 {
		if _, err := m.admin.DeleteKeys(key); err != nil {
			return err
		}
		return nil
	}
	canonicalKey := prefix + canonicalIP
	newPTTL, err := m.admin.PTTL(canonicalKey)
	if err != nil {
		return err
	}
	if newPTTL < oldPTTL {
		if err := m.admin.SetPX(canonicalKey, value, oldPTTL); err != nil {
			return err
		}
	}
	_, err = m.admin.DeleteKeys(key)
	return err
}

func (m *IPBanManager) BannedNetworkCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bannedNetworks)
}

func (m *IPBanManager) BannedIPCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bannedIPs)
}
