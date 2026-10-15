package guardcore

import (
	"log"
	"runtime"
)

// detectionScanBudget carries the per-request scan caps, mirroring the
// reference contextvar trio (guard_core/_utils/detection_scan.py
// _scan_value_budget): the value count and the char count accumulate
// across every value the penetration-detection pass hands to the pattern
// engine, the first over-cap value logs a one-time warning naming the
// client IP (the fail-open stays visible instead of silent), and the JSON
// depth cap warns once when the walk first serializes a too-deep
// container back to text.
type detectionScanBudget struct {
	cfg      *SecurityConfig
	clientIP string

	values      int
	chars       int
	valueWarned bool
	charWarned  bool
	depthWarned bool

	// The time budget (detection_max_scan_seconds): spent is the summed
	// scan-clock time of every finished pass, passStart the clock reading
	// when the current pass began.
	clock       func() float64
	scanSeconds float64
	spent       float64
	passStart   float64
	timeWarned  bool
}

func newDetectionScanBudget(cfg *SecurityConfig, clientIP string) *detectionScanBudget {
	b := &detectionScanBudget{cfg: cfg, clientIP: clientIP, clock: scanCPUNow, scanSeconds: 10.0}
	if cfg != nil && cfg.Detection.MaxScanSeconds > 0 {
		b.scanSeconds = cfg.Detection.MaxScanSeconds
	}
	return b
}

// beginPass starts timing one regex pass (a view scan or the runtime
// registry scan) and returns the function that ends it, adding the pass to
// the spent total. Only regex work runs inside a pass, so decoding and
// semantic analysis are not counted, like the reference. With a per-thread
// CPU clock the goroutine is pinned to its OS thread for the pass so both
// readings come from the same thread.
func (b *detectionScanBudget) beginPass() func() {
	if b == nil {
		return func() {}
	}
	if clockIsThreadCPU {
		runtime.LockOSThread()
	}
	b.passStart = b.clock()
	return func() {
		b.spent += b.clock() - b.passStart
		if clockIsThreadCPU {
			runtime.UnlockOSThread()
		}
	}
}

// timeExhausted mirrors _scan_time_budget_exhausted: true once the time
// spent in finished passes plus the running pass reaches the cap.
func (b *detectionScanBudget) timeExhausted() bool {
	if b == nil {
		return false
	}
	return b.spent+(b.clock()-b.passStart) >= b.scanSeconds
}

// timeBudgetThreat mirrors _scan_time_budget_exhausted_threat plus the
// one-time warning (_warn_scan_time_cap_reached_once): the weighted
// pattern_timeout threat that makes an exhausted budget fail closed.
func (b *detectionScanBudget) timeBudgetThreat() map[string]any {
	if !b.timeWarned {
		b.timeWarned = true
		log.Printf("detection_max_scan_seconds (%v) reached for client %s; remaining patterns and request values are not scanned", b.scanSeconds, b.clientIP)
	}
	return map[string]any{
		"type":           "pattern_timeout",
		"pattern":        scanTimeBudgetExhaustedPattern,
		"match":          "",
		"position":       0,
		"execution_time": 0.0,
		"category":       "custom",
		"weight":         resolvePatternWeight(scanTimeBudgetExhaustedPattern, "custom"),
	}
}

const scanTimeBudgetExhaustedPattern = "scan_time_budget_exhausted"

func (b *detectionScanBudget) valuesCap() int {
	if b.cfg != nil && b.cfg.Detection.MaxScanValues > 0 {
		return b.cfg.Detection.MaxScanValues
	}
	return 512
}

func (b *detectionScanBudget) charsCap() int {
	if b.cfg != nil && b.cfg.Detection.MaxScanChars > 0 {
		return b.cfg.Detection.MaxScanChars
	}
	return 65536
}

func (b *detectionScanBudget) depthCap() int {
	if b.cfg != nil && b.cfg.Detection.MaxJSONDepth > 0 {
		return b.cfg.Detection.MaxJSONDepth
	}
	return 32
}

// exhausted mirrors _scan_budget_exhausted: the value budget counts first
// (the value at cap+1 trips the one-time warning and every value after it
// is skipped), then the char budget accumulates this value's length and
// skips every value once the cap is consumed.
func (b *detectionScanBudget) exhausted(content string) bool {
	if b == nil {
		return false
	}
	b.values++
	if cap := b.valuesCap(); b.values > cap {
		if !b.valueWarned {
			b.valueWarned = true
			log.Printf("detection_max_scan_values (%d) reached for client %s; remaining request values are not scanned", cap, b.clientIP)
		}
		return true
	}
	consumed := b.chars
	if cap := b.charsCap(); consumed >= cap {
		if !b.charWarned {
			b.charWarned = true
			log.Printf("detection_max_scan_chars (%d) reached for client %s; remaining request values are not scanned", cap, b.clientIP)
		}
		return true
	}
	b.chars = consumed + len(content)
	return false
}

// warnJSONDepthOnce mirrors _warn_json_depth_cap_reached_once.
func (b *detectionScanBudget) warnJSONDepthOnce() {
	if b == nil {
		return
	}
	if b.depthWarned {
		return
	}
	b.depthWarned = true
	log.Printf("detection_max_json_depth (%d) reached for client %s; nested content below that depth is scanned as text", b.depthCap(), b.clientIP)
}

// clientIPForBudget resolves the budget's client IP for the warning lines,
// falling back to the unknown-identity sentinel like the reference's
// unknown-client display.
func clientIPForBudget(req Request) string {
	ip := resolveClientIP(req)
	if ip == "" {
		return UnknownClientIdentity
	}
	return ip
}

// budgetDepthCap resolves the walk's depth cap: the budget's configured
// cap when present, the reference default (32, the old jsonWalkDepthCap
// const) otherwise.
func budgetDepthCap(budget *detectionScanBudget) int {
	if budget == nil {
		return 32
	}
	return budget.depthCap()
}
