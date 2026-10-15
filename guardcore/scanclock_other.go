//go:build !(linux || darwin || freebsd)

package guardcore

// clockIsThreadCPU is false here: no per-thread CPU clock is wired for this
// platform, so the budget runs on wall time (see wallClockSeconds).
const clockIsThreadCPU = false

func platformScanClock() float64 { return wallClockSeconds() }
