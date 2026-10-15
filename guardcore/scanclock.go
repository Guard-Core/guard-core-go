package guardcore

import "time"

// scanCPUNow reads the clock the per-request scan time budget runs on. On
// linux, darwin and freebsd it is the CPU time of the calling OS thread
// (clockIsThreadCPU), so a loaded or CPU-starved host does not spend the
// budget; elsewhere it is the wall-clock fallback. A variable so tests can
// drive it.
var scanCPUNow = platformScanClock

var scanClockEpoch = time.Now()

// wallClockSeconds is the fallback scan clock: seconds on the monotonic
// wall clock. It counts time the goroutine spends descheduled, so on a
// platform without a per-thread CPU clock a heavily loaded host can spend
// the budget faster than the CPU work alone would.
func wallClockSeconds() float64 {
	return time.Since(scanClockEpoch).Seconds()
}
