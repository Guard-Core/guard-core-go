//go:build linux || darwin || freebsd

package guardcore

import "golang.org/x/sys/unix"

// clockIsThreadCPU reports that platformScanClock is per-thread CPU time,
// which is only meaningful while the goroutine stays on one OS thread (the
// budget pins it with runtime.LockOSThread for the length of a scan pass).
const clockIsThreadCPU = true

// platformScanClock returns the CPU time of the calling OS thread
// (clock_gettime CLOCK_THREAD_CPUTIME_ID, no cgo). The call cannot fail for
// this clock id; on an impossible error the zero timespec reads as no time
// spent, and the per-pattern regexp2 timeouts still bound each match.
func platformScanClock() float64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts)
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
