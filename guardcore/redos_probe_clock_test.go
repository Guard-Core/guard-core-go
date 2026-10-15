package guardcore

import (
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

// TestProbeTimingIgnoresCPUContention pins the reach-probe samples to CPU
// time: on a starved host the wall time of a match inflates, and a wall
// sample would push the extrapolated cost over budget and flip a pattern's
// cost verdict from safe to unsafe.
func TestProbeTimingIgnoresCPUContention(t *testing.T) {
	if !clockIsThreadCPU {
		t.Skip("no per-thread CPU clock on this platform")
	}
	re, err := compileRE(referenceScanPatternSrc, regexp2.IgnoreCase, 0)
	if err != nil {
		t.Fatal(err)
	}
	probe := "/" + strings.Repeat("0", 400000)

	var stop atomic.Bool
	for i := 0; i < 4*runtime.NumCPU(); i++ {
		go func() {
			for !stop.Load() {
			}
		}()
	}
	defer stop.Store(true)

	var sampled float64
	start := time.Now()
	for i := 0; i < 6; i++ {
		sampled += timeProbes(re, []string{probe}, 1).samplesBySize[0][0]
	}
	wall := time.Since(start).Seconds()
	if sampled > 0.7*wall {
		t.Fatalf("probe samples track wall time under contention: sampled %.3fs of %.3fs wall", sampled, wall)
	}
}
