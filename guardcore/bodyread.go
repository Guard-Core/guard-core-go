package guardcore

import (
	"log"
	"sync"
	"time"
)

// The bounded body read, mirroring the reference body_read_timeout /
// sync_body_read_max_concurrent pair (_security_config_fields.py): the
// async tree bounds the read with asyncio.wait_for, the sync tree runs it
// on a daemon thread joined with the timeout, and a shared budget bounds
// how many threads may be parked inside a stalled stream at once. The Go
// port bounds every engine-side body read the same way: the read runs on
// its own goroutine raced against the timeout, an abandoned read keeps
// running until the stream itself returns (exactly like the reference's
// timed-out daemon thread), and a package-level semaphore keeps the
// parked goroutine count bounded with the reference's queue-then-give-up
// behavior on exhaustion.

var (
	bodyReadSlots     = make(chan struct{}, 64)
	bodyReadSlotsOnce sync.Once
)

// ensureBodyReadSlots sizes the read-slot budget once per process from the
// config's sync_body_read_max_concurrent (the reference builds its thread
// budget once at middleware construction; later config edits are inert).
func ensureBodyReadSlots(n int) {
	bodyReadSlotsOnce.Do(func() {
		bodyReadSlots = make(chan struct{}, normalizeBodyReadSlots(n))
	})
}

// normalizeBodyReadSlots applies the reference default: a non-positive
// budget keeps the 64-slot default.
func normalizeBodyReadSlots(n int) int {
	if n < 1 {
		return 64
	}
	return n
}

// BoundBodyRead runs read within the config's body_read_timeout budget,
// under the sync_body_read_max_concurrent slot budget: a slot is acquired
// (queuing while full), the read races the timer, a timeout leaves the
// read goroutine running until the stream returns and reports the body
// unavailable, and slot exhaustion logs the exhaustion and reports the
// body unavailable without starting a read.
func BoundBodyRead(cfg *SecurityConfig, read func() ([]byte, error)) ([]byte, error) {
	if cfg == nil {
		return read()
	}
	timeout := cfg.BodyReadTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ensureBodyReadSlots(cfg.SyncBodyReadMaxConcurrent)
	select {
	case bodyReadSlots <- struct{}{}:
	case <-time.After(timeout):
		log.Printf("sync_body_read_max_concurrent (%d) exhausted; the body read gives up and the body is treated as unavailable", cap(bodyReadSlots))
		return nil, errBodyReadBudget
	}

	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		// The read goroutine holds the slot until the stream itself
		// returns, exactly like the reference's parked daemon thread: a
		// timed-out caller stops waiting but the budget stays consumed.
		defer func() { <-bodyReadSlots }()
		body, err := read()
		done <- result{body: body, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.body, r.err
	case <-timer.C:
		// The timed-out read keeps running in the background until the
		// adapter's stream itself returns; only this caller stops waiting.
		return nil, errBodyReadTimeout
	}
}

var (
	errBodyReadTimeout = &bodyReadError{kind: "timeout"}
	errBodyReadBudget  = &bodyReadError{kind: "budget"}
)

// bodyReadError marks an unavailable body: the reference treats a timed
// out read exactly like a failed adapter read (the detection pass scans
// nothing for that surface).
type bodyReadError struct{ kind string }

func (e *bodyReadError) Error() string {
	if e.kind == "budget" {
		return "body read gave up: sync_body_read_max_concurrent exhausted"
	}
	return "body read timed out (body_read_timeout)"
}
