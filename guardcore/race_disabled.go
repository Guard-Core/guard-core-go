//go:build !race

package guardcore

// raceEnabled reports a race-detector build. The wall-clock-gated tests
// (the binary noise budget gates) use it to skip: the detector's 10-20x
// scan overhead pushes the bounded regex windows past their timeouts,
// which says nothing about production behavior.
const raceEnabled = false
