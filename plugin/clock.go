package jwtsecrets

import (
	"time"
)

// clock is an interface for obtaining the current time.
type clock interface {
	now() time.Time
}

// realClock is a clock which returns the actual current time.
type realClock struct{}

// Now returns the current time.
func (r realClock) now() time.Time {
	return time.Now()
}

// fakeClock is a clock which can be used for testing.
type fakeClock struct {
	Instant time.Time
}

// Now returns the current time of the fake clock.
func (f fakeClock) now() time.Time {
	return f.Instant
}
