package jwtsecrets

import (
	"strconv"
	"time"

	"github.com/google/uuid"
)

// clock is an interface for obtaining the current time.
type clock interface {
	now() time.Time
}

// realClock is a clock which returns the actual current time.
type realClock struct{}

func (r realClock) now() time.Time {
	return time.Now()
}

// fakeClock is a clock which can be used for testing.
type fakeClock struct {
	Instant time.Time
}

func (f fakeClock) now() time.Time {
	return f.Instant
}

// uuidGenerator is an interface for generating UUIDs.
type uuidGenerator interface {
	uuid() (string, error)
}

// realUUIDGenerator generates actual UUIDs.
type realUUIDGenerator struct{}

func (r realUUIDGenerator) uuid() (string, error) {
	generatedUUID, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	return generatedUUID.String(), nil
}

// fakeUUIDGenerator generates a predictable sequence of UUIDs for testing.
type fakeUUIDGenerator struct {
	Counter int
}

func (f *fakeUUIDGenerator) uuid() (string, error) {
	f.Counter++
	return strconv.Itoa(f.Counter), nil
}
