package jwtsecrets

import (
	"crypto"
	"encoding/base64"
	"path"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/mariuszs/friendlyid-go/friendlyid"
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

// uniqueIdGenerator is an interface for generating unique ids.
type uniqueIdGenerator interface {
	id() (string, error)
}

// friendlyIdGenerator generates friendly-id formatted UUIDs.
type friendlyIdGenerator struct{}

func (fid friendlyIdGenerator) id() (string, error) {
	generatedUUID, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}

	generatedFriendlyId, err := friendlyid.Encode(generatedUUID.String())
	if err != nil {
		return "", err
	}

	return generatedFriendlyId, nil
}

// fakeIDGenerator generates a predictable sequence of numeric ids for testing.
type fakeIDGenerator struct {
	Counter int
}

func (f *fakeIDGenerator) id() (string, error) {
	f.Counter++
	return strconv.Itoa(f.Counter), nil
}

func intMax(x int, y int) int {
	if x > y {
		return x
	}
	return y
}

func durationMin(x time.Duration, y time.Duration) time.Duration {
	if x < y {
		return x
	}
	return y
}

func createKeyId(backendId string, policyName string, version int) string {

	rawId := path.Join(backendId, policyName, strconv.Itoa(version))

	hasher := crypto.SHA1.New()
	hasher.Write([]byte(rawId))

	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}
