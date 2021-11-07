package jwtsecrets

import (
	"context"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
)

func getTestBackend(t *testing.T) (*backend, *logical.Storage) {

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.BackendUUID = uuid.New().String()

	b, err := createBackend(config.BackendUUID)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.clock = &fakeClock{time.Unix(0, 0)}
	b.idGen = &fakeIDGenerator{0}

	_ = b.clearConfig(context.Background(), config.StorageView)

	return b, &config.StorageView
}
