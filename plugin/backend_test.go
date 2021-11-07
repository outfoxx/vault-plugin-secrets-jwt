package jwtsecrets

import (
	"context"
	"github.com/google/uuid"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
)

func getTestBackend(t *testing.T) (*backend, *logical.Storage) {
	sys := &logical.StaticSystemView{}
	sys.DefaultLeaseTTLVal, _ = time.ParseDuration("5m0s")
	sys.MaxLeaseTTLVal, _ = time.ParseDuration("30m0s")

	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      sys,
		StorageView: &logical.InmemStorage{},
		BackendUUID: uuid.New().String(),
	}

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
