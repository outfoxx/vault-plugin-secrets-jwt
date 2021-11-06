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

const testIssuer = "vault-plugin-secrets-jwt:test"

func getTestBackend(t *testing.T) (*backend, *logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := makeBackend(uuid.New().String())
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.clock = &fakeClock{time.Unix(0, 0)}
	b.idGen = &fakeIDGenerator{0}

	return b, &config.StorageView
}
