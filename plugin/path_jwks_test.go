package jwtsecrets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rawKeys, ok := resp.Data["keys"]
	if !ok {
		t.Fatalf("No returned keys.")
	}

	typedKeys, ok := rawKeys.([]byte)
	if !ok {
		t.Fatalf("JWKS was not a []byte")
	}

	expectedKeys := b.GetPublicKeys().Keys

	expectedJSON, err := json.Marshal(expectedKeys)
	if err != nil {
		t.Fatalf("Could not serialize expected JWKS: %s", err)
	}

	if diff := deep.Equal(expectedJSON, typedKeys); diff != nil {
		t.Error(diff)
	}
}
