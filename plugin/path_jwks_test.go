package jwtsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
)

func FetchJWKS(b *backend, storage *logical.Storage) (*jose.JSONWebKeySet, error) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, resp.Error()
	}

	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		return nil, errors.New("no raw body returned")
	}

	jwkSet := jose.JSONWebKeySet{}
	err = json.Unmarshal(rawBody, &jwkSet)
	if err != nil {
		return nil, errors.New("cannot unmarshal body to JSONWebKeySet")
	}

	return &jwkSet, nil
}

func TestJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	err := writeRole(b, storage, "tester", "tester.example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%s\n", err)
	}

	jwkSet, err := FetchJWKS(b, storage)
	if err != nil {
		t.Fatalf("err:%s\n", err)
	}

	expectedKeySet, err := b.getPublicKeys(context.Background(), *storage)
	if err != nil {
		t.Fatalf("err: %#v", err)
	}

	for i, ek := range expectedKeySet.Keys {
		data, _ := json.Marshal(ek)
		var nek jose.JSONWebKey
		if json.Unmarshal(data, &nek) != nil {
			t.Fatalf("Unable to transcode key")
		}
		expectedKeySet.Keys[i] = nek
	}

	if len(expectedKeySet.Keys) == 0 {
		t.Fatal("Expected at least one key to be present.")
	}

	if diff := deep.Equal(expectedKeySet, jwkSet); diff != nil {
		t.Error(diff)
	}
}
