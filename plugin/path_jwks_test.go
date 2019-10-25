package jwtsecrets

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
)

func TestEmptyJwks(t *testing.T) {
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

	typedKeys, ok := resp.Data["keys"].([]jose.JSONWebKey)
	if !ok {
		t.Fatalf("Expected keys to be of type %T. Instead got %T", jose.JSONWebKey{}, resp.Data["keys"])
	}

	if len(typedKeys) != 0 {
		t.Errorf("Expected %v to be an array of length 0.", typedKeys)
	}
}

func TestJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	// Cause it to generate a key
	data := map[string]interface{}{
		"claims": map[string]interface{}{
			"bar": "baz",
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign",
		Storage:   storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rawKeys, ok := resp.Data["keys"]
	if !ok {
		t.Fatalf("No returned keys.")
	}

	typedKeys, ok := rawKeys.([]jose.JSONWebKey)
	if !ok {
		t.Fatalf("JWKS was not a %T", []jose.JSONWebKey{})
	}

	expectedKeys := b.GetPublicKeys().Keys

	if len(expectedKeys) == 0 {
		t.Fatal("Expected at least one key to be present.")
	}

	if diff := deep.Equal(expectedKeys, typedKeys); diff != nil {
		t.Error(diff)
	}
}
