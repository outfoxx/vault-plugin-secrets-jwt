package jwtsecrets

import (
	"context"
	"encoding/json"
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
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("No raw body returned.")
	}

	jwkSet := jose.JSONWebKeySet{}
	err = json.Unmarshal(rawBody, &jwkSet)
	if err != nil {
		t.Fatalf("Cannot unmarshal body to JSONWebKeySet")
	}

	if len(jwkSet.Keys) != 0 {
		t.Errorf("Expected %v to be a set with no keys.", jwkSet)
	}
}

func TestJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	err := writeRole(b, storage, "tester", "tester.example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%s\n", err)
	}

	// Cause it to generate a key
	data := map[string]interface{}{
		"claims": map[string]interface{}{
			"aud": "Zapp Brannigan",
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/tester",
		Storage:   *storage,
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "jwks",
		Storage:   *storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatalf("No raw body returned.")
	}

	jwkSet := jose.JSONWebKeySet{}
	err = json.Unmarshal(rawBody, &jwkSet)
	if err != nil {
		t.Fatalf("Cannot unmarshal body to JSONWebKeySet")
	}

	expectedKeySet := b.getPublicKeys(context.Background(), req.Storage)
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

	if diff := deep.Equal(expectedKeySet, &jwkSet); diff != nil {
		t.Error(diff)
	}
}
