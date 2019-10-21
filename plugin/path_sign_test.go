package jwtsecrets

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestSign(t *testing.T) {
	b, storage := getTestBackend(t)

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

	rawToken, ok := resp.Data["token"]
	if !ok {
		t.Fatalf("No returned token.")
	}

	strToken, ok := rawToken.(string)
	if !ok {
		t.Fatalf("Token was not a string")
	}

	token, err := jwt.ParseSigned(strToken)
	if err != nil {
		t.Fatalf("error parsing jwt: %s", err)
	}

	claims := make(map[string]interface{})
	if err = token.Claims(b.keys[0].Key.Public(), &claims); err != nil {
		t.Fatalf("error decoding claims: %s", err)
	}

	if diff := deep.Equal(data["claims"], claims); diff != nil {
		t.Error(diff)
	}
}
