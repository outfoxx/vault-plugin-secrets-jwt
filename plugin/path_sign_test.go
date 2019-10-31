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
			"aud": "Zapp Brannigan",
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
		t.Fatalf("No returned token.\n")
	}

	strToken, ok := rawToken.(string)
	if !ok {
		t.Fatalf("Token was %T, not a string\n", rawToken)
	}

	token, err := jwt.ParseSigned(strToken)
	if err != nil {
		t.Fatalf("error parsing jwt: %s\n", err)
	}

	var claims jwt.Claims
	if err = token.Claims(b.keys[0].Key.Public(), &claims); err != nil {
		t.Fatalf("error decoding claims: %s\n", err)
	}

	expectedExpiry := jwt.NumericDate(5 * 60)
	expectedIssuedAt := jwt.NumericDate(0)
	expectedClaims := jwt.Claims{
		Audience: []string{"Zapp Brannigan"},
		Expiry:   &expectedExpiry,
		IssuedAt: &expectedIssuedAt,
		ID:       "1",
		Issuer:   testIssuer,
	}

	if diff := deep.Equal(expectedClaims, claims); diff != nil {
		t.Error(diff)
	}
}

func TestRejectReservedClaims(t *testing.T) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"claims": map[string]interface{}{
			"exp": 1234,
		},
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil && (resp != nil && !resp.IsError()) {
		t.Fatalf("expected to get an error from sign. got:%v\n", resp)
	}
}
