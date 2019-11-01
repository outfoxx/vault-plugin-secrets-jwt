package jwtsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2/jwt"
)

func getSignedToken(b *backend, storage *logical.Storage, claims map[string]interface{}, dest interface{}) error {
	data := map[string]interface{}{
		"claims": claims,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign",
		Storage:   *storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		return fmt.Errorf("err:%s resp:%#v", err, resp)
	}

	rawToken, ok := resp.Data["token"]
	if !ok {
		return fmt.Errorf("no returned token")
	}

	strToken, ok := rawToken.(string)
	if !ok {
		return fmt.Errorf("Token was %T, not a string", rawToken)
	}

	token, err := jwt.ParseSigned(strToken)
	if err != nil {
		return fmt.Errorf("error parsing jwt: %s", err)
	}

	if err = token.Claims(b.keys[0].Key.Public(), dest); err != nil {
		return fmt.Errorf("error decoding claims: %s", err)
	}

	return nil
}

func TestSign(t *testing.T) {
	b, storage := getTestBackend(t)

	claims := map[string]interface{}{
		"aud": []string{"Zapp Brannigan", "Kif Kroker"},
	}

	var decoded jwt.Claims
	if err := getSignedToken(b, storage, claims, &decoded); err != nil {
		t.Fatalf("%v\n", err)
	}

	expectedExpiry := jwt.NumericDate(5 * 60)
	expectedIssuedAt := jwt.NumericDate(0)
	expectedNotBefore := jwt.NumericDate(0)
	expectedClaims := jwt.Claims{
		Audience:  []string{"Zapp Brannigan", "Kif Kroker"},
		Expiry:    &expectedExpiry,
		IssuedAt:  &expectedIssuedAt,
		NotBefore: &expectedNotBefore,
		ID:        "1",
		Issuer:    testIssuer,
	}

	if diff := deep.Equal(expectedClaims, decoded); diff != nil {
		t.Error(diff)
	}
}

type customToken struct {
	Foo string `json:"foo"`
}

func TestPrivateClaim(t *testing.T) {
	b, storage := getTestBackend(t)
	b.config.allowedClaimsMap["foo"] = true

	claims := map[string]interface{}{
		"foo": "bar",
	}

	var decoded customToken
	if err := getSignedToken(b, storage, claims, &decoded); err != nil {
		t.Fatalf("%v\n", err)
	}

	expectedClaims := customToken{
		Foo: "bar",
	}

	if diff := deep.Equal(expectedClaims, decoded); diff != nil {
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
		Storage:   *storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil || resp != nil && !resp.IsError() {
		t.Fatalf("expected to get an error from sign. got:%v\n", resp)
	}
}
