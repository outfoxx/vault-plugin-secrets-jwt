package jwtsecrets

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	updatedRotationPeriod       = "5m0s"
	secondUpdatedRotationPeriod = "1h0m0s"
	updatedTTL                  = "6m0s"
	newIssuer                   = "new-vault"
)

func TestDefaultConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod := resp.Data[keyRotationDurationLabel].(string)
	tokenTTL := resp.Data[keyTokenTTL].(string)

	if diff := deep.Equal(DefaultKeyRotationPeriod, rotationPeriod); diff != nil {
		t.Error(diff)
	}

	if diff := deep.Equal(DefaultTokenTTL, tokenTTL); diff != nil {
		t.Error(diff)
	}
}

func TestWriteConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			keyRotationDurationLabel: updatedRotationPeriod,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod := resp.Data[keyRotationDurationLabel].(string)
	tokenTTL := resp.Data[keyTokenTTL].(string)
	setIat := resp.Data[keySetIat].(bool)
	setJti := resp.Data[keySetJTI].(bool)
	issuer := resp.Data[keyIssuer].(string)

	if diff := deep.Equal(updatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(DefaultTokenTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	if diff := deep.Equal(DefaultSetIat, setIat); diff != nil {
		t.Error("set_iat should be unchanged:", diff)
	}

	if diff := deep.Equal(DefaultSetJTI, setJti); diff != nil {
		t.Error("set_jti should be unchanged:", diff)
	}

	if diff := deep.Equal(testIssuer, issuer); diff != nil {
		t.Error("unexpected issuer:", diff)
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			keyRotationDurationLabel: secondUpdatedRotationPeriod,
			keyTokenTTL:              updatedTTL,
			keySetIat:                false,
			keySetJTI:                false,
			keyIssuer:                newIssuer,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod = resp.Data[keyRotationDurationLabel].(string)
	tokenTTL = resp.Data[keyTokenTTL].(string)
	setIat = resp.Data[keySetIat].(bool)
	issuer = resp.Data[keyIssuer].(string)

	if diff := deep.Equal(secondUpdatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(updatedTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	if diff := deep.Equal(false, setIat); diff != nil {
		t.Error("expected set_iat to be false")
	}

	if diff := deep.Equal(newIssuer, issuer); diff != nil {
		t.Error("unexpected issuer:", diff)
	}
}

func TestWriteInvalidConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			keyRotationDurationLabel: "not a real duration",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}
}
