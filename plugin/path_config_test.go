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

func writeConfig(b *backend, storage *logical.Storage, config map[string]interface{}) (*logical.Response, error) {

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   *storage,
		Data:      config,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.IsError() {
		return nil, resp.Error()
	}
	return resp, nil
}

func TestDefaultConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod := resp.Data[keyRotationDuration].(string)
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

	resp, err := writeConfig(b, storage, map[string]interface{}{
		keyRotationDuration: updatedRotationPeriod,
	})
	if err != nil {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod := resp.Data[keyRotationDuration].(string)
	tokenTTL := resp.Data[keyTokenTTL].(string)
	setIAT := resp.Data[keySetIAT].(bool)
	setJTI := resp.Data[keySetJTI].(bool)
	setNBF := resp.Data[keySetNBF].(bool)
	issuer := resp.Data[keyIssuer].(string)

	if diff := deep.Equal(updatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(DefaultTokenTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	if diff := deep.Equal(DefaultSetIAT, setIAT); diff != nil {
		t.Error("set_iat should be unchanged:", diff)
	}

	if diff := deep.Equal(DefaultSetJTI, setJTI); diff != nil {
		t.Error("set_jti should be unchanged:", diff)
	}

	if diff := deep.Equal(DefaultSetNBF, setNBF); diff != nil {
		t.Error("set_nbf should be unchanged:", diff)
	}

	if diff := deep.Equal(testIssuer, issuer); diff != nil {
		t.Error("unexpected issuer:", diff)
	}

	resp, err = writeConfig(b, storage, map[string]interface{}{
		keyRotationDuration: secondUpdatedRotationPeriod,
		keyTokenTTL:         updatedTTL,
		keySetIAT:           false,
		keySetJTI:           false,
		keySetNBF:           false,
		keyIssuer:           newIssuer,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod = resp.Data[keyRotationDuration].(string)
	tokenTTL = resp.Data[keyTokenTTL].(string)
	setIAT = resp.Data[keySetIAT].(bool)
	setJTI = resp.Data[keySetJTI].(bool)
	setNBF = resp.Data[keySetNBF].(bool)
	issuer = resp.Data[keyIssuer].(string)

	if diff := deep.Equal(secondUpdatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(updatedTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	if diff := deep.Equal(false, setIAT); diff != nil {
		t.Error("expected set_iat to be false")
	}

	if diff := deep.Equal(false, setJTI); diff != nil {
		t.Error("expected set_jti to be false")
	}

	if diff := deep.Equal(false, setNBF); diff != nil {
		t.Error("expected set_nbf to be false")
	}

	if diff := deep.Equal(newIssuer, issuer); diff != nil {
		t.Error("unexpected issuer:", diff)
	}
}

func TestWriteInvalidConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	resp, err := writeConfig(b, storage, map[string]interface{}{
		keyRotationDuration: "not a real duration",
	})
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}

	resp, err = writeConfig(b, storage, map[string]interface{}{
		keyAudiencePattern: "(",
	})
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}

	resp, err = writeConfig(b, storage, map[string]interface{}{
		keyAllowedClaims: []string{"sub"},
	})
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}

	resp, err = writeConfig(b, storage, map[string]interface{}{
		keySignatureAlgorithm: "HS256",
	})
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}
}
