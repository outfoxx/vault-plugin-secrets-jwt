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

	if diff := deep.Equal(updatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(DefaultTokenTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			keyRotationDurationLabel: secondUpdatedRotationPeriod,
			keyTokenTTL:              updatedTTL,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rotationPeriod = resp.Data[keyRotationDurationLabel].(string)
	tokenTTL = resp.Data[keyTokenTTL].(string)

	if diff := deep.Equal(secondUpdatedRotationPeriod, rotationPeriod); diff != nil {
		t.Error("failed to update rotation period:", diff)
	}

	if diff := deep.Equal(updatedTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
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
