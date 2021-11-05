package jwtsecrets

import (
	"context"
	"fmt"
	"github.com/go-test/deep"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func writeRole(b *backend, storage *logical.Storage, name string, subject string, otherClaims map[string]interface{}) error {
	data := map[string]interface{}{
		"subject":      subject,
		"other_claims": otherClaims,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   *storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		return fmt.Errorf("err:%s resp:%#v", err, resp)
	}

	return nil
}

func readRole(b *backend, storage *logical.Storage, name string) (*logical.Response, error) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		return nil, fmt.Errorf("err:%s resp:%#v", err, resp)
	}

	return resp, nil
}

func TestCreate(t *testing.T) {
	b, storage := getTestBackend(t)

	role := "tester"

	err := writeRole(b, storage, role, role+".example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	resp, err := readRole(b, storage, role)

	subject := resp.Data[keySubject].(string)
	if diff := deep.Equal(role+".example.com", subject); diff != nil {
		t.Error("failed to update subject:", diff)
	}

}

func TestCreateRestrictedSubject(t *testing.T) {
	b, storage := getTestBackend(t)

	role := "tester"

	resp, err := writeConfig(b, storage, map[string]interface{}{
		keySubjectPattern: "[a-z]+\\.[a-z]+\\.[a-z]+",
	})
	if err != nil {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	err = writeRole(b, storage, role, "invalid role", map[string]interface{}{})
	if err == nil {
		t.Fatalf("create role with non-matching subject pattern succeeded")
	}

	err = writeRole(b, storage, role, role+".example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%s\n", err)
	}

	resp, err = readRole(b, storage, role)

	subject := resp.Data[keySubject].(string)
	if diff := deep.Equal(role+".example.com", subject); diff != nil {
		t.Error("failed to update subject:", diff)
	}

}

func TestCreateDisallowedOtherClaim(t *testing.T) {
	b, storage := getTestBackend(t)

	role := "tester"

	err := writeRole(b, storage, role, role+".example.com", map[string]interface{}{"sub": "not allowed"})
	if err == nil {
		t.Fatalf("Create role should have failed")
	}

	err = writeRole(b, storage, role, role+".example.com", map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Fatalf("Create role should have failed")
	}

	resp, err := writeConfig(b, storage, map[string]interface{}{"allowed_claims": []string{"foo"}})
	if err != nil {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	err = writeRole(b, storage, role, role+".example.com", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Errorf("%s\n", err)
	}

}

func TestList(t *testing.T) {
	b, storage := getTestBackend(t)

	err := writeRole(b, storage, "tester1", "tester.example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	err = writeRole(b, storage, "tester2", "tester.example.com", map[string]interface{}{})
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	keys := resp.Data["keys"].([]string)
	if keys == nil {
		t.Fatalf("Missing keys in list response")
	}

	if diff := deep.Equal(keys, []string{"tester1", "tester2"}); diff != nil {
		t.Error("failed to list roles:", diff)
	}
}

func TestDelete(t *testing.T) {
	b, storage := getTestBackend(t)

	role := "tester"

	if err := writeRole(b, storage, role, role+".example.com", map[string]interface{}{}); err != nil {
		t.Fatalf("%v\n", err)
	}

	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + role,
		Storage:   *storage,
	}

	if _, err := b.HandleRequest(context.Background(), req); err != nil {
		t.Fatalf("%v\n", err)
	}

	if resp, err := readRole(b, storage, role); err != nil || resp != nil {
		t.Errorf("Should have received empty response but got response: %#v", resp)
	}
}
