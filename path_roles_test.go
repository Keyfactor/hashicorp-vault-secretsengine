/*
 *  Copyright 2026 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package kfbackend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// create
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/web",
		Storage:   storage,
		Data: map[string]interface{}{
			"allowed_domains":  "example.com",
			"allow_subdomains": true,
		},
	})
	if err != nil {
		t.Fatalf("role create err: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("role create error response: %v", resp.Error())
	}

	// read
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read err: %v", err)
	}
	if resp == nil {
		t.Fatal("expected role read response, got nil")
	}
	ad, ok := resp.Data["allowed_domains"].([]string)
	if !ok || len(ad) != 1 || ad[0] != "example.com" {
		t.Errorf("allowed_domains = %v", resp.Data["allowed_domains"])
	}
	if resp.Data["allow_subdomains"] != true {
		t.Errorf("allow_subdomains = %v, want true", resp.Data["allow_subdomains"])
	}

	// list
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "roles/", Storage: storage,
	})
	if err != nil {
		t.Fatalf("role list err: %v", err)
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok || len(keys) != 1 || keys[0] != "web" {
		t.Errorf("list keys = %v", resp.Data["keys"])
	}

	// delete
	if _, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "roles/web", Storage: storage,
	}); err != nil {
		t.Fatalf("role delete err: %v", err)
	}
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	if err != nil {
		t.Fatalf("role read-after-delete err: %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil response after delete, got %v", resp.Data)
	}
}

func TestRole_Validation(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	cases := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "weak RSA key",
			data: map[string]interface{}{"key_type": "rsa", "key_bits": 1024},
		},
		{
			name: "ttl greater than max_ttl",
			data: map[string]interface{}{"ttl": 3600, "max_ttl": 60},
		},
		{
			name: "invalid ext_key_usage_oid",
			data: map[string]interface{}{"ext_key_usage_oids": "not-an-oid"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/badrole",
				Storage:   storage,
				Data:      tc.data,
			})
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatalf("expected an error response, got %v", resp)
			}
		})
	}
}
