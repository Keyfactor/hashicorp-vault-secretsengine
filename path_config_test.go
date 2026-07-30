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

func writeConfig(t *testing.T, b *keyfactorBackend, storage logical.Storage, data map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("config write returned error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("config write returned error response: %v", resp.Error())
	}
}

func readConfig(t *testing.T, b *keyfactorBackend, storage logical.Storage, showHidden bool) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
		Data:      map[string]interface{}{"show_hidden": showHidden},
	})
	if err != nil {
		t.Fatalf("config read returned error: %v", err)
	}
	return resp
}

func TestConfig_WriteReadDelete(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	writeConfig(t, b, storage, map[string]interface{}{
		"url":      "https://command.example.com",
		"username": "svc",
		"password": "secret",
		"domain":   "EXAMPLE",
	})

	resp := readConfig(t, b, storage, false)
	if resp == nil {
		t.Fatal("expected config read response, got nil")
	}
	if got := resp.Data["url"]; got != "https://command.example.com" {
		t.Errorf("url = %v", got)
	}
	if got := resp.Data["username"]; got != "svc" {
		t.Errorf("username = %v", got)
	}
	if got := resp.Data["password"]; got != "(hidden)" {
		t.Errorf("password should be masked, got %v", got)
	}
	if got := resp.Data["api_path"]; got != "KeyfactorAPI" {
		t.Errorf("api_path default = %v, want KeyfactorAPI", got)
	}

	// show_hidden reveals the secret
	resp = readConfig(t, b, storage, true)
	if got := resp.Data["password"]; got != "secret" {
		t.Errorf("password with show_hidden = %v, want secret", got)
	}

	// delete then confirm gone
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "config", Storage: storage,
	}); err != nil {
		t.Fatalf("config delete err: %v", err)
	}
	resp = readConfig(t, b, storage, false)
	if resp != nil {
		t.Errorf("expected nil response after delete, got %v", resp.Data)
	}
}

// TestConfig_MergePreservesExisting exercises the update-merge logic: writing a
// single new field must not clear previously-set fields.
func TestConfig_MergePreservesExisting(t *testing.T) {
	b, storage := getTestBackend(t)

	writeConfig(t, b, storage, map[string]interface{}{
		"url":      "https://command.example.com",
		"username": "svc",
	})
	writeConfig(t, b, storage, map[string]interface{}{
		"password": "pw",
	})

	resp := readConfig(t, b, storage, true)
	if got := resp.Data["username"]; got != "svc" {
		t.Errorf("username lost after partial update: %v", got)
	}
	if got := resp.Data["url"]; got != "https://command.example.com" {
		t.Errorf("url lost after partial update: %v", got)
	}
	if got := resp.Data["password"]; got != "pw" {
		t.Errorf("password = %v, want pw", got)
	}
}

// TestFetchConfig_APIPathDefault verifies fetchConfig applies the KeyfactorAPI
// default when a stored config has an empty api_path.
func TestFetchConfig_APIPathDefault(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	entry, err := logical.StorageEntryJSON(configPath, &keyfactorConfig{KeyfactorUrl: "https://c.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	cfg, err := b.fetchConfig(ctx, storage)
	if err != nil {
		t.Fatalf("fetchConfig err: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if cfg.CommandAPIPath != "KeyfactorAPI" {
		t.Errorf("CommandAPIPath = %q, want KeyfactorAPI", cfg.CommandAPIPath)
	}
}
