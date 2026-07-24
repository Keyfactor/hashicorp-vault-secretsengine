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
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestFetchCert_Fields(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	serial := "AABBCCDD"
	notAfter := time.Now().Add(48 * time.Hour)

	if err := storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + serial,
		Value: makeTestCertPEM(t, "host.example.com", notAfter),
	}); err != nil {
		t.Fatal(err)
	}
	metaEntry, err := logical.StorageEntryJSON("metadata/"+serial, map[string]interface{}{"environment": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, metaEntry); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "certs/" + serial,
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("cert read err: %v", err)
	}
	if resp == nil {
		t.Fatal("expected cert read response, got nil")
	}

	if got := resp.Data["serial_number"]; got != serial {
		t.Errorf("serial_number = %v, want %s", got, serial)
	}
	if got := resp.Data["common_name"]; got != "host.example.com" {
		t.Errorf("common_name = %v, want host.example.com", got)
	}
	if _, ok := resp.Data["certificate"]; !ok {
		t.Error("response missing certificate content")
	}
	if exp, ok := resp.Data["expiration"].(string); !ok || exp == "" {
		t.Errorf("expiration = %v, want non-empty RFC3339 string", resp.Data["expiration"])
	}
	md, ok := resp.Data["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata = %v, want map", resp.Data["metadata"])
	}
	if md["environment"] != "prod" {
		t.Errorf("metadata[environment] = %v, want prod", md["environment"])
	}
}

func TestFetchCert_MissingMetadataIsEmpty(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	serial := "AB12CD34"
	if err := storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + serial,
		Value: makeTestCertPEM(t, "no-meta.example.com", time.Now().Add(24*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "certs/" + serial,
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("cert read err: %v", err)
	}
	if _, ok := resp.Data["metadata"]; ok {
		t.Errorf("expected metadata to be omitted when none is stored, got %v", resp.Data["metadata"])
	}
}

// TestDecodeStoredKeyfactorID is a regression guard for the revoke bug where a
// Keyfactor certificate ID whose JSON representation begins with Vault's LZ4
// compression canary ('4') failed to decode with "lz4: bad magic number". The
// IDs below include several '4'-prefixed values; if the decode ever reverts to
// the compression-aware logical.StorageEntry.DecodeJSON, those cases will fail.
func TestDecodeStoredKeyfactorID(t *testing.T) {
	ids := []int32{4, 42, 456789, 1, 123, 2147483647}
	for _, id := range ids {
		entry, err := logical.StorageEntryJSON("kfId/TEST", id)
		if err != nil {
			t.Fatalf("id %d: StorageEntryJSON err: %v", id, err)
		}
		got, err := decodeStoredKeyfactorID(entry)
		if err != nil {
			t.Errorf("id %d: decode err: %v", id, err)
			continue
		}
		if got != id {
			t.Errorf("id %d: round-trip decoded to %d", id, got)
		}
	}

	if _, err := decodeStoredKeyfactorID(nil); err == nil {
		t.Error("expected an error decoding a nil entry")
	}
}

func TestFetchCertList_IncludesCommonName(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	if err := storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/AA11",
		Value: makeTestCertPEM(t, "host1.example.com", time.Now().Add(24*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("cert list err: %v", err)
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok || len(keys) != 1 || keys[0] != "AA11" {
		t.Fatalf("list keys = %v", resp.Data["keys"])
	}
	keyInfo, ok := resp.Data["key_info"].(map[string]interface{})
	if !ok {
		t.Fatalf("key_info missing or wrong type: %v", resp.Data["key_info"])
	}
	info, ok := keyInfo["AA11"].(map[string]interface{})
	if !ok {
		t.Fatalf("key_info[AA11] wrong type: %v", keyInfo["AA11"])
	}
	if info["common_name"] != "host1.example.com" {
		t.Errorf("key_info common_name = %v, want host1.example.com", info["common_name"])
	}
}
