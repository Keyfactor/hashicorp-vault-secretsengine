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

func TestDoTidy(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	put := func(key string, val []byte) {
		t.Helper()
		if err := storage.Put(ctx, &logical.StorageEntry{Key: key, Value: val}); err != nil {
			t.Fatalf("seed put %s: %v", key, err)
		}
	}

	put("certs/EXPIRED", makeTestCertPEM(t, "expired", time.Now().Add(-48*time.Hour)))
	put("certs/VALID", makeTestCertPEM(t, "valid", time.Now().Add(72*time.Hour)))
	put("certs/GARBAGE", []byte("this is not a PEM certificate"))

	kfEntry, err := logical.StorageEntryJSON("kfId/EXPIRED", int32(42))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, kfEntry); err != nil {
		t.Fatal(err)
	}
	metaEntry, err := logical.StorageEntryJSON("metadata/EXPIRED", map[string]interface{}{"env": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, metaEntry); err != nil {
		t.Fatal(err)
	}

	// Prime the status object the same way startTidy would, then run the sweep
	// synchronously.
	b.tidyResult = &tidyStatus{state: "running", started: time.Now()}
	b.doTidy(storage, 0)

	assertGone := func(key string) {
		t.Helper()
		e, err := storage.Get(ctx, key)
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if e != nil {
			t.Errorf("expected %s to be deleted, but it remains", key)
		}
	}
	assertPresent := func(key string) {
		t.Helper()
		e, err := storage.Get(ctx, key)
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if e == nil {
			t.Errorf("expected %s to remain, but it was deleted", key)
		}
	}

	assertGone("certs/EXPIRED")
	assertGone("kfId/EXPIRED")
	assertGone("metadata/EXPIRED")
	assertPresent("certs/VALID")
	assertPresent("certs/GARBAGE") // unparseable entries are skipped, never deleted

	if b.tidyResult.deleted != 1 {
		t.Errorf("tidy deleted = %d, want 1", b.tidyResult.deleted)
	}
	if b.tidyRunning {
		t.Error("tidyRunning should be false after doTidy completes")
	}
}

func TestTidyStatus_BeforeAnyRun(t *testing.T) {
	b, storage := getTestBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "tidy/status",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("tidy/status read err: %v", err)
	}
	if resp == nil {
		t.Fatal("expected tidy/status response, got nil")
	}
	if resp.Data["running"] != false {
		t.Errorf("running = %v, want false", resp.Data["running"])
	}
	if _, ok := resp.Data["last_run"]; ok {
		t.Errorf("did not expect last_run before any sweep, got %v", resp.Data["last_run"])
	}
}
