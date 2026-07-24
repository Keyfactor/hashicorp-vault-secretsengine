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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// defaultTidyInterval is used when automatic tidy is enabled but no
	// interval has been configured.
	defaultTidyInterval = 24 * time.Hour
	// defaultTidySafetyBuffer is how long an expired certificate is retained
	// before the sweep removes it, when none is configured.
	defaultTidySafetyBuffer = 72 * time.Hour
)

// tidyStatus captures the outcome of the most recent tidy sweep so it can be
// surfaced through the tidy/status read endpoint.
type tidyStatus struct {
	state     string // "running", "finished", or "error"
	started   time.Time
	finished  time.Time
	examined  int
	deleted   int
	skipped   int
	errString string
}

func pathTidy(b *keyfactorBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "tidy",
			Fields: map[string]*framework.FieldSchema{
				"safety_buffer": {
					Type:        framework.TypeDurationSecond,
					Description: "The amount of time an expired certificate is retained before it is removed. Defaults to 72h.",
					Default:     259200,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathTidyWrite,
			},
			HelpSynopsis:    pathTidyHelpSyn,
			HelpDescription: pathTidyHelpDesc,
		},
		{
			Pattern: "tidy/status",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathTidyStatusRead,
			},
			HelpSynopsis:    pathTidyStatusHelpSyn,
			HelpDescription: pathTidyStatusHelpDesc,
		},
	}
}

// pathTidyWrite triggers a one-off tidy sweep on demand.
func (b *keyfactorBackend) pathTidyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	safetyBuffer := time.Duration(data.Get("safety_buffer").(int)) * time.Second
	if safetyBuffer < 0 {
		return logical.ErrorResponse("safety_buffer must not be negative"), nil
	}
	return b.startTidy(req.Storage, safetyBuffer), nil
}

// pathTidyStatusRead returns the outcome of the most recent tidy sweep.
func (b *keyfactorBackend) pathTidyStatusRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.tidyLock.Lock()
	defer b.tidyLock.Unlock()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"running": b.tidyRunning,
		},
	}
	if !b.lastTidy.IsZero() {
		resp.Data["last_run"] = b.lastTidy.UTC().Format(time.RFC3339)
	}
	if b.tidyResult != nil {
		s := b.tidyResult
		resp.Data["state"] = s.state
		resp.Data["certs_examined"] = s.examined
		resp.Data["certs_deleted"] = s.deleted
		resp.Data["certs_skipped"] = s.skipped
		if !s.started.IsZero() {
			resp.Data["time_started"] = s.started.UTC().Format(time.RFC3339)
		}
		if !s.finished.IsZero() {
			resp.Data["time_finished"] = s.finished.UTC().Format(time.RFC3339)
		}
		if s.errString != "" {
			resp.Data["error"] = s.errString
		}
	}
	return resp, nil
}

// startTidy launches the sweep in the background unless one is already running.
// It returns a response with a warning describing what happened; the sweep
// itself runs asynchronously so it never blocks the request or the periodic
// loop.
func (b *keyfactorBackend) startTidy(storage logical.Storage, safetyBuffer time.Duration) *logical.Response {
	resp := &logical.Response{}

	b.tidyLock.Lock()
	if b.tidyRunning {
		b.tidyLock.Unlock()
		resp.AddWarning("Tidy operation already in progress; ignoring this request.")
		return resp
	}
	b.tidyRunning = true
	b.tidyResult = &tidyStatus{
		state:   "running",
		started: time.Now(),
	}
	b.tidyLock.Unlock()

	go b.doTidy(storage, safetyBuffer)

	resp.AddWarning("Tidy operation successfully started. Progress is reported in Vault's server logs and via the tidy/status endpoint.")
	return resp
}

// doTidy walks the locally-stored certificates and removes any that have
// expired (past their NotAfter plus the safety buffer), along with their
// associated Keyfactor ID and revocation entries. Certificates that cannot be
// parsed are skipped, never deleted, to avoid removing data we don't fully
// understand.
func (b *keyfactorBackend) doTidy(storage logical.Storage, safetyBuffer time.Duration) {
	// The request context ends when the triggering request returns, so use a
	// fresh background context for the async work.
	ctx := context.Background()

	var examined, deleted, skipped int
	var tidyErr error

	defer func() {
		b.tidyLock.Lock()
		b.tidyRunning = false
		b.lastTidy = time.Now()
		if b.tidyResult != nil {
			b.tidyResult.finished = b.lastTidy
			b.tidyResult.examined = examined
			b.tidyResult.deleted = deleted
			b.tidyResult.skipped = skipped
			if tidyErr != nil {
				b.tidyResult.state = "error"
				b.tidyResult.errString = tidyErr.Error()
			} else {
				b.tidyResult.state = "finished"
			}
		}
		b.tidyLock.Unlock()
	}()

	serials, err := storage.List(ctx, "certs/")
	if err != nil {
		tidyErr = err
		b.Logger().Error("tidy: failed to list stored certificates", "error", err)
		return
	}

	now := time.Now()
	b.Logger().Info(fmt.Sprintf("tidy: examining %d stored certificate(s)", len(serials)))

	for _, serial := range serials {
		// Skip directory-style keys, if any ever appear in this prefix.
		if serial == "" || serial[len(serial)-1] == '/' {
			continue
		}
		examined++

		entry, err := storage.Get(ctx, "certs/"+serial)
		if err != nil {
			b.Logger().Error("tidy: error reading certificate", "serial", serial, "error", err)
			skipped++
			continue
		}
		if entry == nil || len(entry.Value) == 0 {
			skipped++
			continue
		}

		block, _ := pem.Decode(entry.Value)
		if block == nil {
			b.Logger().Warn("tidy: stored value is not PEM; skipping", "serial", serial)
			skipped++
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			b.Logger().Warn("tidy: unable to parse stored certificate; skipping", "serial", serial, "error", err)
			skipped++
			continue
		}

		if now.After(cert.NotAfter.Add(safetyBuffer)) {
			if err := b.deleteCertEntries(ctx, storage, serial); err != nil {
				b.Logger().Error("tidy: failed to delete expired certificate", "serial", serial, "error", err)
				skipped++
				continue
			}
			deleted++
		}
	}

	b.Logger().Info(fmt.Sprintf("tidy: complete. examined=%d deleted=%d skipped=%d", examined, deleted, skipped))
}

// deleteCertEntries removes a certificate and all of its associated storage
// entries.
func (b *keyfactorBackend) deleteCertEntries(ctx context.Context, storage logical.Storage, serial string) error {
	for _, key := range []string{"certs/" + serial, "kfId/" + serial, "revoked/" + serial, "metadata/" + serial} {
		if err := storage.Delete(ctx, key); err != nil {
			return fmt.Errorf("error deleting %s: %w", key, err)
		}
	}
	return nil
}

// periodicFunc is invoked by Vault (roughly once a minute, on the active node
// only) and runs the tidy sweep when it is enabled and the configured interval
// has elapsed.
func (b *keyfactorBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("tidy: unable to load configuration for periodic sweep", "error", err)
		return nil
	}
	if config == nil || !config.TidyEnabled {
		return nil
	}

	interval := time.Duration(config.TidyInterval) * time.Second
	if interval <= 0 {
		interval = defaultTidyInterval
	}

	b.tidyLock.Lock()
	due := !b.tidyRunning && (b.lastTidy.IsZero() || time.Since(b.lastTidy) >= interval)
	b.tidyLock.Unlock()
	if !due {
		return nil
	}

	safetyBuffer := time.Duration(config.TidySafetyBuffer) * time.Second
	if safetyBuffer <= 0 {
		safetyBuffer = defaultTidySafetyBuffer
	}

	b.Logger().Info("tidy: starting scheduled sweep")
	b.startTidy(req.Storage, safetyBuffer)
	return nil
}

const pathTidyHelpSyn = `Tidy up the locally-stored certificate store by removing expired certificates.`

const pathTidyHelpDesc = `
This endpoint removes certificates that have expired from the plugin's local
storage, reclaiming space. A certificate is removed once its expiration date
(NotAfter) plus the safety_buffer has passed. The associated Keyfactor ID and
revocation records are removed along with it.

The sweep runs in the background; use the tidy/status endpoint to view its
progress and results. Automatic, scheduled tidying can be enabled via the
tidy_enabled, tidy_interval, and tidy_safety_buffer settings on the config
endpoint.
`

const pathTidyStatusHelpSyn = `Return the status of the most recent tidy operation.`

const pathTidyStatusHelpDesc = `
This endpoint returns information about the most recent tidy sweep, including
whether one is currently running, when it last ran, and how many certificates
were examined, deleted, and skipped.
`
