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
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Keyfactor/keyfactor-go-client-sdk/v24"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixKeyfactor string = "keyfactor"
	PluginVersion                   = "1.5.0" // this should match the release version of the plugin
)

// Factory configures and returns backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// // Store certificates by serial number
type keyfactorBackend struct {
	*framework.Backend
	configLock   sync.RWMutex
	cachedConfig *keyfactorConfig
	client       *keyfactor.APIClient

	// tidy state guards the expired-certificate cleanup sweep.
	tidyLock    sync.Mutex
	tidyRunning bool
	lastTidy    time.Time
	tidyResult  *tidyStatus
}

// keyfactorBackend defines the target API keyfactorBackend
// for Vault. It must include each path
// and the secrets it will store.
func backend() *keyfactorBackend {
	var b = keyfactorBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(keyfactorHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathConfig(&b),
			pathRoles(&b),
			pathCA(&b),
			pathCerts(&b),
			pathTidy(&b),
		),
		Secrets:        []*framework.Secret{},
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
		InitializeFunc: b.Initialize,
		PeriodicFunc:   b.periodicFunc,
		RunningVersion: "v" + PluginVersion,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *keyfactorBackend) reset() {
	// This mutates shared state, so it requires the write lock.
	b.configLock.Lock()
	defer b.configLock.Unlock()
	b.cachedConfig = nil
	b.client = nil
}

func (b *keyfactorBackend) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	if req == nil {
		return fmt.Errorf("initialization request is nil")
	}
	return nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *keyfactorBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *keyfactorBackend) getClient(ctx context.Context, s logical.Storage) (*keyfactor.APIClient, error) {
	// Fast path: return the cached client under a read lock.
	b.configLock.RLock()
	client := b.client
	b.configLock.RUnlock()
	if client != nil {
		b.Logger().Trace("returning existing client")
		return client, nil
	}

	// get configuration (fetchConfig manages its own locking, so we must not
	// hold configLock while calling it to avoid a recursive-lock deadlock)
	config, err := b.fetchConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("configuration is empty")
	}

	// Slow path: build the client under the write lock, re-checking in case
	// another goroutine created it while we were unlocked.
	b.configLock.Lock()
	defer b.configLock.Unlock()
	if b.client != nil {
		return b.client, nil
	}

	newC, err := newClient(config, b)
	if err != nil {
		return nil, err
	}
	b.client = newC
	return b.client, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates via the Keyfactor Command platform.
`
