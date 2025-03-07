/*
 *  Copyright 2024 Keyfactor
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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	operationPrefixKeyfactor string = "keyfactor"
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
	client       *keyfactorClient
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
		),
		Secrets:        []*framework.Secret{},
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
		InitializeFunc: b.Initialize,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *keyfactorBackend) reset() {
	b.configLock.RLock()
	defer b.configLock.RUnlock()
	b.cachedConfig = nil
	b.client = nil

}

func (b *keyfactorBackend) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	b.configLock.RLock()
	defer b.configLock.RUnlock()
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
func (b *keyfactorBackend) getClient(ctx context.Context, s logical.Storage) (*keyfactorClient, error) {
	b.configLock.RLock()
	defer b.configLock.RUnlock()

	if b.client != nil {
		b.Logger().Debug("closing idle connections before returning existing client")
		b.client.httpClient.CloseIdleConnections()
		return b.client, nil
	}

	// get configuration
	config, err := b.fetchConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("configuration is empty")
	}

	b.client, err = newClient(config, b)
	if err != nil {
		return nil, err
	}
	return b.client, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
