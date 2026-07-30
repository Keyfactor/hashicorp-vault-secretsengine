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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

// getTestBackend spins up an instance of the backend wired to in-memory
// storage, suitable for exercising paths that do not require a live Keyfactor
// Command connection.
func getTestBackend(t *testing.T) (*keyfactorBackend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	kb, ok := b.(*keyfactorBackend)
	if !ok {
		t.Fatalf("Factory returned unexpected type %T", b)
	}
	return kb, config.StorageView
}

// makeTestCertDER creates a self-signed certificate and returns its DER bytes.
func makeTestCertDER(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return der
}

// makeTestCertPEM creates a self-signed certificate and returns it PEM-encoded.
func makeTestCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: makeTestCertDER(t, cn, notAfter)})
}

func TestBackend_Factory(t *testing.T) {
	b, storage := getTestBackend(t)
	if b == nil {
		t.Fatal("nil backend")
	}
	if b.Backend == nil {
		t.Fatal("framework backend was not initialized")
	}
	if storage == nil {
		t.Fatal("nil storage")
	}
}
