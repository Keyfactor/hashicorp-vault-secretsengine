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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
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

// Handle interface with Keyfactor API to enroll a certificate with given content
func (b *keyfactorBackend) submitCSR(ctx context.Context, req *logical.Request, csr string, caName string, templateName string) ([]string, string, error) {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, "", err
	}
	if config == nil {
		return nil, "", errors.New("configuration is empty")
	}

	location, _ := time.LoadLocation("UTC")
	t := time.Now().In(location)
	time := t.Format("2006-01-02T15:04:05")

	// get client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, "", fmt.Errorf("error getting client: %w", err)
	}

	b.Logger().Debug("Closing idle connections")
	client.httpClient.CloseIdleConnections()

	// build request parameter structure

	url := config.KeyfactorUrl + "/" + config.CommandAPIPath + "/Enrollment/CSR"
	b.Logger().Debug("url: " + url)
	bodyContent := "{\"CSR\": \"" + csr + "\",\"CertificateAuthority\":\"" + caName + "\",\"IncludeChain\": true, \"Metadata\": {}, \"Timestamp\": \"" + time + "\",\"Template\": \"" + templateName + "\",\"SANs\": {}}"
	payload := strings.NewReader(bodyContent)
	b.Logger().Debug("body: " + bodyContent)
	httpReq, err := http.NewRequest("POST", url, payload)

	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}

	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("x-certificateformat", "PEM")

	// Send request and check status

	b.Logger().Debug("About to connect to " + config.KeyfactorUrl + "for csr submission")
	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("CSR Enrollment failed: {{err}}", err.Error())
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("CSR Enrollment failed: server returned" + fmt.Sprint(res.StatusCode))
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		b.Logger().Error("Error response: " + string(body[:]))
		return nil, "", fmt.Errorf("CSR Enrollment request failed with status code %d and error: "+string(body[:]), res.StatusCode)
	}

	// Read response and return certificate and key

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.Logger().Error("Error reading response: {{err}}", err)
		return nil, "", err
	}

	// Parse response
	var r map[string]interface{}
	json.Unmarshal(body, &r)
	b.Logger().Debug("response = ", r)

	inner := r["CertificateInformation"].(map[string]interface{})
	certI := inner["Certificates"].([]interface{})
	certs := make([]string, len(certI))
	for i, v := range certI {
		certs[i] = v.(string)
		start := strings.Index(certs[i], "-----BEGIN CERTIFICATE-----")
		certs[i] = certs[i][start:]
	}
	serial := inner["SerialNumber"].(string)
	kfId := inner["KeyfactorID"].(float64)

	b.Logger().Debug("parsed response: ", certI...)

	if err != nil {
		b.Logger().Error("unable to parse ca_chain response", fmt.Sprint(err))
	}
	caEntry, err := logical.StorageEntryJSON("ca_chain/", certs[1:])
	if err != nil {
		b.Logger().Error("error creating ca_chain entry", err)
	}

	err = req.Storage.Put(ctx, caEntry)
	if err != nil {
		b.Logger().Error("error storing the ca_chain locally", err)
	}

	key := "certs/" + normalizeSerial(serial)

	entry := &logical.StorageEntry{
		Key:   key,
		Value: []byte(certs[0]),
	}

	b.Logger().Debug("cert entry.Value = ", string(entry.Value))

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, "", errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
	}

	kfIdEntry, err := logical.StorageEntryJSON("kfId/"+normalizeSerial(serial), kfId)
	if err != nil {
		return nil, "", err
	}

	err = req.Storage.Put(ctx, kfIdEntry)
	if err != nil {
		return nil, "", errwrap.Wrapf("unable to store the keyfactor ID for the certificate locally: {{err}}", err)
	}

	return certs, serial, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
