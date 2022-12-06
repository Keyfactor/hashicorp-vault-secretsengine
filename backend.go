package keyfactor

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//var config map[string]string

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
	lock         sync.RWMutex
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
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *keyfactorBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
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
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	return nil, fmt.Errorf("need to return client")
}

// Handle interface with Keyfactor API to enroll a certificate with given content
func (b *keyfactorBackend) submitCSR(ctx context.Context, req *logical.Request, csr string, caName string, templateName string) ([]string, string, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, "", err
	}
	if config == nil {
		return nil, "", errors.New("configuration is empty.")
	}

	ca := config.CertAuthority
	template := config.CertTemplate

	creds := config.Username + ":" + config.Password
	encCreds := b64.StdEncoding.EncodeToString([]byte(creds))

	location, _ := time.LoadLocation("UTC")
	t := time.Now().In(location)
	time := t.Format("2006-01-02T15:04:05")

	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	http.DefaultClient.CloseIdleConnections()

	// Build request
	url := config.KeyfactorUrl + "/KeyfactorAPI/Enrollment/CSR"
	b.Logger().Debug("url: " + url)
	bodyContent := "{\"CSR\": \"" + csr + "\",\"CertificateAuthority\":\"" + ca + "\",\"IncludeChain\": true, \"Metadata\": {}, \"Timestamp\": \"" + time + "\",\"Template\": \"" + template + "\",\"SANs\": {}}"
	payload := strings.NewReader(bodyContent)
	b.Logger().Debug("body: " + bodyContent)
	httpReq, err := http.NewRequest("POST", url, payload)
	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}
	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("authorization", "Basic "+encCreds)
	httpReq.Header.Add("x-certificateformat", "PEM")

	// Send request and check status
	b.Logger().Debug("About to connect to " + config.KeyfactorUrl + "for csr submission")
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("CSR Enrollment failed: {{err}}", err.Error())
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("CSR Enrollment failed: server returned" + fmt.Sprint(res.StatusCode))
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)
		b.Logger().Error("Error response: " + string(body[:]))
		return nil, "", fmt.Errorf("enrollment failed: server returned  %d\n ", res.StatusCode)
	}

	// Read response and return certificate and key
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
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

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + normalizeSerial(serial),
		Value: []byte(certs[0]),
	})
	if err != nil {
		return nil, "", errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
	}

	entry, err := logical.StorageEntryJSON("kfId/"+normalizeSerial(serial), kfId)
	if err != nil {
		return nil, "", err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, "", errwrap.Wrapf("unable to store the keyfactor ID for the certificate locally: {{err}}", err)
	}

	return certs, serial, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
