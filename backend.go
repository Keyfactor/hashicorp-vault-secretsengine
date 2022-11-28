package keyfactor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var config map[string]string

// Factory configures and returns backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	b := backend()

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)
	return b, nil
}

// // Store certificates by serial number
type keyfactorBackend struct {
	*framework.Backend
	lock sync.RWMutex
	client *api.Client
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
		Paths:       framework.PathAppend(),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

func (b *keyfactorBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	err := req.Storage.Delete(ctx, "/ca")

	if err != nil {
		b.Logger().Error("Error removing previous stored ca values on init")
		return err
	}
	confPath := os.Getenv("KF_CONF_PATH")
	file, _ := ioutil.ReadFile(confPath)
	config = make(map[string]string)
	jsonutil.DecodeJSON(file, &config)
	b.Logger().Debug("INITIALIZE: KF_CONF_PATH = " + confPath)
	b.Logger().Debug("config file contents = ", config)
	return nil
}

// Generate keypair and CSR
func (b *keyfactorBackend) generateCSR(cn string, ip_sans []string, dns_sans []string) (string, []byte) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	subj := pkix.Name{
		CommonName: cn,
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	var netIPSans []net.IP
	for i := range ip_sans {
		netIPSans = append(netIPSans, net.ParseIP(ip_sans[i]))
	}

	csrtemplate := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        netIPSans,
		DNSNames:           dns_sans,
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrBuf.String(), x509.MarshalPKCS1PrivateKey(keyBytes)
}

// Handle interface with Keyfactor API to enroll a certificate with given content
func (b *keyfactorBackend) submitCSR(ctx context.Context, req *logical.Request, csr string, caName string, templateName string) ([]string, string, error) {
	host := config["host"]
	template := config["template"]
	ca := config["CA"]
	creds := config["creds"]

	if caName != "" {
		ca = caName
	}

	if templateName != "" {
		template = templateName
	}

	location, _ := time.LoadLocation("UTC")
	t := time.Now().In(location)
	time := t.Format("2006-01-02T15:04:05")

	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	http.DefaultClient.CloseIdleConnections()

	// Build request
	url := config["protocol"] + "://" + host + "/KeyfactorAPI/Enrollment/CSR"
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
	httpReq.Header.Add("authorization", "Basic "+creds)
	httpReq.Header.Add("x-certificateformat", "PEM")

	// Send request and check status
	b.Logger().Debug("About to connect to " + config["host"] + "for csr submission")
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("CSR Enrollment failed: {{err}}", err)
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("CSR Enrollment failed: server returned" + fmt.Sprint(res.StatusCode))
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)
		b.Logger().Error("Error response: " + fmt.Sprint(body))
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
		b.Logger().Error("unable to parse ca_chain response", err)
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

// reset clears any client configuration for a new
// backend to be configured
func (b *keyfactorBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	//b.client = nil
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
// func (b *keyfactorBackend) getClient(ctx context.Context, s logical.Storage) (*hashiCupsClient, error) {
// 	b.lock.RLock()
// 	unlockFunc := b.lock.RUnlock
// 	defer func() { unlockFunc() }()

// 	// if b.client != nil {
// 	// 	return b.client, nil
// 	// }

// 	b.lock.RUnlock()
// 	b.lock.Lock()
// 	unlockFunc = b.lock.Unlock

// 	return nil, fmt.Errorf("need to return client")
// }

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
