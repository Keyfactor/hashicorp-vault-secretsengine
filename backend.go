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
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var config map[string]string

// Factory configures and returns backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	confPath := os.Getenv("KF_CONF_PATH")
	file, _ := ioutil.ReadFile(confPath)
	config = make(map[string]string)
	//roles = make(map[string]map[string]bool)
	jsonutil.DecodeJSON(file, &config)
	var b backend
	// b := &backend{
	// 	store:       make(map[string][]byte),
	// 	crlLifetime: time.Hour * 72,
	// }

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(keyfactorHelp),
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			pathListRoles(&b),
			pathRoles(&b),
			pathFetchCA(&b),
			pathFetchCAChain(&b),
			pathFetchValid(&b),
			pathFetchListCerts(&b),
			pathRevoke(&b),
			pathIssue(&b),
			pathSign(&b),
		},
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)
	return b, nil
}

// Store certificates by serial number
type backend struct {
	*framework.Backend
	//storage      logical.Storage
	crlLifetime time.Duration
	//tidyCASGuard *uint32
	//store map[string][]byte
}

// func (b *backend) paths() []*framework.Path {
// 	return []*framework.Path{
// 		{
// 			Pattern: "issue/" + framework.GenericNameRegex("role"),

// 			Fields: addIssueAndSignCommonFields(map[string]*framework.FieldSchema{
// 				"role": {
// 					Type:        framework.TypeLowerCaseString,
// 					Description: "Name of the role",
// 					Required:    true,
// 				},
// 			}),

// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.UpdateOperation: b.handleWrite,
// 				logical.CreateOperation: b.handleWrite,
// 			},

// 			ExistenceCheck: b.handleExistenceCheck,
// 		},
// 		{
// 			Pattern: "revoke/",
// 			Fields: map[string]*framework.FieldSchema{
// 				"serial_number": {
// 					Type:        framework.TypeString,
// 					Description: "The serial number of the certificate to revoke",
// 					Required:    true,
// 				},
// 			},
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.UpdateOperation: b.handleRevoke,
// 			},
// 		},
// 		{
// 			Pattern: "sign/",
// 			Fields:  addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.UpdateOperation: b.handleSign,
// 			},
// 		},
// 		{
// 			Pattern: "ca/",
// 			Fields:  addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.ReadOperation: b.getCACert,
// 			},
// 		},
// 		{
// 			Pattern: "ca_chain/",
// 			Fields:  addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.ReadOperation: b.getCertChain,
// 			},
// 		},
// 		{
// 			Pattern: "certs/?$",
// 			Fields:  addIssueAndSignCommonFields(map[string]*framework.FieldSchema{}),
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.ListOperation: b.handleList,
// 			},
// 		},
// 		{
// 			Pattern: `cert/(?P<serial>[0-9A-Fa-f-:]+)`,
// 			Fields: map[string]*framework.FieldSchema{
// 				"serial_number": {
// 					Type:        framework.TypeString,
// 					Description: "The serial number of the certificate to read",
// 					Required:    true,
// 				},
// 			},
// 			Callbacks: map[logical.Operation]framework.OperationFunc{
// 				logical.ReadOperation: b.handleRead,
// 			},
// 		},
// 	}
// }

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

// Generate keypair and CSR
func (b *backend) generateCSR(cn string, ip_sans []string, dns_sans []string) (string, []byte) {
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
func (b *backend) submitCSR(ctx context.Context, req *logical.Request, csr string) ([]string, string, error) {
	host := config["host"]
	template := config["template"]
	ca := config["CA"]
	creds := config["creds"]

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
		b.Logger().Info("Enrollment failed: {{err}}", err)
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("Enrollment failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Error("Error response = " + fmt.Sprint(res.Body))
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
	//caId := inner["CertificateAuthorityId"].(float64)
	//b.Logger().Debug("CertificateAuthorityId = %d", caId)
	// b.Logger().Debug("Serial number: ", serial)
	// b.Logger().Debug("Keyfactor Id: ", kfId)
	//b.store[serial] = []byte(certs[0])
	// Retain the issuer cert for calls to "vault read keyfactor/cert/ca" - TODO Get via Keyfactor API
	//b.save(ctx, req, serial, []byte(certs[0]))
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

	// caIdEntry, err := logical.StorageEntryJSON("caId", caId)
	// if err != nil {
	// 	return nil, "", err
	// }

	// err = req.Storage.Put(ctx, caIdEntry)
	// if err != nil {
	// 	return nil, "", errwrap.Wrapf("unable to store the CA ID for the certificate locally: {{err}}", err)
	// }

	return certs, serial, nil
}

// func (b *backend) requestCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role string) (*logical.Response, error) {
// 	arg, _ := json.Marshal(req.Data)
// 	b.Logger().Debug(string(arg))
// 	cn := ""
// 	var ip_sans []string
// 	var dns_sans []string

// 	// Get and validate subject info from Vault command
// 	if len(req.Data) == 0 {
// 		return nil, fmt.Errorf("common_name must be provided to issue certificate")
// 	}
// 	for k, v := range req.Data {
// 		if k == "common_name" {
// 			cn = v.(string)
// 		}
// 		if k == "ip_sans" { // TODO - type switch
// 			ip_sans = strings.Split(v.(string), ",")
// 		}
// 		if k == "dns_sans" { // TODO - type switch
// 			dns_sans = strings.Split(v.(string), ",")
// 		}
// 	}
// 	b.Logger().Debug("about to check role: " + role + " against domain " + cn)

// 	if !b.checkDomainAgainstRole(ctx, req, role, cn) { // <-- leaving off here.. fix this function
// 		return nil, fmt.Errorf("common name not allowed for provided role")
// 	}
// 	for u := range dns_sans {
// 		if !b.checkDomainAgainstRole(ctx, req, role, dns_sans[u]) {
// 			return nil, fmt.Errorf("Subject Alternative Name " + dns_sans[u] + " not allowed for provided role")
// 		}
// 	}

// 	// Generate and submit the CSR
// 	csr, key := b.generateCSR(cn, ip_sans, dns_sans)
// 	certs, serial, err := b.submitCSR(ctx, req, csr)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not enroll certificate: %s/", err)
// 	}

// 	// Conform response to Vault PKI API
// 	response := &logical.Response{
// 		Data: map[string]interface{}{
// 			"certificate":      certs[0],
// 			"issuing_ca":       certs[1],
// 			"private_key":      "-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(key) + "\n-----END RSA PRIVATE KEY-----",
// 			"private_key_type": "rsa",
// 			"revocation_time":  0,
// 			"serial_number":    serial,
// 		},
// 	}

// 	return response, nil
// }

// func (b *backend) getCACert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
// 	if len(issuer_chain) == 0 {
// 		return nil, fmt.Errorf("CA certificate unknown")
// 	}
// 	b.Logger().Debug("issuer: " + issuer_chain[0])
// 	response := &logical.Response{
// 		Data: map[string]interface{}{
// 			"certificate": issuer_chain[0],
// 		},
// 	}
// 	return response, nil
// }

// func (b *backend) getCertChain(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
// 	chain := ""
// 	for c := range issuer_chain {
// 		chain += issuer_chain[c]
// 	}
// 	b.Logger().Debug("issuer chain: " + chain)
// 	response := &logical.Response{
// 		Data: map[string]interface{}{
// 			"certificate": chain,
// 		},
// 	}
// 	return response, nil
// }

// Check if a domain is allowed for a given role based on allowed domains and whether subdomains are allowed
func (b *backend) checkDomainAgainstRole(ctx context.Context, req *logical.Request, role string, domain string) bool {
	b.Logger().Debug("checking role: " + role + " against domain " + domain)

	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		b.Logger().Error("Error retrieving role " + role)
		return false
	}

	if roleEntry.AllowedBaseDomain == domain {
		return true
	}

	if strings.Contains(domain, roleEntry.AllowedBaseDomain) && roleEntry.AllowSubdomains {
		return true
	}

	return false
}

// Add role or enroll certificate
// func (b *backend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
// 	b.load(ctx, req)
// 	role := data.Get("role").(string)

// 	b.Logger().Debug("parsing role: " + role)

// 	// look up role then request certificate

// 	entry, err := req.Storage.Get(ctx, "role/"+role)
// 	if err != nil || entry == nil {
// 		return nil, fmt.Errorf("cannot find provided role")
// 	}

// 	return b.requestCert(ctx, req, data, role)
// }

// func (b *backend) handleRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
// 	sn := data.Get("serial_number").(string)

// 	if sn == "" {
// 		return nil, fmt.Errorf("must supply serial_number parameter to revoke")
// 	}

// 	return b.revoke(ctx, req, data, sn)
// }

func (b *backend) handleSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role := data.Get("role").(string)
	csr := data.Get("csr").(string)
	if csr == "" {
		return nil, fmt.Errorf("must supply csr parameter to sign")
	}
	return b.sign(ctx, req, csr, role)
}

func (b *backend) sign(ctx context.Context, req *logical.Request, csrString string, role string) (*logical.Response, error) {
	//	TODO - Get CSR to parse from CLI
	//	csr, err := x509.ParseCertificateRequest([]byte(csrString))
	//	if err != nil {
	//		return nil, fmt.Errorf("Could not parse CSR: {{err}}",err)
	//	}
	//	cn := csr.Subject.CommonName
	//	b.Logger().Debug("Got CSR with CN="+cn)
	//	if !b.checkDomainAgainstRole(role, cn) {
	//		return nil, fmt.Errorf("Common name {{cn}} is not allowed for provided role", cn)
	//	}
	// TODO - check SANs

	certs, serial, err := b.submitCSR(ctx, req, csrString)

	if err != nil {
		b.Logger().Info("Error signing certificate: {{err}}", err)
		return nil, err
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"certificate":     certs[0],
			"issuing_ca":      certs[1],
			"ca_chain":        certs[1:],
			"serial_number":   serial,
			"revocation_time": 0,
		},
	}
	// err = req.Storage.Put(ctx, &logical.StorageEntry{
	// 	Key:   "certs/" + normalizeSerial(serial),
	// 	Value: certs[0],
	// })
	// if err != nil {
	// 	return nil, errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
	// }
	return response, nil

}

// Revoke certificate.
// func (b *backend) revoke(ctx context.Context, req *logical.Request, data *framework.FieldData, serial string) (*logical.Response, error) {
// 	serial = strings.ReplaceAll(serial, "-", "")
// 	serial = strings.ReplaceAll(serial, ":", "")
// 	fmt.Println("Revoking serial number " + serial)

// 	//b.Logger().Info(string(b.store[path]))

// 	// set up keyfactor api request
// 	url := config["protocol"] + "://" + config["host"] + "/CMSAPI/Certificates/3/Revoke"
// 	payload := `{"Lookup":{"Type":"Serial","SerialNumber":"` + serial + `","IssuerDN":"CN=jdk-CA1,DC=jdk,DC=cms"},"Details":{"Reason":4, "EffectiveDate": "2020-5-5", "Comment":"" }}`

// 	httpReq, _ := http.NewRequest("POST", url, strings.NewReader(payload))

// 	httpReq.Header.Add("content-type", "application/json")
// 	httpReq.Header.Add("authorization", "Basic "+config["creds"])

// 	res, err := http.DefaultClient.Do(httpReq)
// 	if err != nil {
// 		b.Logger().Error("Revoke failed: {{err}}", err)
// 	}

// 	defer res.Body.Close()
// 	_, _ = ioutil.ReadAll(res.Body)

// 	// Remove entry for specified path
// 	//delete(b.store, path)
// 	certEntry, err := fetchCertBySerial(ctx, req, "certs/", serial)
// 	var revInfo revocationInfo
// 	revEntry, err := fetchCertBySerial(ctx, req, "revoked/", serial)
// 	if err != nil {
// 		switch err.(type) {
// 		case errutil.UserError:
// 			return logical.ErrorResponse(err.Error()), nil
// 		case errutil.InternalError:
// 			return nil, err
// 		}
// 	}

// 	currTime := time.Now()
// 	revInfo.CertificateBytes = certEntry.Value
// 	revInfo.RevocationTime = currTime.Unix()
// 	revInfo.RevocationTimeUTC = currTime.UTC()

// 	revEntry, err = logical.StorageEntryJSON("revoked/"+normalizeSerial(serial), revInfo)
// 	if err != nil {
// 		return nil, fmt.Errorf("error creating revocation entry")
// 	}

// 	err = req.Storage.Put(ctx, revEntry)
// 	if err != nil {
// 		return nil, fmt.Errorf("error saving revoked certificate to new location")
// 	}

// 	return nil, nil
// }

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
