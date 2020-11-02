package keyfactor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var config map[string]string
var roles map[string]map[string]bool
var issuer string

// Factory configures and returns backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	confPath := os.Getenv("KF_CONF_PATH")
	file, _ := ioutil.ReadFile(confPath)
	config = make(map[string]string)
	roles = make(map[string]map[string]bool)
	jsonutil.DecodeJSON(file, &config)

	b := &backend{
		store: make(map[string][]byte),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(keyfactorHelp),
		BackendType: logical.TypeLogical,
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)
	return b, nil
}

// Store certificates by serial number
type backend struct {
	*framework.Backend

	store map[string][]byte
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret from the map.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleList,
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

// List all serial numbers known to engine
func (b *backend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var list []string
	for k, _ := range b.store {
		if k == "roles" {
			continue
		}

		list = append(list, k)
	}
	resp := &logical.Response{
		Data: map[string]interface{} {
			"keys":list,
		},
	}

	return resp, nil
}

// Lookup certificate by serial number
func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get and canonicalize serial number from Vault path
	path := data.Get("path").(string)
	path = strings.ReplaceAll(path, "-","")
	path = strings.ReplaceAll(path, ":","")
	path = strings.ReplaceAll(path, "cert/","")
	b.Logger().Debug("requested " + path)
	if path == "ca" {
		return b.getCACert()
	}

	// Lookup and decode certificate stored by given serial number
	certBytes := b.store[path]
	certString := string(certBytes)

	// Conform response to Vault PKI API
	resp := &logical.Response{
		Data: map[string]interface{}{
			"certificate":certString,
			"revocation_time":0,
		},
	}

	return resp, nil
}

// Handle interface with crypto libraries and Keyfactor API to enroll a certificate with given content
func (b *backend) submitCSR(host string, time string, template string, ca string, cn string, appkey string, creds string) ([]byte, []byte) {
	// Generate keypair and CSR
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	subj := pkix.Name{
		CommonName: cn,
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	csrtemplate := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	http.DefaultClient.CloseIdleConnections()

	// Build request
	url := config["protocol"] + "://" + host + "/KeyfactorAPI/Enrollment/CSR"
	b.Logger().Debug("url: " + url)
	bodyContent := "{\"CSR\": \"" + csrBuf.String() + "\",\"CertificateAuthority\":\"" + ca + "\",\"IncludeChain\": true, \"Metadata\": {}, \"Timestamp\": \"" + time + "\",\"Template\": \"" + template + "\",\"SANs\": {}}"
	payload := strings.NewReader(bodyContent)
	b.Logger().Debug("body: " + bodyContent)
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}
	req.Header.Add("x-keyfactor-requested-with", "APIClient")
	req.Header.Add("content-type", "application/json")
	req.Header.Add("x-keyfactor-appkey", appkey)
	req.Header.Add("authorization", "Basic "+creds)
	req.Header.Add("x-certificateformat", "PEM")

	// Send request and check status
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Logger().Info("Enrollment failed: {{err}}", err)
		return nil, nil
	}
	if res.StatusCode != 200 {
		b.Logger().Info("Enrollment failed: server returned " + string(res.StatusCode))
		return nil, nil
	}

	// Read response and return certificate and key
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
	}
	b.Logger().Debug("Returning body: " + string(body))
	return body, x509.MarshalPKCS1PrivateKey(keyBytes)
}


func (b *backend) requestCert(req *logical.Request, data *framework.FieldData, role string) (*logical.Response, error) {
	location, _ := time.LoadLocation("UTC")
	t := time.Now().In(location)
	timestamp := t.Format("2006-01-02T15:04:05")
	arg, _ := json.Marshal(req.Data)
	b.Logger().Debug(string(arg))
	cn := ""

	// Get and validate subject info from Vault command
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("common_name must be provided to issue certificate")
	}
	for k, v := range req.Data {
		if k == "common_name" {
			cn = v.(string)
		}
	}
	if !b.checkDomainAgainstRole(role, cn) {
		return nil, fmt.Errorf("Common name not allowed for provided role")
	}

	// Call to generate and submit the CSR. TODO - simplify submitCSR params?
	b.Logger().Debug("About to connect to " + config["host"] + "for common name " + cn)
	result, key := b.submitCSR(config["host"], timestamp, config["template"], config["CA"], cn, config["appkey"], config["creds"])
	if result == nil || key == nil {
		return nil, fmt.Errorf("Could not enroll certificate")
	}

	// Parse response. TODO - move to submitCSR?
	var r map[string]interface{}
	json.Unmarshal(result, &r)
	inner := r["CertificateInformation"].(map[string]interface{})
	certI := inner["Certificates"].([]interface{})
	certs := make([]string, len(certI))
	for i, v := range certI {
		certs[i] = v.(string)
		start := strings.Index(certs[i],"-----BEGIN CERTIFICATE-----")
		certs[i] = certs[i][start:]
	}
	serial := inner["SerialNumber"].(string)
	b.Logger().Debug("Cert content: " + certs[0])
	b.Logger().Debug("Serial number: " + serial)
	b.store[serial] = []byte(certs[0])

	// Retain the issuer cert for calls to "vault read keyfactor/cert/ca"
	issuer = certs[1]

	// Conform response to Vault PKI API
	response := &logical.Response{
		Data: map[string]interface{}{
			"certificate":      certs[0],
			"issuing_ca":       certs[1],
			"private_key":      "-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(key) + "\n-----END RSA PRIVATE KEY-----",
			"private_key_type": "rsa",
			"revocation_time":0,
			"serial_number":    serial,
		},
	}

	return response, nil
}

func (b* backend) getCACert() (*logical.Response, error) {
//	query := `(CertState -eq "6" OR CertState -eq "7") AND CA -eq "` + config["CA"] + `"`
/*        url := config["protocol"] + "://" + host + "/KeyfactorAPI/Certificates/Query"
        b.Logger().Debug("url: " + url)
        bodyContent := "{\"CSR\": \"" + csrBuf.String() + "\",\"CertificateAuthority\":\"" + ca + "\",\"IncludeChain\": true, \"Metadata\": {}, \"Timestamp\": \"" + time + "\",\"Template\": \"" + template + "\",\"SANs\": {}}"
        payload := strings.NewReader(bodyContent)
        b.Logger().Debug("body: " + bodyContent)
        req, err := http.NewRequest("POST", url, payload)
        if err != nil {
                b.Logger().Info("Error forming request: {{err}}", err)
        }
        req.Header.Add("x-keyfactor-requested-with", "APIClient")
        req.Header.Add("content-type", "application/json")
        req.Header.Add("x-keyfactor-appkey", appkey)
        req.Header.Add("authorization", "Basic "+creds)
        req.Header.Add("x-certificateformat", "PEM")

        // Send request and check status
        res, err := http.DefaultClient.Do(req)
        if err != nil {
                b.Logger().Info("Enrollment failed: {{err}}", err)
                return nil, nil
        }
        if res.StatusCode != 200 {
                b.Logger().Info("Enrollment failed: server returned " + string(res.StatusCode))
                return nil, nil
        }

        // Read response and return certificate and key
        defer res.Body.Close()
        body, err := ioutil.ReadAll(res.Body)
        if err != nil {
                b.Logger().Info("Error reading response: {{err}}", err)
        }
*/
	b.Logger().Debug("issuer: " + issuer)
	response := &logical.Response{
                Data: map[string]interface{}{
                        "certificate": issuer,
		},
	}
	return response, nil
}

// Return true if a role is defined and false if not
func (b *backend) checkRoleExists(role string) bool {
	b.Logger().Trace("Checking role " + role + " against " + strconv.FormatInt(int64(len(roles)), 10) + " roles")
	for k, _ := range roles {
		b.Logger().Info("Checking against role " + k)
		if k == role {
			return true
		}
	}
	return false
}

// Check if a domain is allowed for a given role based on allowed domains and whether subdomains are allowed
func (b *backend) checkDomainAgainstRole(role string, domain string) bool {
	for k, v := range roles[role] {
		// If subdomains are allowed, only the suffix needs to match the allowed domain
		if v && strings.HasSuffix(domain, k){
			return true
		}
		if !v && k == domain {
			return true
		}
	}
	return false
}

// Add role or enroll certificate
func (b *backend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Break up path
	path := strings.Split(data.Get("path").(string), "/")
	
	// If issue, look up role then request certificate
	if len(path) == 2 && path[0] == "issue" {
		if !b.checkRoleExists(path[1]) {
			return nil, fmt.Errorf("Cannot find provided role")
		}
		return b.requestCert(req, data, path[1])
	}

	// If roles, add role
	if len(path) == 2 && path[0] == "roles" {
		b.Logger().Trace("Adding role " + path[1])

		// Parse role parameters
		var domains []string
		allowSubdomains := false
		for k, v := range req.Data {
			if k == "allowed_domains" {
				domains = strings.Split(v.(string),",")
			}
			if k == "allow_subdomains" {
				allowSubdomains, _ = strconv.ParseBool(v.(string))
			}
		}

		// Add the given role as a map where the keys are the domains and the values are whether to allow subdomains for that domain
		roles[path[1]] = make(map[string]bool)
		for i := range domains{
			roles[path[1]][domains[i]] = allowSubdomains
		}
		roleString, _ := jsonutil.EncodeJSON(roles)
		b.Logger().Debug("roles: " + string(roleString))
		return nil, nil
	}

	if len(path) == 1 && path[0] == "revoke" {
                for k, v := range req.Data {
                        if k == "serial_number" {
				return b.revoke(v.(string))
                        }
                }
		return nil, fmt.Errorf("Must supply serial_number parameter to revoke")

	}
	return nil, fmt.Errorf("Invalid path")
}

// Revoke certificate. TODO - change path
func (b* backend) revoke(path string) (*logical.Response, error) {
        path = strings.ReplaceAll(path, "-","")
        path = strings.ReplaceAll(path, ":","")
	fmt.Println("Revoking serial number " + path)

	b.Logger().Info(string(b.store[path]))

	url := config["protocol"] + "://" + config["host"] + "/CMSAPI/Certificates/3/Revoke"
	payload := `{"Lookup":{"Type":"Serial","SerialNumber":"` + path + `","IssuerDN":"CN=jdk-CA1,DC=jdk,DC=cms"},"Details":{"Reason":4, "EffectiveDate": "2020-5-5", "Comment":"" }}`

	httpReq, _ := http.NewRequest("POST", url, strings.NewReader(payload))

	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("authorization", "Basic "+config["creds"])

	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("Revoke failed: {{err}}", err)
	}

	defer res.Body.Close()
	_, _ = ioutil.ReadAll(res.Body)

	// Remove entry for specified path
	delete(b.store, path)

	return nil, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
