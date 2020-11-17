package keyfactor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net"
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
var issuer_chain []string

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
					Summary:  "Retrieve a certificate by serial number",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Request a certificate",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleList,
				},
                                logical.DeleteOperation: &framework.PathOperation{
                                        Callback: b.handleDelete,
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
	if strings.Contains(data.Get("path").(string), "roles") {
		return b.listRoles()
	}
	var list []string
	for k, _ := range b.store {

		list = append(list, k)
	}
	resp := &logical.Response{
		Data: map[string]interface{} {
			"keys":list,
		},
	}

	return resp, nil
}

func (b *backend) listRoles() (*logical.Response, error) {
	var list []string
	for k, _ := range roles {
		list = append(list, k)
	}
	resp := &logical.Response{
                Data: map[string]interface{} {
                        "keys":list,
                },
        }
        return resp, nil
}

func (b *backend) readRole(roleName string) (*logical.Response, error) {
	if !b.checkRoleExists(roleName){
		return nil, fmt.Errorf("No such role")
	}
	role := roles["roleName"]
	allow_subdomains := false
	allowed_domains := []string{}
	allow_localhost := false
	for k, v := range role {
		if k == "localhost" {
			allow_localhost = true
		}
		allow_subdomains = v
		allowed_domains = append(allowed_domains, k)
	}
	empty := []string{}
	key_usages := []string{"DigitalSignature","KeyAgreement","KeyEncipherment"}
	resp := &logical.Response{
                Data: map[string]interface{}{
			"allow_any_name":false,
			"allow_bare_domains":true,
			"allow_glob_domains":false,
			"allow_ip_sans":true,
			"allow_localhost":allow_localhost,
			"allow_subdomains":allow_subdomains,
			"allow_token_displayname":false,
			"allowed_domains":allowed_domains,
			"allowed_other_sans":nil,
			"allowed_serial_numbers":empty,
			"allowed_uri_sans":allowed_domains,
			"basic_constraints_valid_for_non_ca":false,
			"client_flag":false,
			"code_signing_flag":false,
			"country":empty,
			"email_protection_flag":false,
			"enforce_hostnames":true,
			"ext_key_usage":empty,
			"ext_key_usage_oids":empty,
			"generate_lease":false,
			"key_bits":2048,
			"key_type":"rsa",
			"key_usage":key_usages,
			"locality":empty,
			"max_ttl":"0s",
			"no_store":false,
			"not_before_duration":"10m",
			"organization":empty,
			"ou":empty,
			"policy_identifiers":empty,
			"postal_code":empty,
			"province":empty,
			"require_cn":true,
			"server_flag":true,
			"street_address":empty,
			"ttl":"0s",
			"use_csr_common_name":true,
			"use_csr_sans":true,
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
	if path == "ca_chain" {
		return b.getCertChain()
	}
	if strings.HasPrefix(path, "roles") {
		paths := strings.Split(path, "/")
		if len(paths) != 2 {
			return nil, fmt.Errorf("Invalid role requested")
		}
		return b.readRole(paths[1])
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

// Generate keypair and CSR
func (b *backend) generateCSR(cn string, ip_sans []string, dns_sans []string) (string, []byte) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	subj := pkix.Name{
		CommonName: cn,
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	var netIPSans []net.IP
	for i := range ip_sans{
		netIPSans = append(netIPSans, net.ParseIP(ip_sans[i]))
	}

	csrtemplate := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:	    netIPSans,
		DNSNames:	    dns_sans,
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrBuf.String(), x509.MarshalPKCS1PrivateKey(keyBytes)
}

// Handle interface with Keyfactor API to enroll a certificate with given content
func (b* backend) submitCSR(csr string) ([]string, string, error) {
	host := config["host"]
	template := config["template"]
	ca := config["ca"]
	appkey := config["appkey"]
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
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}
	req.Header.Add("x-keyfactor-requested-with", "APIClient")
	req.Header.Add("content-type", "application/json")
	req.Header.Add("x-keyfactor-appkey", appkey)
	req.Header.Add("authorization", "Basic "+creds)
	req.Header.Add("x-certificateformat", "PEM")

	secretBytes, _ := base64.StdEncoding.DecodeString(config["secret"])
	macAlg := hmac.New(sha1.New, secretBytes)
	macAlg.Write([]byte(bodyContent))
	mac := base64.StdEncoding.EncodeToString(macAlg.Sum(nil))
	b.Logger().Debug("MAC value: " + mac)
	req.Header.Add("x-keyfactor-signature",mac)

	// Send request and check status
	b.Logger().Debug("About to connect to " + config["host"] + "for csr submission")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Logger().Info("Enrollment failed: {{err}}", err)
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Info("Enrollment failed: server returned " + string(res.StatusCode))
		return nil, "", fmt.Errorf("Enrollment failed: server returned " + string(res.StatusCode))
	}

	// Read response and return certificate and key
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
		return nil, "",  err
	}

	// Parse response
        var r map[string]interface{}
        json.Unmarshal(body, &r)
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

	// Retain the issuer cert for calls to "vault read keyfactor/cert/ca" - TODO Get via Keyfactor API
        issuer = certs[1]
        issuer_chain = certs[1:]

	return certs, serial, nil
}

func (b *backend) requestCert(req *logical.Request, data *framework.FieldData, role string) (*logical.Response, error) {
	arg, _ := json.Marshal(req.Data)
	b.Logger().Debug(string(arg))
	cn := ""
	var ip_sans []string
	var dns_sans []string

	// Get and validate subject info from Vault command
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("common_name must be provided to issue certificate")
	}
	for k, v := range req.Data {
		if k == "common_name" {
			cn = v.(string)
		}
		if k == "ip_sans" {  // TODO - type switch
			ip_sans = strings.Split(v.(string), ",")
		}
		if k == "dns_sans" {  // TODO - type switch
			dns_sans = strings.Split(v.(string), ",")
		}
	}
	if !b.checkDomainAgainstRole(role, cn) {
		return nil, fmt.Errorf("Common name not allowed for provided role")
	}
	for u := range dns_sans {
		if !b.checkDomainAgainstRole(role, dns_sans[u]) {
			return nil, fmt.Errorf("Subject Alternative Name " + dns_sans[u] + " not allowed for provided role")
		}
	}

	// Generate and submit the CSR
	csr, key := b.generateCSR(cn, ip_sans, dns_sans)
	certs, serial, err := b.submitCSR(csr)
	if err != nil {
		return nil, fmt.Errorf("Could not enroll certificate: {{err}}", err)
	}

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
	b.Logger().Debug("issuer: " + issuer)
	response := &logical.Response{
                Data: map[string]interface{}{
                        "certificate": issuer,
		},
	}
	return response, nil
}

func (b *backend) getCertChain() (*logical.Response, error){
	chain := ""
	for c := range issuer_chain {
		chain += issuer_chain[c]
	}
        b.Logger().Debug("issuer chain: " + chain)
	response := &logical.Response{
                Data: map[string]interface{}{
                        "certificate": chain,
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

	// Sign a CSR that's provided to vault
	if len(path) == 2 && path[0] == "sign" {
                if !b.checkRoleExists(path[1]) {
                        return nil, fmt.Errorf("Cannot find provided role")
                }
		for k, v := range req.Data {
                        if k == "csr" {
                                return b.sign(v.(string), path[1])
                        }
                }
		return nil, fmt.Errorf("Must supply csr parameter to sign")
	}

	// If roles, add role
	if len(path) == 2 && path[0] == "roles" {
		b.Logger().Trace("Adding role " + path[1])

		// Parse role parameters
		var domains []string
		allowSubdomains := false
		for k, v := range req.Data {
			if k == "allowed_domains" {
				switch t := v.(type) {
				case string:
					domains = strings.Split(v.(string),",")
				case []interface{}:
					for d := range v.([]interface{}) {
						domains = append(domains,v.([]interface{})[d].(string))
					}
				default:
					return nil, fmt.Errorf("Invalid parameter value type: ",t)
				}
			}
			if k == "allow_subdomains" {
				switch t := v.(type) {
				case string:
					allowSubdomains, _ = strconv.ParseBool(v.(string))
				case bool:
					allowSubdomains = v.(bool)
				default:
					return nil, fmt.Errorf("Invalid parameter value type: ", t)
				}
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

	// Certificate revocation
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

func (b* backend) sign(csrString string, role string) (*logical.Response, error) {
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
	certs, serial, err := b.submitCSR(csrString)

	if err != nil {
                b.Logger().Info("Error signing certificate: {{err}}", err)
                return nil,  err
        }

	response := &logical.Response{
                Data: map[string]interface{}{
                        "certificate":      certs[0],
                        "issuing_ca":       certs[1],
			"ca_chain":	    certs[1:],
                        "serial_number":    serial,
			"revocation_time":  0,
                },
        }
	return response, nil

}

// Revoke certificate.
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

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
        path := strings.Split(data.Get("path").(string), "/")
	if len(path) == 2 && path[0] == "roles" {
		if !b.checkRoleExists(path[1]) {
			return nil, fmt.Errorf("Role does not exist")
		}
		delete(roles,path[1])
	}
	return nil,nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
