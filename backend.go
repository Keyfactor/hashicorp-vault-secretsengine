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

//var myClient *http.Client
var config map[string]string
var roles map[string][]string

// Factory configures and returns backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	confPath := os.Getenv("KF_CONF_PATH")
	//	file, _ := ioutil.ReadFile("/root/vault/config/config-mar.json")
	file, _ := ioutil.ReadFile(confPath)
	config = make(map[string]string)
	roles = make(map[string][]string)
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

// backend wraps the backend framework and adds a map for storing key value pairs
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
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret at the specified location.",
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

func (b *backend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var list []string
	for k, _ := range b.store {
		if k == "roles" {
			continue
		}

		list = append(list, strings.Split(k,"/")[1])
	}
//	content, _ := jsonutil.EncodeJSON(b.store)
//	fmt.Println(content)
//	b.Logger().Info("1"+string(content))
//	var r map[string]interface{}
//	jsonutil.DecodeJSON(content, &r)
//	content, _ = jsonutil.EncodeJSON(r)
//	b.Logger().Info("2"+string(content))
	resp := &logical.Response{
		Data: map[string]interface{} {
			"keys":list,
		},
	}

	return resp, nil
}

func (b *backend) load (ctx context.Context, req *logical.Request) {
	data, _ := req.Storage.Get(ctx, "entry")
	if data == nil {
		return
	}
        var rawData map[string][]byte
	jsonutil.DecodeJSON(data.Value, &rawData)
	b.store = rawData
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
//	b.load(ctx, req)
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)
	path = strings.ReplaceAll(path, "-","")
	path = strings.ReplaceAll(path, ":","")
	path = strings.ReplaceAll(path, "/cert/","")
	b.Logger().Debug("requested " + path)
	var rawData map[string]interface{}
	serializedStore, err := jsonutil.EncodeJSON(b.store)
	if err != nil {
		return nil, err
	}
	b.Logger().Trace(string(serializedStore))
	b.Logger().Debug(string(b.store[req.ClientToken+"/"+path]))
	if err := jsonutil.DecodeJSON(b.store[req.ClientToken+"/"+path], &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}
	resp := &logical.Response{
		Data: rawData,
		//		Data: map[string]interface{}{
		//			"certificate":rawData[path],
		//			"revocation_time":0,
		//		},
	}

	return resp, nil
}

func (b *backend) getCSR(host string, time string, template string, ca string, cn string, appkey string, creds string) ([]byte, []byte) {

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

	b.Logger().Debug("Closing idle connections")
	http.DefaultClient.CloseIdleConnections()
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

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Logger().Info("Enrollment failed: {{err}}", err)
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
	}

	b.Logger().Debug("Returning body: " + string(body))
	return body, x509.MarshalPKCS1PrivateKey(keyBytes)
}

func (b *backend) requestCSR(req *logical.Request, data *framework.FieldData, domains []string) (*logical.Response, error) {
	location, _ := time.LoadLocation("UTC")
	t := time.Now().In(location)
	timestamp := t.Format("2006-01-02T15:04:05")

	arg, _ := json.Marshal(req.Data)
	b.Logger().Info(string(arg))
	cn := ""
	for k, v := range req.Data {
		if k == "common_name" {
			cn = v.(string)
		}
	}
	if !strings.HasSuffix(cn, domains[0]) {
		return nil, fmt.Errorf("Role does not allow cn " + cn)
	}
	b.Logger().Debug("Connecting to " + config["host"] + "for common name " + cn)
	result, key := b.getCSR(config["host"], timestamp, config["template"], config["CA"], cn, config["appkey"], config["creds"])

	// Check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data must be provided to store in secret")
	}

	var r map[string]interface{}
	json.Unmarshal(result, &r)

	inner := r["CertificateInformation"].(map[string]interface{})
	certI := inner["Certificates"].([]interface{})
	certs := make([]string, len(certI))
	for i, v := range certI {
		certs[i] = v.(string)
	}
	serial := inner["SerialNumber"].(string)
	b.Logger().Debug("Cert content: " + certs[0])
	b.Logger().Debug("Serial number: " + serial)
	buf := []byte(`{"` + serial + `":"` + certs[0] + `"}`)
	b.store[req.ClientToken+"/"+serial] = buf

	response := &logical.Response{
		Data: map[string]interface{}{
			"certificate":      "-----BEGIN CERTIFICATE-----\n" + certs[0] + "\n-----END CERTIFICATE-----",
			"issuing_ca":       "-----BEGIN CERTIFICATE-----\n" + certs[1] + "\n-----END CERTIFICATE-----",
			"private_key":      "-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(key) + "\n-----END RSA PRIVATE KEY-----",
			"private_key_type": "rsa",
			"serial_number":    serial,
		},
	}

	return response, nil
}

func (b *backend) checkRole(role string) bool {
	b.Logger().Trace("Checking role " + role + " against " + strconv.FormatInt(int64(len(roles)), 10) + " roles")
	jsonutil.DecodeJSON(b.store["roles"], &roles)
	for k, _ := range roles {
		b.Logger().Trace("Checking against role " + k)
		if k == role {
			return true
		}
	}
	return false
}

func (b *backend) save(ctx context.Context, req *logical.Request) {
	data, _ := jsonutil.EncodeJSON(b.store)
	entry := logical.StorageEntry {Key:"Data",Value:data}
	req.Storage.Put(ctx, &entry)
}

func (b *backend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Break up path
	// If issue, look up role then go to CSR
	path := strings.Split(data.Get("path").(string), "/")
	if len(path) == 2 && path[0] == "issue" {
		if b.checkRole(path[1]) {
			return b.requestCSR(req, data, roles[path[1]])
		}
//		b.save(ctx, req)
		return nil, fmt.Errorf("Cannot find provided role")
	}
	// If roles, add role
	if len(path) == 2 && path[0] == "roles" {
		b.Logger().Trace("Adding role " + path[1])
		var domains []string
		for k, v := range req.Data {
			if k == "allowed_domains" {
				domains = strings.Split(v.(string),",")
			}
		}
	        jsonutil.DecodeJSON(b.store["roles"], &roles)
		roles[path[1]] = domains
		buf, _ := json.Marshal(roles)
		b.store["roles"] = []byte(buf)
//		b.save(ctx, req)
		return nil, nil
	}
	return nil, fmt.Errorf("Invalid path")
}

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	if path == "all" {
		b.store = make(map[string][]byte)
		return nil, nil
	}

	fmt.Println(path)
	b.Logger().Info(string(b.store[req.ClientToken+"/"+path]))

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
	delete(b.store, req.ClientToken+"/"+path)

	return nil, nil
}

const keyfactorHelp = `
The Keyfactor backend is a pki service that issues and manages certificates.
`
