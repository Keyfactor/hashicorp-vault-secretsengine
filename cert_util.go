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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"go.mozilla.org/pkcs7"
)

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
func (b *keyfactorBackend) submitCSR(ctx context.Context, req *logical.Request, csr string, caName string, templateName string, dns_sans []string, ip_sans []string, metaDataJson string) ([]string, string, error) {
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

	// build dns_sans payload string
	dns_sans_payload_string := ""

	for _, d := range dns_sans {
		if d != dns_sans[0] {
			dns_sans_payload_string += "," // pre-pend a comma before next entry if not the first entry
		}
		dns_sans_payload_string = dns_sans_payload_string + fmt.Sprintf("\"%s\"", d)
	}
	b.Logger().Debug("dns_sans payload string = %s", dns_sans_payload_string)

	ip_sans_payload_string := ""

	for _, i := range ip_sans {
		if i != ip_sans[0] {
			ip_sans_payload_string += ","
		}
		ip_sans_payload_string = ip_sans_payload_string + fmt.Sprintf("\"%s\"", i)
	}
	b.Logger().Debug("ip_sans payload string = %s", ip_sans_payload_string)

	url := config.KeyfactorUrl + "/" + config.CommandAPIPath + "/Enrollment/CSR"
	b.Logger().Debug("url: " + url)
	bodyContent := "{\"CSR\": \"" + csr + "\", \"CertificateAuthority\":\"" + caName + "\", \"IncludeChain\": true, \"Metadata\": " + metaDataJson + ", \"Timestamp\": \"" + time + "\",\"Template\": \"" + templateName + "\""

	sans_payload := "\"SANs\": {"

	if dns_sans_payload_string != "" || ip_sans_payload_string != "" {
		if dns_sans_payload_string != "" {
			sans_payload += "\"dns\": [" + dns_sans_payload_string + "]"
		}
		if ip_sans_payload_string != "" {
			sans_payload += ", \"ip\": [" + ip_sans_payload_string + "]"
		}
	}
	sans_payload += "}"

	b.Logger().Trace(fmt.Sprintf("sans_payload: %s", sans_payload))
	bodyContent += ", " + sans_payload + "}"
	payload := strings.NewReader(bodyContent)

	b.Logger().Debug("request body: " + bodyContent)
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

// fetch the CA info from keyfactor
func fetchCAInfo(ctx context.Context, req *logical.Request, b *keyfactorBackend, caName string, includeChain bool) (response *logical.Response, retErr error) {
	var resp *logical.Response

	// first we see if we have previously retreived the CA or chain
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}
	storagePath := fmt.Sprintf("ca/%s", caName) // the storage path for the ca cert is "ca/{{ca name}}"

	if includeChain {
		storagePath = fmt.Sprintf("%s_chain", storagePath) // the storage path for the ca chain is "ca/{{ca name}}_chain"
	}
	b.Logger().Debug("local storage path = %s", storagePath)

	caEntry, err := req.Storage.Get(ctx, storagePath)

	if err != nil {
		return logical.ErrorResponse("error fetching ca: %s", err), nil
	}

	if caEntry != nil { // the CA is stored locally, just need to return it
		var r string
		json.Unmarshal(caEntry.Value, &r)
		b.Logger().Debug("stored ca = ", r)

		if includeChain {
			resp = &logical.Response{
				Data: map[string]interface{}{
					"CA Chain": r,
				},
			}
		} else {
			resp = &logical.Response{
				Data: map[string]interface{}{
					"CA Certificate": r,
				},
			}
		}

		return resp, nil
	}

	// it hasn't been stored locally, we we need to retreive a certificate issued by the CA
	// and then extract the chain

	issued_certs, err := fetchCertIssuedByCA(ctx, req, b, caName) // we get the ID of a cert issued by the CA

	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed to retreive any cert issued by the CA: %s", err)}
	}

	if len(issued_certs) == 0 {
		return nil, fmt.Errorf("no certificates issued by %s were found", caName)
	}

	issued_cert := issued_certs[0]

	b.Logger().Trace("extracting the CA and Chain from the retreived cert.")
	ca_chain, ca_cert, err := fetchChainAndCAForCert(ctx, req, b, issued_cert.ID) // we download the full cert and chain
	if err != nil {
		b.Logger().Error("error getting full chain and CA for cert: %s", err)
		return nil, err
	}
	b.Logger().Trace("extracted ca and chain from cert. chain has a length of %d \n", len(ca_chain))

	// now we have the full cert + chain, in PEM format

	// store the CA cert locally
	caStorageEntry, err := logical.StorageEntryJSON("ca/"+caName, ca_cert)
	if err != nil {
		b.Logger().Error("error creating ca entry", err)
	}

	err = req.Storage.Put(ctx, caStorageEntry)
	if err != nil {
		b.Logger().Error("error storing the ca locally", err)
	}

	ca_chain_combined := strings.Join(ca_chain, "") // store as a single PEM chain

	// store the full chain locally
	caChainStorageEntry, err := logical.StorageEntryJSON("ca/"+caName+"_chain", ca_chain_combined)
	if err != nil {
		b.Logger().Error("error creating ca chain entry", err)
	}

	err = req.Storage.Put(ctx, caChainStorageEntry)
	if err != nil {
		b.Logger().Error("error storing the ca chain locally", err)
	}

	if includeChain {
		resp = &logical.Response{
			Data: map[string]interface{}{
				"CA Chain": ca_chain,
			},
		}
	} else {
		resp = &logical.Response{
			Data: map[string]interface{}{
				"CA Certificate": ca_cert,
			},
		}
	}

	return resp, nil
}

// Allows fetching certificates from the backend; it handles the slightly
// separate pathing for CA and revoked certificates.
func fetchCertBySerial(ctx context.Context, req *logical.Request, prefix, serial string) (*logical.StorageEntry, error) {
	var path, legacyPath string
	var err error
	var certEntry *logical.StorageEntry

	hyphenSerial := normalizeSerial(serial)
	colonSerial := strings.Replace(strings.ToLower(serial), "-", ":", -1)

	switch {
	// Revoked goes first as otherwise ca/crl get hardcoded paths which fail if
	// we actually want revocation info
	case strings.HasPrefix(prefix, "revoked/"):
		legacyPath = "revoked/" + colonSerial
		path = "revoked/" + hyphenSerial
	default:
		legacyPath = "certs/" + colonSerial
		path = "certs/" + hyphenSerial
	}

	certEntry, err = req.Storage.Get(ctx, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", serial, err)}
	}
	if certEntry != nil {
		if len(certEntry.Value) == 0 {
			return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
		}
		return certEntry, nil
	}

	// If legacyPath is unset, it's going to be a CA or CRL; return immediately
	if legacyPath == "" {
		return nil, nil
	}

	// Retrieve the old-style path.  We disregard errors here because they
	// always manifest on windows, and thus the initial check for a revoked
	// cert fails would return an error when the cert isn't revoked, preventing
	// the happy path from working.
	certEntry, _ = req.Storage.Get(ctx, legacyPath)
	if certEntry == nil {
		return nil, nil
	}
	if len(certEntry.Value) == 0 {
		return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
	}

	// Update old-style paths to new-style paths
	certEntry.Key = path
	if err = req.Storage.Put(ctx, certEntry); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error saving certificate with serial %s to new location", serial)}
	}
	if err = req.Storage.Delete(ctx, legacyPath); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error deleting certificate with serial %s from old location", serial)}
	}

	return certEntry, nil
}

func fetchCertIssuedByCA(ctx context.Context, req *logical.Request, b *keyfactorBackend, caName string) (KeyfactorCertResponse, error) {
	// call certificates endpoint, limit results to 1, filter by CA name
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("unable to load configuration")
	}

	// get the client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("unable to create the http client")
	}
	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	client.httpClient.CloseIdleConnections()
	caName = strings.Replace(caName, " ", "%20", -1)
	reqUrl := config.KeyfactorUrl + "/" + config.CommandAPIPath + "/Certificates?pq.queryString=CA%20-eq%20%22" + caName + "%20%22&ReturnLimit=1"

	b.Logger().Debug("url: " + reqUrl)

	httpReq, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}

	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")

	// Send request and check status
	b.Logger().Debug("About to connect to " + reqUrl + "for cert retrieval")
	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("failed getting cert: {{err}}", err)
		return nil, err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("request failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Error("Error response = " + fmt.Sprint(res.Body))
		return nil, fmt.Errorf("error downloading certificate. returned status = %d\n ", res.StatusCode)
	}

	// Read response and return certificate and key
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
		return nil, err
	}

	// Parse response
	var r KeyfactorCertResponse
	json.Unmarshal(body, &r)
	b.Logger().Debug("response = ", r)

	if len(r) == 0 {
		return nil, fmt.Errorf("no certificates issued by CA %s found in Command.  At least 1 must exist in order to retreive the CA or CA chain certificate(s)", caName)
	}

	return r, nil
}

func fetchChainAndCAForCert(ctx context.Context, req *logical.Request, b *keyfactorBackend, kfCertId int) ([]string, string, error) {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, "", err
	}
	if config == nil {
		return nil, "", errors.New("unable to load configuration")
	}

	// get the client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("unable to create the http client")
	}
	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	client.httpClient.CloseIdleConnections()

	// Build request
	reqUrl := config.KeyfactorUrl + "/" + config.CommandAPIPath + "/Certificates/Download"
	b.Logger().Debug("url: " + reqUrl)
	bodyContent := fmt.Sprintf(`{"CertID": %d, "IncludeChain": true, "ChainOrder": "endentityfirst" }`, kfCertId)
	payload := strings.NewReader(bodyContent)
	b.Logger().Debug("body: " + bodyContent)
	httpReq, err := http.NewRequest("POST", reqUrl, payload)
	if err != nil {
		b.Logger().Info("Error forming request: %s", err)
	}
	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("x-certificateformat", "P7B")

	// Send request and check status
	b.Logger().Debug("About to connect to " + config.KeyfactorUrl + "for cert retrieval")
	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Info(fmt.Sprintf("failed getting cert: %s", err))
		return nil, "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("request failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Error("Error response = " + fmt.Sprint(res.Body))
		return nil, "", fmt.Errorf("error downloading certificate. returned status = %d\n ", res.StatusCode)
	}

	// Read response and return certificate and key
	defer res.Body.Close()
	// Parse response

	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: %s", err)
		return nil, "", err
	}
	var r KeyfactorCertDownloadResponse
	json.Unmarshal(body, &r)
	b.Logger().Debug("response = ", r)

	certs, p7bErr := ConvertBase64P7BtoCertificates(r.Content)
	if p7bErr != nil {
		return nil, "", p7bErr
	}

	// first cert is leaf, next cert is CA,  remaining certs are chain
	ca_chain := certs[1:]
	ca_cert := certs[1]

	b.Logger().Trace(fmt.Sprintf("the chain contains %d certs", len(ca_chain)))

	var ca_chain_pem []string
	var ca_pem string

	// Encode each certificate found in the PKCS#7 structure into PEM format.
	for _, cert := range ca_chain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemEncoded := pem.EncodeToMemory(pemBlock)
		ca_chain_pem = append(ca_chain_pem, string(pemEncoded))
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca_cert.Raw,
	}
	caPemEncoded := pem.EncodeToMemory(pemBlock)
	ca_pem = string(caPemEncoded)

	return ca_chain_pem, ca_pem, nil
}

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

// ConvertBase64P7BtoCertificates takes a base64 encoded P7B certificate string and returns a slice of *x509.Certificate.
func ConvertBase64P7BtoCertificates(base64P7B string) ([]*x509.Certificate, error) {
	// Decode the base64 string to a byte slice.
	decodedBytes, err := base64.StdEncoding.DecodeString(base64P7B)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 string: %w", err)
	}

	// Parse the PKCS#7 structure.
	p7, err := pkcs7.Parse(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKCS#7 data: %w", err)
	}

	// Return the certificates.
	return p7.Certificates, nil
}

func ConvertBase64P7BtoPEM(base64P7B string) ([]string, error) {
	// Decode the base64 string to a byte slice.
	decodedBytes, err := base64.StdEncoding.DecodeString(base64P7B)
	if err != nil {
		return []string{}, fmt.Errorf("error decoding base64 string: %w", err)
	}

	// Parse the PKCS#7 structure.
	p7, err := pkcs7.Parse(decodedBytes)

	if err != nil {
		return []string{}, fmt.Errorf("error parsing PKCS#7 data: %w", err)
	}

	// Initialize an empty string to append the PEM encoded certificates.
	var pemEncodedCerts []string

	// Encode each certificate found in the PKCS#7 structure into PEM format.
	for _, cert := range p7.Certificates {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemEncoded := pem.EncodeToMemory(pemBlock)
		pemEncodedCerts = append(pemEncodedCerts, string(pemEncoded))
	}

	return pemEncodedCerts, nil
}

type KeyfactorCertResponse []struct {
	ID                       int              `json:"Id"`
	Thumbprint               string           `json:"Thumbprint"`
	SerialNumber             string           `json:"SerialNumber"`
	IssuedDN                 string           `json:"IssuedDN"`
	IssuedCN                 string           `json:"IssuedCN"`
	ImportDate               time.Time        `json:"ImportDate"`
	NotBefore                time.Time        `json:"NotBefore"`
	NotAfter                 time.Time        `json:"NotAfter"`
	IssuerDN                 string           `json:"IssuerDN"`
	PrincipalID              interface{}      `json:"PrincipalId"`
	TemplateID               interface{}      `json:"TemplateId"`
	CertState                int              `json:"CertState"`
	KeySizeInBits            int              `json:"KeySizeInBits"`
	KeyType                  int              `json:"KeyType"`
	RequesterID              int              `json:"RequesterId"`
	IssuedOU                 interface{}      `json:"IssuedOU"`
	IssuedEmail              interface{}      `json:"IssuedEmail"`
	KeyUsage                 int              `json:"KeyUsage"`
	SigningAlgorithm         string           `json:"SigningAlgorithm"`
	CertStateString          string           `json:"CertStateString"`
	KeyTypeString            string           `json:"KeyTypeString"`
	RevocationEffDate        interface{}      `json:"RevocationEffDate"`
	RevocationReason         interface{}      `json:"RevocationReason"`
	RevocationComment        interface{}      `json:"RevocationComment"`
	CertificateAuthorityID   int              `json:"CertificateAuthorityId"`
	CertificateAuthorityName string           `json:"CertificateAuthorityName"`
	TemplateName             interface{}      `json:"TemplateName"`
	ArchivedKey              bool             `json:"ArchivedKey"`
	HasPrivateKey            bool             `json:"HasPrivateKey"`
	PrincipalName            interface{}      `json:"PrincipalName"`
	CertRequestID            interface{}      `json:"CertRequestId"`
	RequesterName            string           `json:"RequesterName"`
	ContentBytes             string           `json:"ContentBytes"`
	ExtendedKeyUsages        []interface{}    `json:"ExtendedKeyUsages"`
	SubjectAltNameElements   []interface{}    `json:"SubjectAltNameElements"`
	CRLDistributionPoints    []interface{}    `json:"CRLDistributionPoints"`
	LocationsCount           []interface{}    `json:"LocationsCount"`
	SSLLocations             []interface{}    `json:"SSLLocations"`
	Locations                []interface{}    `json:"Locations"`
	Metadata                 Metadata         `json:"Metadata"`
	CertificateKeyID         int              `json:"CertificateKeyId"`
	CARowIndex               int              `json:"CARowIndex"`
	DetailedKeyUsage         DetailedKeyUsage `json:"DetailedKeyUsage"`
	KeyRecoverable           bool             `json:"KeyRecoverable"`
}
type Metadata struct {
}
type DetailedKeyUsage struct {
	CrlSign          bool   `json:"CrlSign"`
	DataEncipherment bool   `json:"DataEncipherment"`
	DecipherOnly     bool   `json:"DecipherOnly"`
	DigitalSignature bool   `json:"DigitalSignature"`
	EncipherOnly     bool   `json:"EncipherOnly"`
	KeyAgreement     bool   `json:"KeyAgreement"`
	KeyCertSign      bool   `json:"KeyCertSign"`
	KeyEncipherment  bool   `json:"KeyEncipherment"`
	NonRepudiation   bool   `json:"NonRepudiation"`
	HexCode          string `json:"HexCode"`
}

type KeyfactorCertDownloadResponse struct {
	Content string `json:"Content"`
}
