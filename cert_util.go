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
	"crypto/sha1"
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
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// fetch the CA info from keyfactor
func fetchCAInfo(ctx context.Context, req *logical.Request, b *keyfactorBackend) (response *logical.Response, retErr error) {
	// first we see if we have previously retreived the CA or chain
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	caEntry, err := req.Storage.Get(ctx, "ca")

	if err != nil {
		return logical.ErrorResponse("error fetching ca: %s", err), nil
	}

	if caEntry != nil {
		var r map[string]interface{}
		json.Unmarshal(caEntry.Value, &r)
		b.Logger().Debug("stored ca = ", r)

		resp := &logical.Response{
			Data: r,
		}
		return resp, nil
	}

	// if not, we retreive the CA entry from the "CertificateAuthorities" endpoint

	// then we look up certs with CertificateAuthorityId = the CA ID.

	// if at least one exists, we download the cert and chain

	// if not; we can't get it yet; return appropriate error

	caId, err := getCAId(ctx, req, b)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error getting CA ID from Keyfactor: %s", err)}
	}

	// with the certificate Id, we can retreive and store the CA certificate from Keyfactor

	caCert, err := fetchCertFromKeyfactor(ctx, req, b, caId, false)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error getting certificate from Keyfactor: %s", err)}
	}

	certBytes, _ := base64.StdEncoding.DecodeString(caCert)
	certString := string(certBytes[:])
	caStorageEntry, err := logical.StorageEntryJSON("ca/", certString)
	if err != nil {
		b.Logger().Error("error creating ca entry", err)
	}

	err = req.Storage.Put(ctx, caStorageEntry)
	if err != nil {
		b.Logger().Error("error storing the ca locally", err)
	}

	cn := config.CertAuthority
	resp := &logical.Response{
		Data: map[string]interface{}{
			cn: certString,
		},
	}

	return resp, nil
}

func fetchCaChainInfo(ctx context.Context, req *logical.Request, b *keyfactorBackend) (response *logical.Response, retErr error) {
	// first we see if we have previously retreived the CA or chain
	caEntry, err := req.Storage.Get(ctx, "ca_chain")
	if err != nil {
		return logical.ErrorResponse("error fetching ca_chain: %s", err), nil
	}
	if caEntry != nil {
		var r map[string]interface{}
		json.Unmarshal(caEntry.Value, &r)
		b.Logger().Debug("caChainEntry.Value = ", r)

		resp := &logical.Response{
			Data: r,
		}
		return resp, nil
	}

	// if not we search certs for 'CA -eq "keyfactor-KFTRAIN-CA" AND CertState -eq "6"'
	//

	caId, err := getCAId(ctx, req, b)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error getting CA ID from Keyfactor: %s", err)}
	}

	// with the certificate Id, we can retreive and store the CA certificate from Keyfactor

	caCert, err := fetchCertFromKeyfactor(ctx, req, b, caId, true)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error getting certificate from Keyfactor: %s", err)}
	}

	certBytes, _ := base64.StdEncoding.DecodeString(caCert)
	certString := string(certBytes[:])
	caStorageEntry, err := logical.StorageEntryJSON("ca_chain/", certString)
	if err != nil {
		b.Logger().Error("error creating ca entry", err)
	}

	err = req.Storage.Put(ctx, caStorageEntry)
	if err != nil {
		b.Logger().Error("error storing the ca locally", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"CA_CHAIN": certString,
		},
	}

	return resp, nil
}

func getCAId(ctx context.Context, req *logical.Request, b *keyfactorBackend) (string, error) {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return "", err
	}
	if config == nil {
		return "", errors.New("unable to load configuration")
	}

	if config.CertAuthority == "" {
		b.Logger().Error("no value in config for CA.")
		return "", nil
	}

	ca_name := strings.Split(config.CertAuthority, `\\`)[1]

	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("unable to create the http client")
	}
	client.httpClient.CloseIdleConnections()

	ca_name = url.QueryEscape(ca_name)

	//creds := config.Username + ":" + config.Password
	//encCreds := b64.StdEncoding.EncodeToString([]byte(creds))

	// Build request

	url := config.KeyfactorUrl + "/" + config.CommandAPIPath + "/Certificates?pq.queryString=CA%20-eq%20%22" + ca_name + "%22%20AND%20CertState%20-eq%20%226%22" // CertState 6 = cert
	b.Logger().Debug("url: " + url)
	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		b.Logger().Info("Error forming request: {{err}}", err)
	}
	//httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("x-keyfactor-api-version", "1")
	//httpReq.Header.Add("authorization", "Basic "+encCreds)

	// Send request and check status
	b.Logger().Debug("About to connect to " + config.KeyfactorUrl + "for ca retrieval")
	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("failed getting CA: {{err}}", err)
		return "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("request failed: server returned" + fmt.Sprint(res.StatusCode))
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			b.Logger().Info("Error reading response: {{err}}", err)
			return "", err
		}
		b.Logger().Error("Error response = " + fmt.Sprint(body))
		return "", fmt.Errorf("error querying certificates for CA. returned status = %d\n ", res.StatusCode)
	}

	// Read response and return certificate and key
	defer res.Body.Close()

	// Parse response
	var r KeyfactorCertResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		panic(err)
	}
	b.Logger().Debug("response = ", r)

	return fmt.Sprintf("%d", r[0].ID), nil
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

func fetchCertFromKeyfactor(ctx context.Context, req *logical.Request, b *keyfactorBackend, kfCertId string, includeChain bool) (string, error) {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return "", err
	}
	if config == nil {
		return "", errors.New("unable to load configuration")
	}

	// get the client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("unable to create the http client")
	}
	// This is only needed when running as a vault extension
	b.Logger().Debug("Closing idle connections")
	client.httpClient.CloseIdleConnections()

	include := "false"
	if includeChain {
		include = "true"
	}

	// Build request
	url := config.KeyfactorUrl + "Certificates/Download"
	b.Logger().Debug("url: " + url)
	bodyContent := fmt.Sprintf(`{"CertID": %s, "IncludeChain": %s }`, kfCertId, include)
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
	b.Logger().Debug("About to connect to " + config.KeyfactorUrl + "for cert retrieval")
	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Info("failed getting cert: {{err}}", err)
		return "", err
	}
	if res.StatusCode != 200 {
		b.Logger().Error("request failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Error("Error response = " + fmt.Sprint(res.Body))
		return "", fmt.Errorf("error downloading certificate. returned status = %d\n ", res.StatusCode)
	}

	// Read response and return certificate and key
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.Logger().Info("Error reading response: {{err}}", err)
		return "", err
	}

	// Parse response
	var r KeyfactorCertDownloadResponse
	json.Unmarshal(body, &r)
	b.Logger().Debug("response = ", r)

	return r.Content, nil

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

func parseOtherSANs(others []string) (map[string][]string, error) {
	result := map[string][]string{}
	for _, other := range others {
		splitOther := strings.SplitN(other, ";", 2)
		if len(splitOther) != 2 {
			return nil, fmt.Errorf("expected a semicolon in other SAN %q", other)
		}
		splitType := strings.SplitN(splitOther[1], ":", 2)
		if len(splitType) != 2 {
			return nil, fmt.Errorf("expected a colon in other SAN %q", other)
		}
		switch {
		case strings.EqualFold(splitType[0], "utf8"):
		case strings.EqualFold(splitType[0], "utf-8"):
		default:
			return nil, fmt.Errorf("only utf8 other SANs are supported; found non-supported type in other SAN %q", other)
		}
		result[splitOther[0]] = append(result[splitOther[0]], splitType[1])
	}

	return result, nil
}

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

// ensureCorrectOrder ensures the correct order of the certificate chain using a known leaf thumbprint
func ensureCorrectOrder(chain []*x509.Certificate, leafThumbprint string) []*x509.Certificate {
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	var root *x509.Certificate

	// Identify the leaf, intermediate(s), and root
	for _, cert := range chain {
		if cert.CheckSignatureFrom(cert) == nil {
			root = cert // Verified self-signed root
		} else if getCertThumbprint(cert) == leafThumbprint {
			leaf = cert
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	// Sort intermediates by issuer-subject relationship
	sortedIntermediates := make([]*x509.Certificate, 0, len(intermediates))
	remaining := append([]*x509.Certificate{}, intermediates...)

	for len(remaining) > 0 {
		for i, cert := range remaining {
			if len(sortedIntermediates) == 0 || sortedIntermediates[len(sortedIntermediates)-1].Subject.String() == cert.Issuer.String() {
				sortedIntermediates = append(sortedIntermediates, cert)
				remaining = append(remaining[:i], remaining[i+1:]...)
				break
			}
		}
	}

	// Construct ordered chain
	orderedChain := []*x509.Certificate{leaf}
	orderedChain = append(orderedChain, sortedIntermediates...)
	if root != nil {
		orderedChain = append(orderedChain, root)
	}
	return orderedChain
}

// getCertThumbprint computes the SHA-1 thumbprint of a certificate
func getCertThumbprint(cert *x509.Certificate) string {
	hash := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", hash)
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
