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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const kf_revoke_path = "/Certificates/Revoke"

type revocationInfo struct {
	CertificateBytes  []byte    `json:"certificate_bytes"`
	RevocationTime    int64     `json:"revocation_time"`
	RevocationTimeUTC time.Time `json:"revocation_time_utc"`
}

func pathCerts(b *keyfactorBackend) []*framework.Path {

	return []*framework.Path{
		{ // certs list
			Pattern: "certs/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathFetchCertList,
			},

			HelpSynopsis:    pathFetchListHelpSyn,
			HelpDescription: pathFetchListHelpDesc,
		},
		{ // issue
			Pattern: "issue/" + framework.GenericNameRegex("role"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathIssue,
			},

			HelpSynopsis:    pathIssueHelpSyn,
			HelpDescription: pathIssueHelpDesc,
			Fields:          addNonCACommonFields(map[string]*framework.FieldSchema{}),
		},
		{ // sign
			Pattern: "sign/" + framework.GenericNameRegex("role"),

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathSign,
			},

			HelpSynopsis:    pathSignHelpSyn,
			HelpDescription: pathSignHelpDesc,
			Fields: addNonCACommonFields(map[string]*framework.FieldSchema{
				"csr": {
					Type:        framework.TypeString,
					Default:     "",
					Description: `PEM-format CSR to be signed.`,
					Required:    true,
				}}),
		},
		{ // fetch cert
			Pattern: `certs/(?P<serial>[0-9A-Fa-f-:]+)`,
			Fields: map[string]*framework.FieldSchema{
				"serial": {
					Type: framework.TypeString,
					Description: `Certificate serial number, in colon- or
		hyphen-separated octal`,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathFetchCert,
			},

			HelpSynopsis:    pathFetchHelpSyn,
			HelpDescription: pathFetchHelpDesc,
		},
		{ // revoke
			Pattern: `revoke/?$`,

			Fields: map[string]*framework.FieldSchema{
				"serial": {
					Type:        framework.TypeString,
					Description: `The serial number of the certificate to revoke`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRevokeCert,
				logical.CreateOperation: b.pathRevokeCert,
			},

			HelpSynopsis:    pathRevokeHelpSyn,
			HelpDescription: pathRevokeHelpDesc,
		},
	}
}

func (b *keyfactorBackend) pathFetchCertList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *keyfactorBackend) pathFetchCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	var serial, contentType string
	var certEntry, revokedEntry *logical.StorageEntry
	var funcErr error
	var certificate string
	var revocationTime int64
	response = &logical.Response{
		Data: map[string]interface{}{},
	}

	// Some of these need to return raw and some non-raw;
	// this is basically handled by setting contentType or not.
	// Errors don't cause an immediate exit, because the raw
	// paths still need to return raw output.

	b.Logger().Debug("fetching cert, path = " + req.Path)

	serial = data.Get("serial").(string)

	if len(serial) == 0 {
		response = logical.ErrorResponse("The serial number must be provided")
		goto reply
	}

	b.Logger().Debug("fetching certificate; serial = " + serial)

	certEntry, funcErr = fetchCertBySerial(ctx, req, req.Path, serial)
	if funcErr != nil {
		switch funcErr.(type) {
		case errutil.UserError:
			response = logical.ErrorResponse(funcErr.Error())
			goto reply
		case errutil.InternalError:
			retErr = funcErr
			goto reply
		}
	}
	if certEntry == nil {
		response = nil
		goto reply
	}

	b.Logger().Debug("fetched certEntry.Value = ", certEntry.Value)

	certificate = string(certEntry.Value)
	revokedEntry, funcErr = fetchCertBySerial(ctx, req, "revoked/", serial)
	if funcErr != nil {
		switch funcErr.(type) {
		case errutil.UserError:
			response = logical.ErrorResponse(funcErr.Error())
			goto reply
		case errutil.InternalError:
			retErr = funcErr
			goto reply
		}
	}
	if revokedEntry != nil {
		var revInfo revocationInfo
		err := revokedEntry.DecodeJSON(&revInfo)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error decoding revocation entry for serial %s: %s", serial, err)), nil
		}
		revocationTime = revInfo.RevocationTime
	}

reply:
	switch {
	case len(contentType) != 0:
		response = &logical.Response{
			Data: map[string]interface{}{
				logical.HTTPContentType: contentType,
				logical.HTTPRawBody:     certificate,
			}}
		if retErr != nil {
			if b.Logger().IsWarn() {
				b.Logger().Warn("possible error, but cannot return in raw response. Note that an empty CA probably means none was configured, and an empty CRL is possibly correct", "error", retErr)
			}
		}
		retErr = nil
		if len(certificate) > 0 {
			response.Data[logical.HTTPStatusCode] = 200
		} else {
			response.Data[logical.HTTPStatusCode] = 204
		}
	case retErr != nil:
		response = nil
		return
	case response == nil:
		return
	case response.IsError():
		return response, nil
	default:
		response.Data["certificate"] = string(certificate)
		response.Data["revocation_time"] = revocationTime
	}

	return
}

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *keyfactorBackend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	b.Logger().Debug(fmt.Sprintf("got role name of %s", roleName))

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	if role.KeyType == "any" {
		return logical.ErrorResponse("role key type \"any\" not allowed for issuing certificates, only signing"), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role, roleName)
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *keyfactorBackend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	csr := data.Get("csr").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	if !role.NoStore && b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	var err_resp error
	var valid bool

	arg, _ := json.Marshal(req.Data)
	b.Logger().Debug(string(arg))

	// validate DNS SANS (optional)
	var dns_sans []string
	b.Logger().Debug("parsing dns_sans...")
	dns_sans_string, ok := data.GetOk("dns_sans")

	if ok && dns_sans_string != nil && dns_sans_string == "" {
		dns_sans_string = dns_sans_string.(string)
		dns_sans = strings.Split(dns_sans_string.(string), ",")
		b.Logger().Debug(fmt.Sprintf("dns_sans = %s", dns_sans))

		b.Logger().Trace("checking to make sure all DNS SANs are allowed by role..")

		// check the provided DNS sans against allowed domains
		valid, err_resp = checkAllowedDomains(role, roleName, dns_sans)
		if err_resp != nil && !valid {
			b.Logger().Error(err_resp.Error())
			return logical.ErrorResponse("DNS_SAN(s) not allowed for role: %s", err_resp.Error()), err_resp
		}
	} else {
		b.Logger().Debug("no DNS SANs provided")
	}

	// ip sans (optional)
	var ip_sans []string
	b.Logger().Debug("parsing ip_sans...")
	ip_sans_string, ok := data.GetOk("ip_sans")

	if ok && ip_sans_string != nil && ip_sans_string.(string) != "" {
		b.Logger().Trace(fmt.Sprintf("passed ip_sans: %s", ip_sans_string.(string)))
		ip_sans = strings.Split(ip_sans_string.(string), ",")
	} else {
		b.Logger().Debug("no IP SANs provided")
	}

	// get the CA name
	b.Logger().Debug("parsing ca...")
	caName := data.Get("ca").(string)
	if caName == "" {
		b.Logger().Debug("no ca passed, retreiving from config")
		caName = b.cachedConfig.CertAuthority
	}
	if caName == "" {
		return logical.ErrorResponse("no certificate authority was provided and there is no configuration entry for ca"), fmt.Errorf("CA name is required")
	}
	b.Logger().Debug(fmt.Sprintf("ca name = %s", caName))

	// get the template name
	b.Logger().Debug("parsing template name...")
	templateName := data.Get("template").(string)
	if templateName == "" {
		b.Logger().Debug("no template name in parameters, retrieving from config")
		templateName = b.cachedConfig.CertTemplate
		if templateName == "" {
			return logical.ErrorResponse("no certificate template name was provided and there is no configuration entry for 'template'"), fmt.Errorf("template name is required")
		}
	}
	b.Logger().Debug(fmt.Sprintf("template name: %s", templateName))

	//check role permissions

	metadata := data.Get("metadata").(string)

	if metadata == "" {
		metadata = "{}"
	}

	// verify that any passed metadata string is valid JSON

	if !b.isValidJSON(metadata) {
		err_resp := fmt.Errorf("'%s' is not a valid JSON string", metadata)
		b.Logger().Error(err_resp.Error())
	}

	if err_resp != nil {
		return nil, err_resp
	}

	certs, serial, errr := b.submitCSR(ctx, req, csr, caName, templateName, dns_sans, ip_sans, metadata)

	if errr != nil {
		return nil, fmt.Errorf("could not sign csr: %s", errr)
	}
	response := &logical.Response{
		Data: map[string]interface{}{
			"certificate":   certs[0],
			"issuing_ca":    certs[1],
			"serial_number": serial,
		},
	}

	return response, nil
}

func (b *keyfactorBackend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry, roleName string) (*logical.Response, error) {
	// If storing the certificate and on a performance standby, forward this request on to the primary
	if !role.NoStore && b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	var ip_sans []string
	var dns_sans []string
	var err_resp error
	var valid bool

	arg, _ := json.Marshal(req.Data)
	b.Logger().Debug(string(arg))

	// validate Common Name (required)
	b.Logger().Debug("parsing common_name...")
	cn, ok := data.GetOk("common_name")

	if !ok || cn == nil || cn.(string) == "" {
		return nil, fmt.Errorf("common_name must be provided to issue certificate")
	}
	cn = cn.(string)

	b.Logger().Debug(fmt.Sprintf("common_name = %s", cn))

	// check to make sure common name is allowed by role
	b.Logger().Trace("checking common name" + cn.(string))
	valid, err_resp = checkAllowedDomains(role, roleName, []string{cn.(string)})

	if err_resp != nil && !valid {
		b.Logger().Error(err_resp.Error())
		return logical.ErrorResponse("disallowed common name was provided: %s", err_resp.Error()), err_resp
	}

	// validate DNS SANS (required)
	b.Logger().Debug("parsing dns_sans...")
	dns_sans_string, ok := data.GetOk("dns_sans")

	if !ok || dns_sans_string == nil || dns_sans_string == "" {
		return nil, fmt.Errorf("dns_sans must be provided to issue certificate")
	}
	dns_sans_string = dns_sans_string.(string)
	dns_sans = strings.Split(dns_sans_string.(string), ",")

	b.Logger().Debug(fmt.Sprintf("dns_sans = %s", dns_sans))

	cnMatch := false

	// make sure at least one DNS SAN matches the common name
	for u := range dns_sans {
		if cnMatch {
			break
		} // no need to check the rest if there was a match.
		cnMatch = dns_sans[u] == cn.(string)
	}

	if !cnMatch {
		err_resp = fmt.Errorf("at least one DNS SAN is required to match the supplied Common Name for RFC 2818 compliance")
		b.Logger().Error(err_resp.Error())
		return logical.ErrorResponse(err_resp.Error()), err_resp
	}

	b.Logger().Trace("checking to make sure all DNS SANs are allowed by role..")

	// check the provided DNS sans against allowed domains
	valid, err_resp = checkAllowedDomains(role, roleName, dns_sans)
	if err_resp != nil && !valid {
		b.Logger().Error(err_resp.Error())
		return logical.ErrorResponse("DNS_SAN(s) not allowed for role: %s", err_resp.Error()), err_resp
	}

	// ip sans (optional)
	b.Logger().Debug("parsing ip_sans...")
	ip_sans_string, ok := data.GetOk("ip_sans")
	if ok && ip_sans_string != nil && ip_sans_string.(string) != "" {
		ip_sans = strings.Split(ip_sans_string.(string), ",")
	}

	// get the CA name
	b.Logger().Debug("parsing ca...")
	caName := data.Get("ca").(string)
	if caName == "" {
		b.Logger().Debug("no ca passed, retreiving from config")
		caName = b.cachedConfig.CertAuthority
	}
	if caName == "" {
		return logical.ErrorResponse("no certificate authority was provided and there is no configuration entry for ca"), fmt.Errorf("CA name is required")
	}
	b.Logger().Debug(fmt.Sprintf("ca name = %s", caName))

	// get the template name
	b.Logger().Debug("parsing template name...")
	templateName := data.Get("template").(string)
	if templateName == "" {
		b.Logger().Debug("no template name in parameters, retrieving from config")
		templateName = b.cachedConfig.CertTemplate
	}
	b.Logger().Debug(fmt.Sprintf("template name: %s", templateName))

	//check role permissions

	metadata := data.Get("metadata").(string)

	if metadata == "" {
		metadata = "{}"
	}

	// verify that any passed metadata string is valid JSON

	if !b.isValidJSON(metadata) {
		err_resp := fmt.Errorf("'%s' is not a valid JSON string", metadata)
		b.Logger().Error(err_resp.Error())
	}

	if err_resp != nil {
		return nil, err_resp
	}

	//generate and submit CSR
	b.Logger().Debug("generating the CSR...")
	csr, key := b.generateCSR(cn.(string), ip_sans, dns_sans)
	certs, serial, errr := b.submitCSR(ctx, req, csr, caName, templateName, dns_sans, ip_sans, metadata)

	if errr != nil {
		return nil, fmt.Errorf("could not enroll certificate: %s", errr)
	}

	// Conform response to Vault PKI API
	response := &logical.Response{
		Data: map[string]interface{}{
			"certificate":      certs[0],
			"issuing_ca":       certs[1],
			"private_key":      "-----BEGIN RSA PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(key) + "\n-----END RSA PRIVATE KEY-----",
			"private_key_type": "rsa",
			"revocation_time":  0,
			"serial_number":    serial,
		},
	}

	return response, nil
}

func (b *keyfactorBackend) pathRevokeCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	serial := data.Get("serial").(string)
	b.Logger().Debug("serial = " + serial)

	if len(serial) == 0 {
		return logical.ErrorResponse("the serial number must be provided"), fmt.Errorf("the serial number must be provided")
	}

	// We store and identify by lowercase colon-separated hex, but other
	// utilities use dashes and/or uppercase, so normalize
	serial = strings.Replace(strings.ToLower(serial), "-", ":", -1)

	return revokeCert(ctx, b, req, serial, false)
}

// Revokes a cert, and tries to be smart about error recovery
func revokeCert(ctx context.Context, b *keyfactorBackend, req *logical.Request, serial string, fromLease bool) (*logical.Response, error) {
	if b.System().Tainted() {
		return nil, nil
	}

	// get client
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	b.Logger().Debug("Closing idle connections")
	client.httpClient.CloseIdleConnections()

	kfId, err := req.Storage.Get(ctx, "kfId/"+serial) //retrieve the keyfactor certificate ID, keyed by sn here
	if err != nil {
		b.Logger().Error("Unable to retreive Keyfactor certificate ID for cert with serial: "+serial, err)
		return nil, err
	}

	var keyfactorId int
	err = kfId.DecodeJSON(&keyfactorId)

	if err != nil {
		b.Logger().Error("Unable to parse stored certificate ID for cert with serial: "+serial, err)
		return nil, err
	}

	// set up keyfactor api request
	url := b.cachedConfig.KeyfactorUrl + "/" + b.cachedConfig.CommandAPIPath + kf_revoke_path
	payload := fmt.Sprintf(`{
		"CertificateIds": [
		  %d
		],
		"Reason": 0,
		"Comment": "%s",
		"EffectiveDate": "%s"},
		"CollectionId": 0
	  }`, keyfactorId, "via HashiCorp Vault", time.Now().Format(time.RFC3339))
	b.Logger().Debug("Sending revocation request.  payload =  " + payload)
	httpReq, _ := http.NewRequest("POST", url, strings.NewReader(payload))

	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")

	res, err := client.httpClient.Do(httpReq)
	if err != nil {
		b.Logger().Error("Revoke failed: {{err}}", err)
		return nil, err
	}
	r, _ := io.ReadAll(res.Body)

	b.Logger().Debug("response received.  Status code " + fmt.Sprint(res.StatusCode) + " response body: \n " + string(r[:]))
	if res.StatusCode != 204 && res.StatusCode != 200 {
		b.Logger().Info("revocation failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Info("error response = " + string(r[:]))
		return nil, fmt.Errorf("revocation failed: server returned  %s\n ", res.Status)
	}

	defer res.Body.Close()

	alreadyRevoked := false
	var revInfo revocationInfo

	revEntry, err := fetchCertBySerial(ctx, req, "revoked/", serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}
	if revEntry != nil {
		// Set the revocation info to the existing values
		alreadyRevoked = true
		err = revEntry.DecodeJSON(&revInfo)
		if err != nil {
			return nil, fmt.Errorf("error decoding existing revocation info")
		}
	}

	if !alreadyRevoked {
		certEntry, err := fetchCertBySerial(ctx, req, "certs/", serial)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(err.Error()), nil
			case errutil.InternalError:
				return nil, err
			}
		}
		if certEntry == nil {
			if fromLease {
				// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
				// and there's no reason to expect this will work on a subsequent
				// retry.  Just give up and let the lease get deleted.
				b.Logger().Warn("expired certificate revoke failed because not found in storage, treating as success", "serial", serial)
				return nil, nil
			}
			return logical.ErrorResponse(fmt.Sprintf("certificate with serial %s not found", serial)), nil
		}
		b.Logger().Debug("certEntry key = " + certEntry.Key)
		b.Logger().Debug("certEntry value = " + string(certEntry.Value))

		currTime := time.Now()
		revInfo.CertificateBytes = certEntry.Value
		revInfo.RevocationTime = currTime.Unix()
		revInfo.RevocationTimeUTC = currTime.UTC()

		revEntry, err = logical.StorageEntryJSON("revoked/"+normalizeSerial(serial), revInfo)
		if err != nil {
			return nil, fmt.Errorf("error creating revocation entry")
		}

		err = req.Storage.Put(ctx, revEntry)
		if err != nil {
			return nil, fmt.Errorf("error saving revoked certificate to new location")
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"revocation_time": revInfo.RevocationTime,
		},
	}
	if !revInfo.RevocationTimeUTC.IsZero() {
		resp.Data["revocation_time_rfc3339"] = revInfo.RevocationTimeUTC.Format(time.RFC3339)
	}
	return resp, nil
}

func checkAllowedDomains(role *roleEntry, roleName string, domains []string) (bool, error) {
	//check role permissions
	var err_resp error
	var valid bool
	var hasSuffix bool
	var disallowed []string

	// check the allowed domains for a match.
	// if allowed_domains is '*', allow any domain

	for _, d := range domains {
		for _, v := range role.AllowedDomains {
			if v == "*" || strings.HasSuffix(d, v) { // if it has the suffix..
				hasSuffix = true
				if d == v || role.AllowSubdomains { // and there is an exact match, or subdomains are allowed..
					valid = true // then it is valid
				} else {
					valid = false
					disallowed = append(disallowed, d)
				}
			}
		}
	}
	if !valid {
		var disallowed_domains = strings.Join(disallowed, ",")
		var allowed_domains = strings.Join(role.AllowedDomains, ",")
		err_resp = fmt.Errorf("domain name not allowed for role: %s.  \n allowed domains for %s are: %s", disallowed_domains, roleName, allowed_domains)
	}
	if !valid && hasSuffix {
		err_resp = fmt.Errorf("sub-domains are not allowed for role %s", roleName)
	}

	if err_resp != nil {
		return false, err_resp
	}

	return true, nil
}

func (b *keyfactorBackend) isValidJSON(str string) bool {
	var js json.RawMessage
	err := json.Unmarshal([]byte(str), &js)
	if err != nil {
		b.Logger().Debug(err.Error())
		return false
	} else {
		b.Logger().Debug("the metadata was able to be parsed as valid JSON")
		return true
	}
}

const pathIssueHelpSyn = `
Request a certificate using a certain role with the provided details.
example: vault write keyfactor/issue/<role> common_name=<cn> dns_sans=<dns sans>
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given role. The certificate will only be issued if the
requested details are allowed by the role policy.

This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
sign path instead.
`

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
example: vault write keyfactor/sign/<role> csr=<csr>
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.

This path requires a CSR; if you want Vault to generate a private key
for you, use the issue path instead.

Note: the CSR must contain at least one DNS SANs entry.
`

const pathFetchHelpSyn = `
Fetch a CA, CRL, CA Chain, or non-revoked certificate.
`

const pathFetchHelpDesc = `
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
Using "ca_chain" as the value fetches the certificate authority trust chain in PEM encoding.
`

const pathFetchListHelpSyn = `
List all of the certificates managed by this secrets engine.
`

const pathFetchListHelpDesc = `
Use with the "list" command to display the list of certificate serial numbers for certificates managed by this secrets engine.
`

const pathRevokeHelpSyn = `
Revoke a certificate by serial number.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoked using its serial number. A root token is required.
`
