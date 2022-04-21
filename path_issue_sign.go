package keyfactor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathIssue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIssue,
		},

		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathSign(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSign,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
		Required:    true,
	}

	return ret
}

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *backend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

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

	return b.pathIssueSignCert(ctx, req, data, role)
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	certs, serial, errr := b.submitCSR(ctx, req, csr)

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

func (b *backend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
	// If storing the certificate and on a performance standby, forward this request on to the primary
	if !role.NoStore && b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	arg, _ := json.Marshal(req.Data)
	b.Logger().Debug(string(arg))
	cn := ""
	var ip_sans []string
	var dns_sans []string

	// Get and validate subject info from Vault command
	for k, v := range req.Data {
		if k == "common_name" {
			cn = v.(string)
		}
		if k == "ip_sans" { // TODO - type switch
			ip_sans = strings.Split(v.(string), ",")
		}
		if k == "dns_sans" { // TODO - type switch
			dns_sans = strings.Split(v.(string), ",")
		}
	}

	if cn == "" {
		return nil, fmt.Errorf("common_name must be provided to issue certificate")
	}

	var err_resp error

	if strings.Contains(cn, role.AllowedBaseDomain) && !role.AllowSubdomains {
		err_resp = fmt.Errorf("sub-domains not allowed for role")
	}

	if role.AllowedBaseDomain == cn {
		err_resp = fmt.Errorf("common name not allowed for provided role")
	}

	if err_resp != nil {
		return nil, err_resp
	}

	for u := range dns_sans {
		if !strings.Contains(dns_sans[u], role.AllowedBaseDomain) || strings.Contains(dns_sans[u], role.AllowedBaseDomain) && !role.AllowSubdomains {
			return nil, fmt.Errorf("Subject Alternative Name " + dns_sans[u] + " not allowed for provided role")
		}
	}

	csr, key := b.generateCSR(cn, ip_sans, dns_sans)
	certs, serial, errr := b.submitCSR(ctx, req, csr)

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

	// input := &inputBundle{
	// 	req:     req,
	// 	apiData: data,
	// 	role:    role,
	// }
	// var parsedBundle *certutil.ParsedCertBundle
	// var err error
	// if useCSR {
	// 	parsedBundle, err = b.generateCSR(cn, ip_sans, dns_sans)(b, input, signingBundle, false, useCSRValues)
	// } else {
	// 	parsedBundle, err = generateCert(ctx, b, input, signingBundle, false)
	// }
	// if err != nil {
	// 	switch err.(type) {
	// 	case errutil.UserError:
	// 		return logical.ErrorResponse(err.Error()), nil
	// 	case errutil.InternalError:
	// 		return nil, err
	// 	default:
	// 		return nil, errwrap.Wrapf("error signing/generating certificate: {{err}}", err)
	// 	}
	// }

	// signingCB, err := signingBundle.ToCertBundle()
	// if err != nil {
	// 	return nil, errwrap.Wrapf("error converting raw signing bundle to cert bundle: {{err}}", err)
	// }

	// cb, err := parsedBundle.ToCertBundle()
	// if err != nil {
	// 	return nil, errwrap.Wrapf("error converting raw cert bundle to cert bundle: {{err}}", err)
	// }

	// respData := map[string]interface{}{
	// 	"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
	// 	"serial_number": cb.SerialNumber,
	// }

	// switch format {
	// case "pem":
	// 	respData["issuing_ca"] = signingCB.Certificate
	// 	respData["certificate"] = cb.Certificate
	// 	if cb.CAChain != nil && len(cb.CAChain) > 0 {
	// 		respData["ca_chain"] = cb.CAChain
	// 	}
	// 	if !useCSR {
	// 		respData["private_key"] = cb.PrivateKey
	// 		respData["private_key_type"] = cb.PrivateKeyType
	// 	}

	// case "pem_bundle":
	// 	respData["issuing_ca"] = signingCB.Certificate
	// 	respData["certificate"] = cb.ToPEMBundle()
	// 	if cb.CAChain != nil && len(cb.CAChain) > 0 {
	// 		respData["ca_chain"] = cb.CAChain
	// 	}
	// 	if !useCSR {
	// 		respData["private_key"] = cb.PrivateKey
	// 		respData["private_key_type"] = cb.PrivateKeyType
	// 	}

	// case "der":
	// 	respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
	// 	respData["issuing_ca"] = base64.StdEncoding.EncodeToString(key)

	// 	var caChain []string
	// 	for _, caCert := range parsedBundle.CAChain {
	// 		caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
	// 	}
	// 	if caChain != nil && len(caChain) > 0 {
	// 		respData["ca_chain"] = caChain
	// 	}

	// 	if !useCSR {
	// 		respData["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
	// 		respData["private_key_type"] = cb.PrivateKeyType
	// 	}
	// }

	// var resp *logical.Response
	// switch {
	// case role.GenerateLease == nil:
	// 	return nil, fmt.Errorf("generate lease in role is nil")
	// case *role.GenerateLease == false:
	// 	// If lease generation is disabled do not populate `Secret` field in
	// 	// the response
	// 	resp = &logical.Response{
	// 		Data: respData,
	// 	}
	// default:

	// 	resp = b.Secret("pki").Response(
	// 		respData,
	// 		map[string]interface{}{
	// 			"serial_number": cb.SerialNumber,
	// 		})
	// 	resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())

	// }

	// if data.Get("private_key_format").(string) == "pkcs8" {
	// 	err = convertRespToPKCS8(resp)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// if !role.NoStore {
	// 	err = req.Storage.Put(ctx, &logical.StorageEntry{
	// 		Key:   "certs/" + normalizeSerial(cb.SerialNumber),
	// 		Value: parsedBundle.CertificateBytes,
	// 	})
	// 	if err != nil {
	// 		return nil, errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
	// 	}
	// }

	// if useCSR {
	// 	if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
	// 		resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
	// 	}
	// 	if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
	// 		resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
	// 	}
	// }

	// return resp, nil
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
