/*
 *  Copyright 2024 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package kfbackend

import "github.com/hashicorp/vault/sdk/framework"

// addNonCACommonFields adds fields with help text specific to non-CA
// certificate issuing and signing
func addNonCACommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {

	fields["ca"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Specify the CA to use for the request in the format "<host\\logical>". If blank, will use the default from configuration.`,
	}

	fields["template"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Specify the name of the certificate template to use for the request. If blank, will use the default from configuration.`,
	}

	fields["dns_sans"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Comma seperated list of DNS Subject Alternative Names`,
		Required:    true,
	}

	fields["role"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The desired role with configuration for this
request`,
	}

	fields["common_name"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested common name; if you want more than
one, specify the alternative names in the
alt_names map. If email protection is enabled
in the role, this may be an email address.`,
		Required: true,
	}

	fields["alt_names"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested Subject Alternative Names, if any,
in a comma-delimited list. If email protection
is enabled for the role, this may contain
email addresses.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "DNS/Email Subject Alternative Names (SANs)",
		},
	}

	fields["serial_number"] = &framework.FieldSchema{
		Type: framework.TypeString,
		Description: `The requested serial number, if any. If you want
more than one, specify alternative names in
the alt_names map using OID 2.5.4.5.`,
	}

	fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: `The requested Time To Live for the certificate;
sets the expiration date. If not specified
the role default, backend default, or system
default TTL is used, in that order. Cannot
be larger than the role max TTL.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "TTL",
		},
	}

	fields["metadata"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `Metadata in JSON format to be passed along with the signing request and associated with the certificate in Command.`,
	}

	return fields
}

func addRoleFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {

	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the role",
	}
	fields["ttl"] = &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: `The lease duration if no specific lease duration is
requested. The lease duration controls the expiration
of certificates issued by this backend. Defaults to
the value of max_ttl.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "TTL",
		},
	}

	fields["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "The maximum allowed lease duration",
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Max TTL",
		},
	}

	fields["allow_localhost"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `Whether to allow "localhost" as a valid common
name in a request`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: true,
		},
	}

	fields["allowed_domains"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, clients can request certificates for
subdomains directly beneath these domains, including
the wildcard subdomains. See the documentation for more
information. This parameter accepts a comma-separated 
string or list of domains.`,
	}
	fields["allowed_domains_template"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, Allowed domains can be specified using identity template policies.
				Non-templated domains are also permitted.`,
		Default: false,
	}
	fields["allow_bare_domains"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, clients can request certificates
for the base domains themselves, e.g. "example.com".
This is a separate option as in some cases this can
be considered a security threat.`,
	}

	fields["allow_subdomains"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, clients can request certificates for
subdomains of the CNs allowed by the other role options,
including wildcard subdomains. See the documentation for
more information.`,
	}

	fields["allow_glob_domains"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, domains specified in "allowed_domains"
can include glob patterns, e.g. "ftp*.example.com". See
the documentation for more information.`,
	}

	fields["allow_any_name"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, clients can request certificates for
any CN they like. See the documentation for more
information.`,
	}

	fields["enforce_hostnames"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, only valid host names are allowed for
CN and SANs. Defaults to true.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: true,
		},
	}

	fields["allow_ip_sans"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, IP Subject Alternative Names are allowed.
Any valid IP is accepted.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name:  "Allow IP Subject Alternative Names",
			Value: true,
		},
	}

	fields["allowed_uri_sans"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, an array of allowed URIs to put in the URI Subject Alternative Names.
Any valid URI is accepted, these values support globbing.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Allowed URI Subject Alternative Names",
		},
	}

	fields["allowed_other_sans"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `If set, an array of allowed other names to put in SANs. These values support globbing and must be in the format <oid>;<type>:<value>. Currently only "utf8" is a valid type. All values, including globbing values, must use this syntax, with the exception being a single "*" which allows any OID and any value (but type must still be utf8).`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Allowed Other Subject Alternative Names",
		},
	}

	fields["allowed_serial_numbers"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `If set, an array of allowed serial numbers to put in Subject. These values support globbing.`,
	}

	fields["server_flag"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, certificates are flagged for server auth use.
Defaults to true.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: true,
		},
	}

	fields["client_flag"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, certificates are flagged for client auth use.
Defaults to true.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: true,
		},
	}

	fields["code_signing_flag"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, certificates are flagged for code signing
use. Defaults to false.`,
	}

	fields["email_protection_flag"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `If set, certificates are flagged for email
protection use. Defaults to false.`,
	}

	fields["key_type"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "rsa",
		Description: `The type of key to use; defaults to RSA. "rsa"
and "ec" are the only valid values.`,
		AllowedValues: []interface{}{"rsa", "ec"},
	}

	fields["key_bits"] = &framework.FieldSchema{
		Type:    framework.TypeInt,
		Default: 2048,
		Description: `The number of bits to use. You will almost
certainly want to change this if you adjust
the key_type.`,
	}

	fields["key_usage"] = &framework.FieldSchema{
		Type:    framework.TypeCommaStringSlice,
		Default: []string{"DigitalSignature", "KeyAgreement", "KeyEncipherment"},
		Description: `A comma-separated string or list of key usages (not extended
key usages). Valid values can be found at
https://golang.org/pkg/crypto/x509/#KeyUsage
-- simply drop the "KeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "DigitalSignature,KeyAgreement,KeyEncipherment",
		},
	}

	fields["ext_key_usage"] = &framework.FieldSchema{
		Type:    framework.TypeCommaStringSlice,
		Default: []string{},
		Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Extended Key Usage",
		},
	}

	fields["ext_key_usage_oids"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `A comma-separated string or list of extended key usage oids.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Extended Key Usage OIDs",
		},
	}

	fields["use_csr_common_name"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, when used with a signing profile,
the common name in the CSR will be used. This
does *not* include any requested Subject Alternative
Names. Defaults to true.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name:  "Use CSR Common Name",
			Value: true,
		},
	}

	fields["use_csr_sans"] = &framework.FieldSchema{
		Type:    framework.TypeBool,
		Default: true,
		Description: `If set, when used with a signing profile,
the SANs in the CSR will be used. This does *not*
include the Common Name (cn). Defaults to true.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name:  "Use CSR Subject Alternative Names",
			Value: true,
		},
	}

	fields["ou"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, OU (OrganizationalUnit) will be set to
this value in certificates issued by this role.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Organizational Unit",
		},
	}

	fields["organization"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, O (Organization) will be set to
this value in certificates issued by this role.`,
	}

	fields["country"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, Country will be set to
this value in certificates issued by this role.`,
	}

	fields["locality"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, Locality will be set to
this value in certificates issued by this role.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Locality/City",
		},
	}

	fields["province"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, Province will be set to
this value in certificates issued by this role.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Province/State",
		},
	}

	fields["street_address"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, Street Address will be set to
this value in certificates issued by this role.`,
	}

	fields["postal_code"] = &framework.FieldSchema{
		Type: framework.TypeCommaStringSlice,
		Description: `If set, Postal Code will be set to
this value in certificates issued by this role.`,
	}

	fields["generate_lease"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false". Certificates can be added to the CRL by
"vault revoke <lease_id>" when certificates are associated with leases.  It can
also be done using the "pki/revoke" endpoint. However, when lease generation is
disabled, invoking "pki/revoke" would be the only way to add the certificates
to the CRL.  When large number of certificates are generated with long
lifetimes, it is recommended that lease generation be disabled, as large amount of
leases adversely affect the startup time of Vault.`,
	}

	fields["no_store"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `
If set, certificates issued/signed against this role will not be stored in the
storage backend. This can improve performance when issuing large numbers of 
certificates. However, certificates issued in this way cannot be enumerated
or revoked, so this option is recommended only for certificates that are
non-sensitive, or extremely short-lived. This option implies a value of "false"
for "generate_lease".`,
	}

	fields["require_cn"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Default:     true,
		Description: `If set to false, makes the 'common_name' field optional while generating a certificate.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Require Common Name",
		},
	}

	fields["policy_identifiers"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `A comma-separated string or list of policy oids.`,
	}

	fields["basic_constraints_valid_for_non_ca"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Description: `Mark Basic Constraints valid when issuing non-CA certificates.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Name: "Basic Constraints Valid for Non-CA",
		},
	}

	fields["not_before_duration"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Default:     30,
		Description: `The duration before now the cert needs to be created / signed.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: 30,
		},
	}

	return fields
}
