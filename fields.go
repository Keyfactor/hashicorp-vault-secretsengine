/* 
 *  Copyright 2022 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package keyfactor

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

	// fields["email"] = &framework.FieldSchema{
	// 	Type: framework.TypeCommaStringSlice,
	// 	Description: `Email address to be associated with the certificate`,
	// 	Required:    false,
	// }

	fields["c"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Country for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	fields["ou"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Organizational Unit for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	fields["o"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Organization for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	fields["l"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Locality for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	fields["p"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Province for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	fields["zip"] = &framework.FieldSchema{
		Type:        framework.TypeCommaStringSlice,
		Description: `Postal code for the certificate.  If omitted, the value associated with the role is used.`,
		Required:    false,
	}

	return fields
}

// addCACommonFields adds fields with help text specific to CA
// certificate issuing and signing
// func addCACommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
// 	fields = addIssueAndSignCommonFields(fields)

// 	fields["alt_names"] = &framework.FieldSchema{
// 		Type: framework.TypeString,
// 		Description: `The requested Subject Alternative Names, if any,
// in a comma-delimited list. May contain both
// DNS names and email addresses.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "DNS/Email Subject Alternative Names (SANs)",
// 		},
// 	}

// 	fields["common_name"] = &framework.FieldSchema{
// 		Type: framework.TypeString,
// 		Description: `The requested common name; if you want more than
// one, specify the alternative names in the alt_names
// map. If not specified when signing, the common
// name will be taken from the CSR; other names
// must still be specified in alt_names or ip_sans.`,
// 	}

// 	fields["ttl"] = &framework.FieldSchema{
// 		Type: framework.TypeDurationSecond,
// 		Description: `The requested Time To Live for the certificate;
// sets the expiration date. If not specified
// the role default, backend default, or system
// default TTL is used, in that order. Cannot
// be larger than the mount max TTL. Note:
// this only has an effect when generating
// a CA cert or signing a CA cert, not when
// generating a CSR for an intermediate CA.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "TTL",
// 		},
// 	}

// 	fields["ou"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, OU (OrganizationalUnit) will be set to
// this value.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "OU (Organizational Unit)",
// 		},
// 	}

// 	fields["organization"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, O (Organization) will be set to
// this value.`,
// 	}

// 	fields["country"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, Country will be set to
// this value.`,
// 	}

// 	fields["locality"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, Locality will be set to
// this value.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "Locality/City",
// 		},
// 	}

// 	fields["province"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, Province will be set to
// this value.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "Province/State",
// 		},
// 	}

// 	fields["street_address"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, Street Address will be set to
// this value.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "Street Address",
// 		},
// 	}

// 	fields["postal_code"] = &framework.FieldSchema{
// 		Type: framework.TypeCommaStringSlice,
// 		Description: `If set, Postal Code will be set to
// this value.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "Postal Code",
// 		},
// 	}

// 	fields["serial_number"] = &framework.FieldSchema{
// 		Type: framework.TypeString,
// 		Description: `The requested serial number, if any. If you want
// more than one, specify alternative names in
// the alt_names map using OID 2.5.4.5.`,
// 	}

// 	return fields
// }

// // addCAKeyGenerationFields adds fields with help text specific to CA key
// // generation and exporting
// func addCAKeyGenerationFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
// 	fields["exported"] = &framework.FieldSchema{
// 		Type: framework.TypeString,
// 		Description: `Must be "internal" or "exported". If set to
// "exported", the generated private key will be
// returned. This is your *only* chance to retrieve
// the private key!`,
// 	}

// 	fields["key_bits"] = &framework.FieldSchema{
// 		Type:    framework.TypeInt,
// 		Default: 2048,
// 		Description: `The number of bits to use. You will almost
// certainly want to change this if you adjust
// the key_type.`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Value: 2048,
// 		},
// 	}

// 	fields["key_type"] = &framework.FieldSchema{
// 		Type:    framework.TypeString,
// 		Default: "rsa",
// 		Description: `The type of key to use; defaults to RSA. "rsa"
// and "ec" are the only valid values.`,
// 		AllowedValues: []interface{}{"rsa", "ec"},
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Value: "rsa",
// 		},
// 	}
// 	return fields
// }

// addCAIssueFields adds fields common to CA issuing, e.g. when returning
// an actual certificate
// func addCAIssueFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
// 	fields["max_path_length"] = &framework.FieldSchema{
// 		Type:        framework.TypeInt,
// 		Default:     -1,
// 		Description: "The maximum allowable path length",
// 	}

// 	fields["permitted_dns_domains"] = &framework.FieldSchema{
// 		Type:        framework.TypeCommaStringSlice,
// 		Description: `Domains for which this certificate is allowed to sign or issue child certificates. If set, all DNS names (subject and alt) on child certs must be exact matches or subsets of the given domains (see https://tools.ietf.org/html/rfc5280#section-4.2.1.10).`,
// 		DisplayAttrs: &framework.DisplayAttributes{
// 			Name: "Permitted DNS Domains",
// 		},
// 	}

// 	return fields
// }
