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

	return fields
}
