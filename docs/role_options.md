# Role Options

`vault write keyfactor/roles/<role> <key>="<value>"`

Here is a table of the available configuration parameters

| name | value type | required | default | description |
| ---- | ----------- | -------- | -------- | ----------- |
| ttl | duration (seconds) | false |  | The lease duration if no specific lease duration is requested. The lease duration controls the expiration of certificates issued by this backend. Defaults to the value of max_ttl. |
| max_ttl | duration (seconds) | false |  | The maximum allowed lease duration |
| allow_localhost | bool | false | true | Whether to allow "localhost" as a valid common name in a request |
| allowed_domains | string slice (comma-separated) | false |  | If set, clients can request certificates for subdomains directly beneath these domains, including the wildcard subdomains. Accepts a comma-separated string or list of domains. |
| allowed_domains_template | bool | false | false | If set, allowed domains can be specified using identity template policies. Non-templated domains are also permitted. |
| allow_bare_domains | bool | false |  | If set, clients can request certificates for the base domains themselves, e.g. "example.com". In some cases this can be considered a security threat. |
| allow_subdomains | bool | false |  | If set, clients can request certificates for subdomains of the CNs allowed by the other role options, including wildcard subdomains. |
| allow_glob_domains | bool | false |  | If set, domains specified in "allowed_domains" can include glob patterns, e.g. "ftp*.example.com". |
| allow_any_name | bool | false |  | If set, clients can request certificates for any CN they like. |
| enforce_hostnames | bool | false | true | If set, only valid host names are allowed for CN and SANs. Defaults to true. |
| allow_ip_sans | bool | false | true | If set, IP Subject Alternative Names are allowed. Any valid IP is accepted. |
| allowed_uri_sans | string slice (comma-separated) | false |  | If set, an array of allowed URIs to put in the URI Subject Alternative Names. Any valid URI is accepted; supports globbing. |
| allowed_other_sans | string slice (comma-separated) | false |  | If set, an array of allowed other names to put in SANs. Values support globbing and must be in the format `<oid>;<type>:<value>`. Only "utf8" is a valid type. |
| allowed_serial_numbers | string slice (comma-separated) | false |  | If set, an array of allowed serial numbers to put in Subject. Values support globbing. |
| server_flag | bool | false | true | If set, certificates are flagged for server auth use. Defaults to true. |
| client_flag | bool | false | true | If set, certificates are flagged for client auth use. Defaults to true. |
| code_signing_flag | bool | false |  | If set, certificates are flagged for code signing use. Defaults to false. |
| email_protection_flag | bool | false |  | If set, certificates are flagged for email protection use. Defaults to false. |
| key_type | string | false | rsa | The type of key to use; defaults to RSA. Valid values: "rsa", "ec". |
| key_bits | int | false | 2048 | The number of bits to use. You may want to change this if you adjust key_type. |
| key_usage | string slice (comma-separated) | false | DigitalSignature, KeyAgreement, KeyEncipherment | A list of key usages (not extended). To remove all, set to an empty list. |
| ext_key_usage | string slice (comma-separated) | false | [] | A list of extended key usages. To remove all, set to an empty list. |
| ext_key_usage_oids | string slice (comma-separated) | false |  | A list of extended key usage OIDs. |
| use_csr_common_name | bool | false | true | If set, when used with a signing profile, the CN in the CSR will be used. Defaults to true. |
| use_csr_sans | bool | false | true | If set, when used with a signing profile, the SANs in the CSR will be used. Defaults to true. |
| ou | string slice (comma-separated) | false |  | If set, OU (OrganizationalUnit) will be set to this value in issued certificates. |
| organization | string slice (comma-separated) | false |  | If set, O (Organization) will be set to this value in issued certificates. |
| country | string slice (comma-separated) | false |  | If set, Country will be set to this value in issued certificates. |
| locality | string slice (comma-separated) | false |  | If set, Locality will be set to this value in issued certificates. |
| province | string slice (comma-separated) | false |  | If set, Province will be set to this value in issued certificates. |
| street_address | string slice (comma-separated) | false |  | If set, Street Address will be set to this value in issued certificates. |
| postal_code | string slice (comma-separated) | false |  | If set, Postal Code will be set to this value in issued certificates. |
| generate_lease | bool | false |  | If set, certificates issued against this role will have Vault leases attached to them. Recommended to disable when issuing many long-lived certs. |
| no_store | bool | false |  | If set, certificates issued against this role will not be stored in the backend. Improves performance but prevents revocation/enumeration. |
| require_cn | bool | false | true | If false, makes the 'common_name' field optional when generating a certificate. |
| policy_identifiers | string slice (comma-separated) | false |  | A list of policy OIDs. |
| basic_constraints_valid_for_non_ca | bool | false |  | Mark Basic Constraints valid when issuing non-CA certificates. |
| not_before_duration | duration (seconds) | false | 30 | The duration before now the certificate should be considered valid (creation offset). |
