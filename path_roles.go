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
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRoles(b *keyfactorBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"), // read or update role

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.UpdateOperation: b.pathRoleCreate,
				logical.DeleteOperation: b.pathRoleDelete,
			},

			Fields:          addRoleFields(map[string]*framework.FieldSchema{}),
			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
		{
			Pattern: "roles/?$", //list roles

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},

			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
	}
}

func (b *keyfactorBackend) getRole(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	// Migrate existing saved entries and save back if changed
	modified := false
	if len(result.DeprecatedTTL) == 0 && len(result.Lease) != 0 {
		result.DeprecatedTTL = result.Lease
		result.Lease = ""
		modified = true
	}
	if result.TTL == 0 && len(result.DeprecatedTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedTTL)
		if err != nil {
			return nil, err
		}
		result.TTL = parsed
		result.DeprecatedTTL = ""
		modified = true
	}
	if len(result.DeprecatedMaxTTL) == 0 && len(result.LeaseMax) != 0 {
		result.DeprecatedMaxTTL = result.LeaseMax
		result.LeaseMax = ""
		modified = true
	}
	if result.MaxTTL == 0 && len(result.DeprecatedMaxTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedMaxTTL)
		if err != nil {
			return nil, err
		}
		result.MaxTTL = parsed
		result.DeprecatedMaxTTL = ""
		modified = true
	}
	if result.AllowBaseDomain {
		result.AllowBaseDomain = false
		result.AllowBareDomains = true
		modified = true
	}
	if result.AllowedDomainsOld != "" {
		result.AllowedDomains = strings.Split(result.AllowedDomainsOld, ",")
		result.AllowedDomainsOld = ""
		modified = true
	}
	if result.AllowedBaseDomain != "" {
		found := false
		for _, v := range result.AllowedDomains {
			if v == result.AllowedBaseDomain {
				found = true
				break
			}
		}
		if !found {
			result.AllowedDomains = append(result.AllowedDomains, result.AllowedBaseDomain)
		}
		result.AllowedBaseDomain = ""
		modified = true
	}

	// Upgrade generate_lease in role
	if result.GenerateLease == nil {
		// All the new roles will have GenerateLease always set to a value. A
		// nil value indicates that this role needs an upgrade. Set it to
		// `true` to not alter its current behavior.
		result.GenerateLease = new(bool)
		*result.GenerateLease = true
		modified = true
	}

	// Upgrade key usages
	if result.KeyUsageOld != "" {
		result.KeyUsage = strings.Split(result.KeyUsageOld, ",")
		result.KeyUsageOld = ""
		modified = true
	}

	// Upgrade OU
	if result.OUOld != "" {
		result.OU = strings.Split(result.OUOld, ",")
		result.OUOld = ""
		modified = true
	}

	// Upgrade Organization
	if result.OrganizationOld != "" {
		result.Organization = strings.Split(result.OrganizationOld, ",")
		result.OrganizationOld = ""
		modified = true
	}

	if modified && (b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		jsonEntry, err := logical.StorageEntryJSON("role/"+n, &result)
		if err != nil {
			return nil, err
		}
		if err := s.Put(ctx, jsonEntry); err != nil {
			// Only perform upgrades on replication primary
			if !strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return nil, err
			}
		}
	}

	return &result, nil
}

func (b *keyfactorBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *keyfactorBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *keyfactorBackend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *keyfactorBackend) pathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

	entry := &roleEntry{
		MaxTTL:                        time.Duration(data.Get("max_ttl").(int)) * time.Second,
		TTL:                           time.Duration(data.Get("ttl").(int)) * time.Second,
		AllowLocalhost:                data.Get("allow_localhost").(bool),
		AllowedDomains:                data.Get("allowed_domains").([]string),
		AllowedDomainsTemplate:        data.Get("allowed_domains_template").(bool),
		AllowBareDomains:              data.Get("allow_bare_domains").(bool),
		AllowSubdomains:               data.Get("allow_subdomains").(bool),
		AllowGlobDomains:              data.Get("allow_glob_domains").(bool),
		AllowAnyName:                  data.Get("allow_any_name").(bool),
		EnforceHostnames:              data.Get("enforce_hostnames").(bool),
		AllowIPSANs:                   data.Get("allow_ip_sans").(bool),
		AllowedURISANs:                data.Get("allowed_uri_sans").([]string),
		ServerFlag:                    data.Get("server_flag").(bool),
		ClientFlag:                    data.Get("client_flag").(bool),
		CodeSigningFlag:               data.Get("code_signing_flag").(bool),
		EmailProtectionFlag:           data.Get("email_protection_flag").(bool),
		KeyType:                       data.Get("key_type").(string),
		KeyBits:                       data.Get("key_bits").(int),
		UseCSRCommonName:              data.Get("use_csr_common_name").(bool),
		UseCSRSANs:                    data.Get("use_csr_sans").(bool),
		KeyUsage:                      data.Get("key_usage").([]string),
		ExtKeyUsage:                   data.Get("ext_key_usage").([]string),
		ExtKeyUsageOIDs:               data.Get("ext_key_usage_oids").([]string),
		OU:                            data.Get("ou").([]string),
		Organization:                  data.Get("organization").([]string),
		Country:                       data.Get("country").([]string),
		Locality:                      data.Get("locality").([]string),
		Province:                      data.Get("province").([]string),
		StreetAddress:                 data.Get("street_address").([]string),
		PostalCode:                    data.Get("postal_code").([]string),
		GenerateLease:                 new(bool),
		NoStore:                       data.Get("no_store").(bool),
		RequireCN:                     data.Get("require_cn").(bool),
		AllowedSerialNumbers:          data.Get("allowed_serial_numbers").([]string),
		PolicyIdentifiers:             data.Get("policy_identifiers").([]string),
		BasicConstraintsValidForNonCA: data.Get("basic_constraints_valid_for_non_ca").(bool),
		NotBeforeDuration:             time.Duration(data.Get("not_before_duration").(int)) * time.Second,
	}

	allowedOtherSANs := data.Get("allowed_other_sans").([]string)
	switch {
	case len(allowedOtherSANs) == 0:
	case len(allowedOtherSANs) == 1 && allowedOtherSANs[0] == "*":
	default:
		_, err := parseOtherSANs(allowedOtherSANs)
		if err != nil {
			return logical.ErrorResponse(errwrap.Wrapf("error parsing allowed_other_sans: {{err}}", err).Error()), nil
		}
	}
	entry.AllowedOtherSANs = allowedOtherSANs

	// no_store implies generate_lease := false
	if entry.NoStore {
		*entry.GenerateLease = false
	} else {
		*entry.GenerateLease = data.Get("generate_lease").(bool)
	}

	if entry.KeyType == "rsa" && entry.KeyBits < 2048 {
		return logical.ErrorResponse("RSA keys < 2048 bits are unsafe and not supported"), nil
	}

	if entry.MaxTTL > 0 && entry.TTL > entry.MaxTTL {
		return logical.ErrorResponse(
			`"ttl" value must be less than "max_ttl" value`,
		), nil
	}

	if err := certutil.ValidateKeyTypeLength(entry.KeyType, entry.KeyBits); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(entry.ExtKeyUsageOIDs) > 0 {
		for _, oidstr := range entry.ExtKeyUsageOIDs {
			_, err := certutil.StringToOid(oidstr)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%q could not be parsed as a valid oid for an extended key usage", oidstr)), nil
			}
		}
	}

	if len(entry.PolicyIdentifiers) > 0 {
		for _, oidstr := range entry.PolicyIdentifiers {
			_, err := certutil.StringToOid(oidstr)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%q could not be parsed as a valid oid for a policy identifier", oidstr)), nil
			}
		}
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
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

type roleEntry struct {
	LeaseMax                      string        `json:"lease_max"`
	Lease                         string        `json:"lease"`
	DeprecatedMaxTTL              string        `json:"max_ttl" mapstructure:"max_ttl"`
	DeprecatedTTL                 string        `json:"ttl" mapstructure:"ttl"`
	TTL                           time.Duration `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL                        time.Duration `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
	AllowLocalhost                bool          `json:"allow_localhost" mapstructure:"allow_localhost"`
	AllowedBaseDomain             string        `json:"allowed_base_domain" mapstructure:"allowed_base_domain"`
	AllowedDomainsOld             string        `json:"allowed_domains,omitempty"`
	AllowedDomains                []string      `json:"allowed_domains_list" mapstructure:"allowed_domains"`
	AllowedDomainsTemplate        bool          `json:"allowed_domains_template"`
	AllowBaseDomain               bool          `json:"allow_base_domain"`
	AllowBareDomains              bool          `json:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowTokenDisplayName         bool          `json:"allow_token_displayname" mapstructure:"allow_token_displayname"`
	AllowSubdomains               bool          `json:"allow_subdomains" mapstructure:"allow_subdomains"`
	AllowGlobDomains              bool          `json:"allow_glob_domains" mapstructure:"allow_glob_domains"`
	AllowAnyName                  bool          `json:"allow_any_name" mapstructure:"allow_any_name"`
	EnforceHostnames              bool          `json:"enforce_hostnames" mapstructure:"enforce_hostnames"`
	AllowIPSANs                   bool          `json:"allow_ip_sans" mapstructure:"allow_ip_sans"`
	ServerFlag                    bool          `json:"server_flag" mapstructure:"server_flag"`
	ClientFlag                    bool          `json:"client_flag" mapstructure:"client_flag"`
	CodeSigningFlag               bool          `json:"code_signing_flag" mapstructure:"code_signing_flag"`
	EmailProtectionFlag           bool          `json:"email_protection_flag" mapstructure:"email_protection_flag"`
	UseCSRCommonName              bool          `json:"use_csr_common_name" mapstructure:"use_csr_common_name"`
	UseCSRSANs                    bool          `json:"use_csr_sans" mapstructure:"use_csr_sans"`
	KeyType                       string        `json:"key_type" mapstructure:"key_type"`
	KeyBits                       int           `json:"key_bits" mapstructure:"key_bits"`
	MaxPathLength                 *int          `json:",omitempty" mapstructure:"max_path_length"`
	KeyUsageOld                   string        `json:"key_usage,omitempty"`
	KeyUsage                      []string      `json:"key_usage_list" mapstructure:"key_usage"`
	ExtKeyUsage                   []string      `json:"extended_key_usage_list" mapstructure:"extended_key_usage"`
	OUOld                         string        `json:"ou,omitempty"`
	OU                            []string      `json:"ou_list" mapstructure:"ou"`
	OrganizationOld               string        `json:"organization,omitempty"`
	Organization                  []string      `json:"organization_list" mapstructure:"organization"`
	Country                       []string      `json:"country" mapstructure:"country"`
	Locality                      []string      `json:"locality" mapstructure:"locality"`
	Province                      []string      `json:"province" mapstructure:"province"`
	StreetAddress                 []string      `json:"street_address" mapstructure:"street_address"`
	PostalCode                    []string      `json:"postal_code" mapstructure:"postal_code"`
	GenerateLease                 *bool         `json:"generate_lease,omitempty"`
	NoStore                       bool          `json:"no_store" mapstructure:"no_store"`
	RequireCN                     bool          `json:"require_cn" mapstructure:"require_cn"`
	AllowedOtherSANs              []string      `json:"allowed_other_sans" mapstructure:"allowed_other_sans"`
	AllowedSerialNumbers          []string      `json:"allowed_serial_numbers" mapstructure:"allowed_serial_numbers"`
	AllowedURISANs                []string      `json:"allowed_uri_sans" mapstructure:"allowed_uri_sans"`
	PolicyIdentifiers             []string      `json:"policy_identifiers" mapstructure:"policy_identifiers"`
	ExtKeyUsageOIDs               []string      `json:"ext_key_usage_oids" mapstructure:"ext_key_usage_oids"`
	BasicConstraintsValidForNonCA bool          `json:"basic_constraints_valid_for_non_ca" mapstructure:"basic_constraints_valid_for_non_ca"`
	NotBeforeDuration             time.Duration `json:"not_before_duration" mapstructure:"not_before_duration"`

	// Used internally for signing intermediates
	AllowExpirationPastCA bool
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"ttl":                                int64(r.TTL.Seconds()),
		"max_ttl":                            int64(r.MaxTTL.Seconds()),
		"allow_localhost":                    r.AllowLocalhost,
		"allowed_domains":                    r.AllowedDomains,
		"allowed_domains_template":           r.AllowedDomainsTemplate,
		"allow_bare_domains":                 r.AllowBareDomains,
		"allow_token_displayname":            r.AllowTokenDisplayName,
		"allow_subdomains":                   r.AllowSubdomains,
		"allow_glob_domains":                 r.AllowGlobDomains,
		"allow_any_name":                     r.AllowAnyName,
		"enforce_hostnames":                  r.EnforceHostnames,
		"allow_ip_sans":                      r.AllowIPSANs,
		"server_flag":                        r.ServerFlag,
		"client_flag":                        r.ClientFlag,
		"code_signing_flag":                  r.CodeSigningFlag,
		"email_protection_flag":              r.EmailProtectionFlag,
		"use_csr_common_name":                r.UseCSRCommonName,
		"use_csr_sans":                       r.UseCSRSANs,
		"key_type":                           r.KeyType,
		"key_bits":                           r.KeyBits,
		"key_usage":                          r.KeyUsage,
		"ext_key_usage":                      r.ExtKeyUsage,
		"ext_key_usage_oids":                 r.ExtKeyUsageOIDs,
		"ou":                                 r.OU,
		"organization":                       r.Organization,
		"country":                            r.Country,
		"locality":                           r.Locality,
		"province":                           r.Province,
		"street_address":                     r.StreetAddress,
		"postal_code":                        r.PostalCode,
		"no_store":                           r.NoStore,
		"allowed_other_sans":                 r.AllowedOtherSANs,
		"allowed_serial_numbers":             r.AllowedSerialNumbers,
		"allowed_uri_sans":                   r.AllowedURISANs,
		"require_cn":                         r.RequireCN,
		"policy_identifiers":                 r.PolicyIdentifiers,
		"basic_constraints_valid_for_non_ca": r.BasicConstraintsValidForNonCA,
		"not_before_duration":                int64(r.NotBeforeDuration.Seconds()),
	}
	if r.MaxPathLength != nil {
		responseData["max_path_length"] = r.MaxPathLength
	}
	if r.GenerateLease != nil {
		responseData["generate_lease"] = r.GenerateLease
	}
	return responseData
}

const pathRoleHelpSyn = `Manage the roles that can be created with this backend.`

const pathRoleHelpDesc = `Manage the roles that can be created with this plugin. Roles loosely correspond to Certificate Templates in Keyfactor Command 
and have been implemented here to maintain compatibility with the Vault PKI secrets engine.
The Certificate Template configured within Keyfactor Command should be used to set certificate defaults.  
The Role-specific fields that are verified before passing a certificate issuing request to Command are:
AllowedDomains, AllowSubdomains.  These can be used to restrict the domains for which certificates can be issued.`
