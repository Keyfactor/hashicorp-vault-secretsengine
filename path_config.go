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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath = "config"
)

// keyfactorConfig includes the minimum configuration
// required to instantiate a new Keyfactor connection.
type keyfactorConfig struct {
	KeyfactorUrl    string   `json:"url"`
	CommandAPIPath  string   `json:"api_path"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	Domain          string   `json:"domain"`
	ClientId        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	TokenUrl        string   `json:"token_url"`
	AccessToken     string   `json:"access_token"`
	SkipTLSVerify   bool     `json:"skip_verify"`
	Scopes          []string `json:"scopes"`
	Audience        []string `json:"audience"`
	CertTemplate    string   `json:"template"`
	CertAuthority   string   `json:"ca"`
	CommandCertPath string   `json:"command_cert_path"`
}

func (b *keyfactorBackend) fetchConfig(ctx context.Context, s logical.Storage) (*keyfactorConfig, error) {
	if b.cachedConfig != nil {
		return b.cachedConfig, nil
	}

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &keyfactorConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	b.cachedConfig = config

	return config, nil
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *keyfactorBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `config`,
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "The username for authenticating with Keyfactor Command using `Basic` auth.",
					Required:    false,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "The password for authenticating with Keyfactor Command using `Basic` auth.",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"client_id": {
					Type: framework.TypeString,
					Description: "The client ID for authenticating with Keyfactor Command using `OAuth2` client" +
						" credentials.",
					Required: false,
				},
				"client_secret": {
					Type: framework.TypeString,
					Description: "The client secret for authenticating with Keyfactor Command using `OAuth2` client" +
						" credentials.",
					Required: false,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"token_url": {
					Type: framework.TypeString,
					Description: "The token URL for authenticating with Keyfactor Command using `OAuth2` client" +
						" credentials.",
					Required: false,
				},
				"scopes": {
					Type: framework.TypeCommaStringSlice,
					Description: "The scopes for authenticating with Keyfactor Command using `OAuth2` client" +
						" credentials.",
					Required: false,
				},
				"audience": {
					Type: framework.TypeCommaStringSlice,
					Description: "The audience for authenticating with Keyfactor Command using `OAuth2` client" +
						" credentials.",
					Required: false,
				},
				"access_token": {
					Type:        framework.TypeString,
					Description: "The access token for authenticating with Keyfactor Command using `OAuth2`",
					Required:    false,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"skip_verify": {
					Type:        framework.TypeBool,
					Description: "Set to true if we should skip verification of the TLS certificate when authenticating.",
					Required:    false,
					Default:     false,
				},
				"url": {
					Type:        framework.TypeString,
					Description: "[REQUIRED] The URL for the Keyfactor platform.",
					Required:    true,
				},
				"api_path": {
					Type:        framework.TypeString,
					Description: "The API path for the Keyfactor platform.",
					Required:    false,
					Default:     "KeyfactorAPI",
				},
				"domain": {
					Type:        framework.TypeString,
					Description: "The Active Directory domain if using AD authentication",
					Required:    false,
				},
				"template": {
					Type:        framework.TypeString,
					Description: "The certificate template to use with this instance of the plugin.  If not provided, a value will need to be provided for each enrollment request.",
					Required:    false,
				},
				"ca": {
					Type:        framework.TypeString,
					Description: "The certificate authority to use with this instance of the plugin.  If not provided, a value will need to be provided for each enrollment request.",
					Required:    false,
				},
				"command_cert_path": {
					Type:        framework.TypeString,
					Description: "Path to CA certificate to use when connecting to the Keyfactor Command API in PEM format.",
					Required:    false,
				},
				"show_hidden": {
					Type:        framework.TypeBool,
					Description: "Set this flag to show sensitive values in the output",
					Required:    false,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathConfigRead,
				logical.UpdateOperation: b.pathConfigUpdate,
				logical.DeleteOperation: b.pathConfigDelete,
			},
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
	}
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *keyfactorBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	showSensitiveData := data.Get("show_hidden").(bool)
	// obscuring sensitive info:

	clientSecret := config.ClientSecret
	if clientSecret != "" && !showSensitiveData {
		clientSecret = "(hidden)"
	}

	password := config.Password
	if password != "" && !showSensitiveData {
		password = "(hidden)"
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":               config.KeyfactorUrl,
			"api_path":          config.CommandAPIPath,
			"username":          config.Username,
			"password":          password,
			"client_id":         config.ClientId,
			"client_secret":     clientSecret,
			"token_url":         config.TokenUrl,
			"scopes":            config.Scopes,
			"audience":          config.Audience,
			"access_token":      config.AccessToken,
			"ca":                config.CertAuthority,
			"template":          config.CertTemplate,
			"command_cert_path": config.CommandCertPath,
			"skip_verify":       config.SkipTLSVerify,
			"domain":            config.Domain,
		},
	}, nil
}

// pathConfigUpdate updates the configuration for the backend
func (b *keyfactorBackend) pathConfigUpdate(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	b.Logger().Debug("Calling pathConfigUpdate")
	b.configLock.RLock()
	defer b.configLock.RUnlock()

	newConfig := &keyfactorConfig{
		KeyfactorUrl:    data.Get("url").(string),
		Username:        data.Get("username").(string),
		Password:        data.Get("password").(string),
		CertAuthority:   data.Get("ca").(string),
		CertTemplate:    data.Get("template").(string),
		CommandAPIPath:  data.Get("api_path").(string),
		ClientId:        data.Get("client_id").(string),
		ClientSecret:    data.Get("client_secret").(string),
		TokenUrl:        data.Get("token_url").(string),
		AccessToken:     data.Get("access_token").(string),
		Scopes:          data.Get("scopes").([]string),
		Audience:        data.Get("audience").([]string),
		Domain:          data.Get("domain").(string),
		CommandCertPath: data.Get("command_cert_path").(string),
		SkipTLSVerify:   data.Get("skip_verify").(bool),
	}

	// Check if the config already exists, to determine if this is a create or
	// an update, since req.Operation is always 'update' in this handler, and
	// there's no existence check defined.
	existingConfig, err := b.fetchConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if existingConfig == nil {
		existingConfig = newConfig
	}

	if username, ok := data.GetOk("username"); ok {
		existingConfig.Username = username.(string)
	}

	if url, ok := data.GetOk("url"); ok {
		existingConfig.KeyfactorUrl = url.(string)
	}

	if password, ok := data.GetOk("password"); ok {
		existingConfig.Password = password.(string)
	}

	if ca, ok := data.GetOk("ca"); ok {
		existingConfig.CertAuthority = ca.(string)
	}

	if template, ok := data.GetOk("template"); ok {
		existingConfig.CertTemplate = template.(string)
	}

	if apiPath, ok := data.GetOk("api_path"); ok {
		existingConfig.CommandAPIPath = apiPath.(string)
	}

	if clientId, ok := data.GetOk("client_id"); ok {
		existingConfig.ClientId = clientId.(string)
	}

	if clientSecret, ok := data.GetOk("client_secret"); ok {
		existingConfig.ClientSecret = clientSecret.(string)
	}

	if tokenUrl, ok := data.GetOk("token_url"); ok {
		existingConfig.TokenUrl = tokenUrl.(string)
	}

	if accessToken, ok := data.GetOk("access_token"); ok {
		existingConfig.AccessToken = accessToken.(string)
	}

	if scopes, ok := data.GetOk("scopes"); ok {
		existingConfig.Scopes = scopes.([]string)
	}

	if audience, ok := data.GetOk("audience"); ok {
		existingConfig.Audience = audience.([]string)
	}

	if domain, ok := data.GetOk("domain"); ok {
		existingConfig.Domain = domain.(string)
	}

	if skipVerify, ok := data.GetOk("skip_verify"); ok {
		existingConfig.SkipTLSVerify = skipVerify.(bool)
	}

	if caCertPath, ok := data.GetOk("command_cert_path"); ok {
		existingConfig.CommandCertPath = caCertPath.(string)
	}

	entry, err := logical.StorageEntryJSON(configPath, existingConfig)
	if err != nil {
		b.Logger().Error("[ERROR] there was an error converting the values to JSON for storage: %s", err)
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.Logger().Error("[ERROR] there was an error writing the configuration to the backend: %s", err)
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()
	b.cachedConfig = existingConfig
	return nil, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *keyfactorBackend) pathConfigDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configPath)
	return nil, err
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Keyfactor Secrets Engine backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Keyfactor Secrets Engine plugin requires the following values to be defined; depending on Authentication strategy:
  oAuth: 
	clientId - the client ID for authenticating
	clientSecret - the client secret
	tokenUrl - the url where the oAuth token will be retreived
	scopes (optional) - a comma-separated list of the scopes of the token to be returned
	audience (optional) - the audience to be passed when requesting the token
	access_token (optional) - the access token to use if available
  basic authentication:
    username - Keyfactor user that the plugin will use for authenticating
	password - Keyfactor user password

  the following should be defined regardless of authentication strategy:
	url - url of the Keyfactor platform with no trailing slashes (ie: https://keyfactor.lab)
	ca (optional) - the certificate authority in the format <hostname\\\\logical name>.  If omitted, will need to be passed for each request
	template (optional) - the certificate template to use when enrolling.  If omitted, will need to be passed for each request.
`
