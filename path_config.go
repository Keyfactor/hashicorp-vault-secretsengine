/*
 *  Copyright 2024 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath = "config"
)

// keyfactorConfig includes the minimum configuration
// required to instantiate a new Keyfactor connection.
type keyfactorConfig struct {
	KeyfactorUrl   string   `json:"url"`
	CommandAPIPath string   `json:"api_path"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	ClientId       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	TokenUrl       string   `json:"token_url"`
	AccessToken    string   `json:"access_token"`
	Scopes         []string `json:"scopes"`
	Audience       string   `json:"audience"`
	CertTemplate   string   `json:"template"`
	CertAuthority  string   `json:"ca"`
}

func (b *keyfactorBackend) config(ctx context.Context, s logical.Storage) (*keyfactorConfig, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

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
					Type: framework.TypeString,
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
				"url": {
					Type:        framework.TypeString,
					Description: "The URL for the Keyfactor platform.",
					Required:    true,
				},
				"api_path": {
					Type:        framework.TypeString,
					Description: "The API path for the Keyfactor platform.",
					Required:    false,
					Default:     "KeyfactorAPI",
				},
				"template": {
					Type:        framework.TypeString,
					Description: "The certificate template to use with this instance of the plugin.",
					Required:    true,
				},
				"ca": {
					Type:        framework.TypeString,
					Description: "The certificate authority to use with this instance of the plugin",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathConfigRead,
				logical.UpdateOperation: b.pathConfigWrite,
			},

			//ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *keyfactorBackend) pathConfigExistenceCheck(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *keyfactorBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":           config.KeyfactorUrl,
			"api_path":      config.CommandAPIPath,
			"username":      config.Username,
			"password":      config.Password,
			"client_id":     config.ClientId,
			"client_secret": config.ClientSecret,
			"token_url":     config.TokenUrl,
			"scopes":        config.Scopes,
			"audience":      config.Audience,
			"access_token":  config.AccessToken,
			"CA":            config.CertAuthority,
			"template":      config.CertTemplate,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *keyfactorBackend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	b.Logger().Debug("Calling pathConfigWrite")

	newConfig := &keyfactorConfig{
		KeyfactorUrl:  data.Get("url").(string),
		Username:      data.Get("username").(string),
		Password:      data.Get("password").(string),
		CertAuthority: data.Get("ca").(string),
		CertTemplate:  data.Get("template").(string),
	}

	// Check if the config already exists, to determine if this is a create or
	// an update, since req.Operation is always 'update' in this handler, and
	// there's no existence check defined.
	existingConfig, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := false // always update.  not necessary to require all fields added simultaneously

	if existingConfig == nil {
		existingConfig = newConfig
	}

	if username, ok := data.GetOk("username"); ok {
		existingConfig.Username = username.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing username in configuration")
	}

	if url, ok := data.GetOk("url"); ok {
		existingConfig.KeyfactorUrl = url.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing url in configuration")
	}

	if password, ok := data.GetOk("password"); ok {
		existingConfig.Password = password.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing password in configuration")
	}

	if ca, ok := data.GetOk("ca"); ok {
		existingConfig.CertAuthority = ca.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing Certificate Authority in configuration")
	}

	if template, ok := data.GetOk("template"); ok {
		existingConfig.CertTemplate = template.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing Certificate Template in configuration")
	}

	entry, err := logical.StorageEntryJSON(configPath, existingConfig)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	return nil, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *keyfactorBackend) pathConfigDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configPath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*keyfactorConfig, error) {
	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(keyfactorConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the Keyfactor Secrets Engine backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The Keyfactor secret backend requires credentials in order to connect to the Keyfactor platform.
`

const pathConfigDesc = `
The Keyfactor Secrets Engine plugin requires the following values to be defined:
  username - Keyfactor user that the plugin will use for authenticating
	password - Keyfactor user password
	url - url of the Keyfactor platform with no trailing slashes (ie: https://keyfactor.lab)
	ca - the certificate authority in the format <hostname\\\\logical name>
`
