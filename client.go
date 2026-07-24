/*
 *  Copyright 2026 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package kfbackend

import (
	"errors"
	"fmt"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client-sdk/v24"
)

func newClient(config *keyfactorConfig, b *keyfactorBackend) (*keyfactor.APIClient, error) {
	b.Logger().Trace("creating a new Keyfactor API client..")

	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.KeyfactorUrl == "" {
		return nil, errors.New("the URL to Command was not defined")
	}

	hostname := config.KeyfactorUrl

	isBasicAuth := config.Username != "" && config.Password != ""
	isOAuth := (config.ClientId != "" && config.ClientSecret != "" && config.TokenUrl != "") || config.AccessToken != ""

	if !isBasicAuth && !isOAuth {
		return nil, errors.New(
			"invalid Keyfactor Command client configuration, " +
				"please provide a valid Basic (username/password) or OAuth configuration",
		)
	}

	var conf *auth_providers.Server

	if isBasicAuth {
		b.Logger().Debug(fmt.Sprintf("using basic auth with username %s, domain %s and password (hidden)", config.Username, config.Domain))

		basicAuthConfig := &auth_providers.CommandAuthConfigBasic{}

		basicAuthConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath).
			WithSkipVerify(config.SkipTLSVerify).
			WithCommandCACert(config.CommandCertPath)
		bErr := basicAuthConfig.
			WithUsername(config.Username).
			WithPassword(config.Password).
			WithDomain(config.Domain).
			Authenticate()

		if bErr != nil {
			errMsg := fmt.Sprintf("[ERROR] unable to authenticate with provided basic auth credentials: %s", bErr.Error())
			b.Logger().Error(errMsg)
			return nil, bErr
		}
		b.Logger().Debug("successfully authenticated using basic auth")

		conf = basicAuthConfig.GetServerConfig()

	} else if isOAuth {
		oAuthConfig := &auth_providers.CommandConfigOauth{}

		b.Logger().Debug(fmt.Sprintf("using oAuth authentication with client_id: %s, token_url %s and client_secret: (hidden)", config.ClientId, config.TokenUrl))

		oAuthConfig.CommandAuthConfig.
			WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath).
			WithSkipVerify(config.SkipTLSVerify).
			WithCommandCACert(config.CommandCertPath)

		oErr := oAuthConfig.
			WithClientId(config.ClientId).
			WithClientSecret(config.ClientSecret).
			WithTokenUrl(config.TokenUrl).
			WithAccessToken(config.AccessToken).
			WithScopes(config.Scopes).
			WithAudience(config.Audience).
			Authenticate()

		conf = oAuthConfig.GetServerConfig()

		if oErr != nil {
			errMsg := fmt.Sprintf("[ERROR] unable to authenticate with provided oAuth credentials: %s", oErr.Error())
			b.Logger().Error(errMsg)
			return nil, oErr
		}
	}

	c, err := keyfactor.NewAPIClient(conf)

	if err != nil {
		errMsg := fmt.Sprintf("[ERROR] there was an error creating the Keyfactor client: %s", err.Error())
		b.Logger().Error(errMsg)
		return nil, err
	}

	return c, nil
}
