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
	"errors"
	"fmt"
	"net/http"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
)

type keyfactorClient struct {
	httpClient *http.Client
}

func newClient(config *keyfactorConfig, b *keyfactorBackend) (*keyfactorClient, error) {
	client := new(keyfactorClient)

	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.KeyfactorUrl == "" {
		return nil, errors.New("the URL to Command was not defined")
	}

	hostname := config.KeyfactorUrl
	b.Logger().Debug(fmt.Sprintf("using hostname %s", hostname))

	isBasicAuth := config.Username != "" && config.Password != ""
	isOAuth := (config.ClientId != "" && config.ClientSecret != "" && config.TokenUrl != "") || config.AccessToken != ""

	if !isBasicAuth && !isOAuth {
		return nil, errors.New(
			"invalid Keyfactor Command client configuration, " +
				"please provide a valid Basic auth or OAuth configuration",
		)
	}

	oAuthConfig := &auth_providers.CommandConfigOauth{}
	basicAuthConfig := &auth_providers.CommandAuthConfigBasic{}

	if isBasicAuth {
		b.Logger().Debug(
			fmt.Sprintf(
				"using basic auth with username %s, domain %s and password (hidden)",
				config.Username,
				config.Domain,
			),
		)
		b.Logger().With(
			"url", hostname,
			"api_path", config.CommandAPIPath,
			"skip_verify", config.SkipTLSVerify,
			"ca_cert", config.CommandCertPath,
		).Debug("setting base Command configuration")

		basicAuthConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath).
			WithSkipVerify(config.SkipTLSVerify).
			WithCommandCACert(config.CommandCertPath)

		b.Logger().With(
			"username",
			config.Username,
			"domain",
			config.Domain,
			"password",
			"(hidden)",
		).Debug("setting basic auth credentials")
		bErr := basicAuthConfig.
			WithUsername(config.Username).
			WithPassword(config.Password).
			WithDomain(config.Domain).
			Authenticate()

		if bErr != nil {
			errMsg := fmt.Sprintf(
				"[ERROR] unable to authenticate with provided basic auth credentials: %s",
				bErr.Error(),
			)
			b.Logger().Error(errMsg)
			return nil, bErr
		} else {
			b.Logger().Debug("successfully authenticated using basic auth")
		}

		client.httpClient, bErr = basicAuthConfig.GetHttpClient()

		if bErr != nil {
			errMsg := fmt.Sprintf("[ERROR] there was an error retreiving the basic auth http client: %s", bErr.Error())
			b.Logger().Error(errMsg)
			return nil, bErr
		}

	} else if isOAuth {
		b.Logger().With(
			"url", hostname,
			"api_path", config.CommandAPIPath,
			"skip_verify", config.SkipTLSVerify,
			"ca_cert", config.CommandCertPath,
		).Debug("setting base Command configuration")
		_ = oAuthConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath).
			WithSkipVerify(config.SkipTLSVerify).
			WithCommandCACert(config.CommandCertPath)

		b.Logger().Debug(
			fmt.Sprintf(
				"using oAuth authentication with client_id: %s, token_url %s and client_secret: (hidden)",
				config.ClientId,
				config.TokenUrl,
			),
		)
		oErr := oAuthConfig.
			WithClientId(config.ClientId).
			WithClientSecret(config.ClientSecret).
			WithTokenUrl(config.TokenUrl).
			WithAccessToken(config.AccessToken).
			Authenticate()

		if oErr != nil {
			errMsg := fmt.Sprintf("[ERROR] unable to authenticate with provided oAuth credentials: %s", oErr.Error())
			b.Logger().Error(errMsg)
			return nil, oErr
		}

		client.httpClient, oErr = oAuthConfig.GetHttpClient()
		if oErr != nil {
			errMsg := fmt.Sprintf("[ERROR] there was an error retreiving the oAuth http client: %s", oErr.Error())
			b.Logger().Error(errMsg)
			return nil, oErr
		}
	}
	return client, nil
}
