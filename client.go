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
	"errors"
	"log"
	"strings"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
)

type keyfactorClient struct {
	*api.Client
}

func newClient(config *keyfactorConfig) (*api.Client, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.KeyfactorUrl == "" {
		return nil, errors.New("client URL was not defined")
	}
	hostname := config.KeyfactorUrl
	if strings.HasPrefix(config.KeyfactorUrl, "http") {
		hostname = strings.Split(config.KeyfactorUrl, "//")[1] //extract just the domain
	}

	isBasicAuth := config.Username != "" && config.Password != ""
	isOAuth := (config.ClientId != "" && config.ClientSecret != "" && config.TokenUrl != "") || config.AccessToken != ""

	if !isBasicAuth && !isOAuth {
		return nil, errors.New(
			"invalid Keyfactor Command client configuration, " +
				"please provide a valid Basic auth or OAuth configuration",
		)
	}

	serverConfig := &auth_providers.Server{}
	if isBasicAuth {
		basicAuthConfig := &auth_providers.CommandAuthConfigBasic{}
		_ = basicAuthConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath)

		bErr := basicAuthConfig.
			WithUsername(config.Username).
			WithPassword(config.Password).
			Authenticate()

		if bErr != nil {
			return nil, bErr
		}
		serverConfig = basicAuthConfig.GetServerConfig()
	} else if isOAuth {
		oauthConfig := &auth_providers.CommandConfigOauth{}
		_ = oauthConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(config.CommandAPIPath)

		oErr := oauthConfig.
			WithClientId(config.ClientId).
			WithClientSecret(config.ClientSecret).
			WithTokenUrl(config.TokenUrl).
			WithAccessToken(config.AccessToken).
			Authenticate()

		if oErr != nil {
			return nil, oErr
		}
		serverConfig = oauthConfig.GetServerConfig()
	}

	c, err := api.NewKeyfactorClient(serverConfig, nil)
	if err != nil {
		log.Fatalf("[ERROR] creating Keyfactor client: %s", err)
	}

	return c, err
}
