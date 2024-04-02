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
	"fmt"
	"log"
	"strings"

	"github.com/Keyfactor/keyfactor-go-client/api"
)

type keyfactorClient struct {
	*api.Client
}

func newClient(config *keyfactorConfig) (*api.Client, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}

	if config.Username == "" {
		return nil, errors.New("client username was not defined")
	}

	if config.Password == "" {
		return nil, errors.New("client password was not defined")
	}

	if config.KeyfactorUrl == "" {
		return nil, errors.New("client URL was not defined")
	}
	username := strings.Split(config.Username, "//")[1]
	domain := strings.Split(config.Username, "//")[1]
	hostname := config.KeyfactorUrl
	if strings.HasPrefix(config.KeyfactorUrl, "http") {
		hostname = strings.Split(config.KeyfactorUrl, "//")[1] //extract just the domain
	}

	var clientAuth api.AuthConfig
	clientAuth.Username = username
	clientAuth.Password = config.Password
	clientAuth.Domain = domain
	clientAuth.Hostname = hostname

	fmt.Printf("clientAuth values: \n %s", clientAuth)

	c, err := api.NewKeyfactorClient(&clientAuth)
	if err != nil {
		log.Fatalf("[ERROR] creating Keyfactor client: %s", err)
	}

	return c, err
}
