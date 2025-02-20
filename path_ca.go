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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCA(b *keyfactorBackend) []*framework.Path {
	return []*framework.Path{
		{ //fetch ca
			Pattern: `ca`,
			Fields: map[string]*framework.FieldSchema{
				"ca": {
					Type:        framework.TypeString,
					Description: pathCAFieldDesck,
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathFetchCa,
			},

			HelpSynopsis:    pathFetchCAHelp,
			HelpDescription: pathFetchCAHelpDesc,
		},
		{ // fetch ca chain
			Pattern: `ca_chain`,
			Fields: map[string]*framework.FieldSchema{
				"ca": {
					Type:        framework.TypeString,
					Description: pathCAFieldDesck,
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathFetchCaChain,
			},

			HelpSynopsis:    pathFetchChainHelp,
			HelpDescription: pathFetchChainHelpDesc,
		},
	}
}

func (b *keyfactorBackend) pathFetchCa(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	b.Logger().Debug("fetching ca, path = " + req.Path)
	b.Logger().Trace("reading CA name...")

	caName := data.Get("ca").(string)
	if caName == "" {
		b.Logger().Debug("no ca passed, retreiving from config")
		caName = b.cachedConfig.CertAuthority
	}
	b.Logger().Debug(fmt.Sprintf("ca name = %s", caName))
	if caName == "" {
		return nil, fmt.Errorf("the CA name needs to be specified in the configuration, or passed along with the request")
	}

	return fetchCAInfo(ctx, req, b, caName, false)
}

func (b *keyfactorBackend) pathFetchCaChain(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	b.Logger().Debug("fetching ca chain, path = " + req.Path)
	b.Logger().Trace("reading CA name...")
	caName := data.Get("ca").(string)
	if caName == "" {
		b.Logger().Debug("no ca passed, retreiving from config")
		caName = b.cachedConfig.CertAuthority
	}
	b.Logger().Debug(fmt.Sprintf("ca name = %s", caName))
	if caName == "" {
		return nil, fmt.Errorf("the CA name needs to be specified in the configuration, or passed along with the request")
	}
	return fetchCAInfo(ctx, req, b, caName, true)
}

const pathFetchCAHelp = `
Fetch a Certificate Authority.
`

const pathFetchChainHelp = `
Fetch a CA Chain.
`
const pathFetchCAHelpDesc = `
This allows the Certificate Authority certificate to be fetched.
The "ca" command fetches the PEM encoded CA certificate.  The CA will have to be defined in the configuration or passed along with the request.
`

const pathFetchChainHelpDesc = `
This allows the Certificate Authority chain certificates to be fetched.
The "ca_chain" command fetches the PEM encoded CA certificate chain.  The CA will have to be defined in the configuration or passed along with the request.
`

const pathCAFieldDesck = `The logical CA Name as defined in Command.  If not provided, we will attempt to use the CA Name stored in the configuration.`
