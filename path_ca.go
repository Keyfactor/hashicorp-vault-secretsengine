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

func pathCA(b *keyfactorBackend) []*framework.Path {
	return []*framework.Path{
		{ //fetch ca
			Pattern: `ca(/pem)?`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathFetchCa,
			},

			HelpSynopsis:    pathFetchCAHelp,
			HelpDescription: pathFetchCAHelpDesc,
		},
		{ // fetch ca chain
			Pattern: `ca_chain(/pem)?`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathFetchCa,
			},

			HelpSynopsis:    pathFetchChainHelp,
			HelpDescription: pathFetchChainHelpDesc,
		},
	}
}

func (b *keyfactorBackend) pathFetchCa(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	var serial string

	response = &logical.Response{
		Data: map[string]interface{}{},
	}

	// Some of these need to return raw and some non-raw;
	// this is basically handled by setting contentType or not.
	// Errors don't cause an immediate exit, because the raw
	// paths still need to return raw output.
	b.Logger().Debug("fetching ca, path = " + req.Path)

	switch {
	case req.Path == "ca" || req.Path == "ca/pem":
		serial = "ca"
	case req.Path == "ca_chain" || req.Path == "cert/ca_chain":
		serial = "ca_chain"
	default:
		serial = "ca"
	}

	if len(serial) == 0 {
		response = logical.ErrorResponse("The serial number must be provided")
	}

	if serial == "ca" {
		return fetchCAInfo(ctx, req, b)
	}

	return fetchCaChainInfo(ctx, req, b)
}

const pathFetchCAHelp = `
Fetch a Certificate Authority.
`

const pathFetchChainHelp = `
Fetch a CA Chain.
`
const pathFetchCAHelpDesc = `
This allows Certificate Authorities to be fetched.
The "ca" command fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
`

const pathFetchChainHelpDesc = `
This allows the Certificate Authority chain to be fetched.
The "ca_chain" command fetches the certificate authority trust chain in PEM encoding.
`
