package keyfactor

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
