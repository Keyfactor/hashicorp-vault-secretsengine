package keyfactor

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// keyfactorConfig includes the minimum configuration
// required to instantiate a new Keyfactor connection.
type keyfactorConfig struct {
	KeyfactorUrl  string `json:"url"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	CertTemplate  string `json:"template"`
	CertAuthority string `json:"ca"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *keyfactorBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "The Keyfactor user name for authenticating with the platform.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "The password for the Keyfactor account used for authenticating.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The URL for the Keyfactor platform.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Url",
					Sensitive: false,
				},
			},
			"template": {
				Type:        framework.TypeString,
				Description: "The certificate template to use with this instance of the plugin.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"ca": {
				Type:        framework.TypeString,
				Description: "The certificate authority to use with this instance of the plugin",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "CA",
					Sensitive: false,
				},
			},
		},
		Operations:      map[logical.Operation]framework.OperationHandler{},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *keyfactorBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*keyfactorConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
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
