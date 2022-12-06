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
