package keyvault

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/pkg/errors"
)

type Keyvaults struct {
	authorizer autorest.Authorizer
	clients    map[string]*Client
}

func NewKeyvaults() (*Keyvaults, error) {
	msicfg := auth.MSIConfig{
		Resource: "https://vault.azure.net",
	}

	authorizer, err := msicfg.Authorizer()
	if err != nil {
		return nil, err
	}

	return &Keyvaults{
		authorizer: authorizer,
		clients:    make(map[string]*Client),
	}, nil
}

func (kv *Keyvaults) GetClient(kvname string) (*Client, error) {
	if client, ok := kv.clients[kvname]; ok {
		return client, nil
	}

	if kvname == "" {
		return nil, errors.New("Unspecified keyvault")
	}

	client := keyvault.New()
	client.Authorizer = kv.authorizer

	kvc := &Client{
		name:          kvname,
		baseUrl:       fmt.Sprintf("https://%s.vault.azure.net", strings.ToLower(kvname)),
		client:        client,
		secretCache:   make(map[string]*secretCacheItem),
		certCache:     make(map[string]*certCacheItem),
		certListCache: nil,
	}

	kv.clients[kvname] = kvc
	return kvc, nil
}

func (kv *Keyvaults) Invalidate() {
	for _, client := range kv.clients {
		client.Invalidate()
	}
}
