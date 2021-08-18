package keyvault

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/pkg/errors"
)

// Keyvaults tracks keyvault clients and provides authorization.
type Keyvaults struct {
	authorizer autorest.Authorizer
	clients    map[string]*Client
	env        azure.Environment
}

// NewKeyvaults creates a new Keyvaults tracker object with the specified
// Azure environment
func NewKeyvaults(env azure.Environment) (*Keyvaults, error) {
	msicfg := auth.MSIConfig{
		Resource: strings.TrimSuffix(env.KeyVaultEndpoint, "/"),
	}

	authorizer, err := msicfg.Authorizer()
	if err != nil {
		return nil, err
	}

	return &Keyvaults{
		authorizer: authorizer,
		clients:    make(map[string]*Client),
		env:        env,
	}, nil
}

// Implements the base TemplateContext interface for the keyvaults collection
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
		name:            kvname,
		baseUrl:         fmt.Sprintf("https://%s.%s", strings.ToLower(kvname), kv.env.KeyVaultDNSSuffix),
		client:          client,
		secretCache:     make(map[string]*secretCacheItem),
		certCache:       make(map[string]*certCacheItem),
		keyCache:        make(map[string]*keyCacheItem),
		certListCache:   nil,
		secretListCache: nil,
	}

	kv.clients[kvname] = kvc
	return kvc, nil
}

// Invalidates all keyvault clients' caches
func (kv *Keyvaults) Invalidate() {
	for _, client := range kv.clients {
		client.Invalidate()
	}
}
