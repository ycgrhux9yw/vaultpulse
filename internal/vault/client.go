package vault

import (
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Client wraps the Vault API client with helper methods.
type Client struct {
	api     *vaultapi.Client
	Address string
}

// SecretMeta holds TTL and lease information for a Vault secret.
type SecretMeta struct {
	Path      string
	LeaseTTL  time.Duration
	LeaseID   string
	Renewable bool
	ExpiresAt time.Time
}

// NewClient creates a new Vault client using the provided address and token.
func NewClient(address, token string) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address

	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	api.SetToken(token)

	return &Client{
		api:     api,
		Address: address,
	}, nil
}

// GetSecretMeta reads a secret at the given path and returns its TTL metadata.
func (c *Client) GetSecretMeta(path string) (*SecretMeta, error) {
	secret, err := c.api.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret at %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret found at path %q", path)
	}

	ttl := time.Duration(secret.LeaseDuration) * time.Second
	expiresAt := time.Now().Add(ttl)

	return &SecretMeta{
		Path:      path,
		LeaseTTL:  ttl,
		LeaseID:   secret.LeaseID,
		Renewable: secret.Renewable,
		ExpiresAt: expiresAt,
	}, nil
}

// ListPaths lists all secret paths under a given prefix.
func (c *Client) ListPaths(prefix string) ([]string, error) {
	secret, err := c.api.Logical().List(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list paths under %q: %w", prefix, err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	paths := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			paths = append(paths, s)
		}
	}
	return paths, nil
}
