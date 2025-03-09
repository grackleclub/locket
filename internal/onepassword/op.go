package onepassword

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

var (
	envTokenName = "OP_SERVICE_ACCOUNT_TOKEN"
)

// the default title of the secret, an assumption which
// narrows the flexibility of the utility by assuming
// only simple k/v pairs
var defaultKey = "password"

// vault represents a 1Password vault
type vault struct {
	ID      string
	Name    string
	Secrets map[string]secret
}

type secret struct {
	ID    string // 1password item ID
	Title string // 1password item title
	Value string // value of the item's '$defaultKey' field
}

func init() {
	if _, ok := os.LookupEnv("DEBUG"); ok {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
}

func NewClient(ctx context.Context) (*onepassword.Client, error) {
	now := time.Now().UTC()
	token, ok := os.LookupEnv(envTokenName)
	if !ok {
		return nil, fmt.Errorf("required %q not set", envTokenName)
	}
	slog.Debug("found token", "name", envTokenName)

	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(
			onepassword.DefaultIntegrationName,
			onepassword.DefaultIntegrationVersion,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("init client: %w", err)
	}
	slog.Debug("client created", "elapsed", time.Since(now))
	return client, nil
}

type allSecrets map[string]serviceSecrets // all secrets for all services
type serviceSecrets map[string]string     // all secrets for a single service

func Vault(ctx context.Context, client *onepassword.Client, name string) (allSecrets, error) {
	var secrets = make(allSecrets)
	start := time.Now().UTC()
	vault, err := client.VaultsAPI.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	var found bool
	for {
		vlt, err := vault.Next()
		if errors.Is(err, onepassword.ErrorIteratorDone) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("iterate vaults: %w", err)
		}
		if vlt.Title == name {
			slog.Debug("loading selected vault", "id", vlt.ID, "title", vlt.Title)
			found = true
			services, err := client.ItemsAPI.ListAll(ctx, vlt.ID)
			if err != nil {
				return nil, fmt.Errorf("list items: %w", err)
			}
			// var serviceManySecrets = make(map[string]map[string]string)
			var serviceSecrects = make(serviceSecrets)
			for {
				service, err := services.Next()
				if err != nil {
					if errors.Is(err, onepassword.ErrorIteratorDone) {
						break
					} else {
						return nil, fmt.Errorf("iterate items: %w", err)
					}
				}
				slog.Debug("loading service",
					"id", service.ID,
					"title", service.Title,
				)
				serviceDetail, err := client.ItemsAPI.Get(ctx, vlt.ID, service.ID)
				if err != nil {
					return nil, fmt.Errorf("get item: %w", err)
				}
				for _, secret := range serviceDetail.Fields {
					serviceSecrects[secret.Title] = secret.Value
				}
				secrets[service.Title] = serviceSecrects
				slog.Debug("loaded secrets for service", "qty", len(serviceSecrects), "service", service.Title)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("vault %q not found", name)
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("no services/items found in vault %q", name)
	}
	slog.Debug("vault load complete",
		"elapsed", time.Since(start),
		"vault", name,
		"services", len(secrets),
	)
	return secrets, nil
}

// Vaults connects to 1Password and loads all vault secrets which
// have a '$defaultKey' field. The function returns a map of vaults
// with their secrets.
func Vaults(ctx context.Context) (map[string]vault, error) {
	client, err := NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}

	v, err := client.VaultsAPI.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	var vaults = make(map[string]vault)
	for {
		vlt, err := v.Next()
		if errors.Is(err, onepassword.ErrorIteratorDone) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("iterate vaults: %w", err)
		}
		slog.Debug("found vault", "id", vlt.ID, "title", vlt.Title)
		vaults[vlt.Title] = vault{
			ID:      vlt.ID,
			Name:    vlt.Title,
			Secrets: make(map[string]secret),
		}
	}

	for _, vault := range vaults {
		items, err := client.ItemsAPI.ListAll(ctx, vault.ID)
		if err != nil {
			return nil, fmt.Errorf("list items: %w", err)
		}
		var secrets = make(map[string]secret)
		for {
			item, err := items.Next()
			if errors.Is(err, onepassword.ErrorIteratorDone) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("iterate items: %w", err)
			}
			str := fmt.Sprintf("op://%s/%s/%s", vault.Name, item.Title, defaultKey)
			val, err := client.SecretsAPI.Resolve(ctx, str)
			if err != nil {
				slog.Error("resolve secret", "ref", str, "error", err)
				// return nil, fmt.Errorf("resolve secret: %w", err)
			} else {
				secrets[item.Title] = secret{
					ID:    item.ID,
					Title: item.Title,
					Value: val,
				}
			}
		}
		v := vaults[vault.Name]
		v.Secrets = secrets
		vaults[vault.Name] = v
	}
	return vaults, nil
}
