package onepassword

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/1password/onepassword-sdk-go"
	"github.com/grackleclub/log"
)

var (
	envTokenName = "OP_SERVICE_ACCOUNT_TOKEN"
)

func init() {
	if _, ok := os.LookupEnv("DEBUG"); ok {
		log.Init(slog.LevelDebug)
	} else {
		log.Init(slog.LevelInfo)
	}
}

// newOpClient creates a new 1password client
func newOpClient(ctx context.Context) (*onepassword.Client, error) {
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

type secrets map[string]string // all key/value secrets for a single service

// Load1password loads all service secrets from a 1password vault
func Load1password(ctx context.Context, name string) (map[string]secrets, error) {
	client, err := newOpClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}

	var allSecrets = make(map[string]secrets)
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
			var serviceSecrects = make(secrets)
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
				allSecrets[service.Title] = serviceSecrects
				slog.Debug("loaded secrets for service", "qty", len(serviceSecrects), "service", service.Title)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("vault %q not found", name)
	}
	if len(allSecrets) == 0 {
		return nil, fmt.Errorf("no services/items found in vault %q", name)
	}
	slog.Debug("vault load complete",
		"elapsed", time.Since(start),
		"vault", name,
		"services", len(allSecrets),
	)
	return allSecrets, nil
}
