package locket

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/1password/onepassword-sdk-go"
)

func TestMisc(t *testing.T) {
	ctx := context.Background()

	token, ok := os.LookupEnv(envTokenName)
	if !ok {
		panic(fmt.Errorf("required %q not set", envTokenName))
	}
	slog.Debug("found token", "name", envTokenName)

	// Authenticates with your service account token and connects to 1Password.
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(
			onepassword.DefaultIntegrationName,
			onepassword.DefaultIntegrationVersion,
		),
	)
	if err != nil {
		panic(fmt.Errorf("init client: %w", err))
	}
	v, err := client.VaultsAPI.ListAll(ctx)
	if err != nil {
		panic(fmt.Errorf("list vaults: %w", err))
	}
	for {
		vlt, err := v.Next()
		if errors.Is(err, onepassword.ErrorIteratorDone) {
			break
		} else if err != nil {
			panic(fmt.Errorf("iterate vaults: %w", err))
		}
		vaults = append(vaults, vault{
			ID:    vlt.ID,
			Title: vlt.Title,
		})
		fmt.Printf("%s %s\n", vlt.ID, vlt.Title)
	}
	// slog.Debug("vaults", "count", len(vaults), "items", vaults)

	for _, vault := range vaults {
		items, err := client.ItemsAPI.ListAll(ctx, vault.ID)
		if err != nil {
			panic(fmt.Errorf("list items: %w", err))
		}
		for {
			item, err := items.Next()
			if errors.Is(err, onepassword.ErrorIteratorDone) {
				break
			} else if err != nil {
				panic(fmt.Errorf("iterate items: %w", err))
			}
			ref := fmt.Sprintf("op://%s/%s/%s", vault.ID, item.ID, "password")
			// fmt.Printf("%s %s %s\n", item.ID, item.Title, ref)
			// slog.Info("fetching secret", "ref", ref)
			err = onepassword.Secrets.ValidateSecretReference(ctx, ref)
			if err != nil {
				slog.Error("invalid", "error", err)
			}

		}
	}
	secret, err := client.SecretsAPI.Resolve(ctx, "op://test/fake1234/password")
	if err != nil {
		panic(fmt.Errorf("resolve secret: %w", err))
	}
	fmt.Println("secret: ", secret)
	// ref := fmt.Sprintf("op://%s/%s/%s", vault.ID, item.ID, "password")
	// secret, err := client.Secrets.Resolve(ctx, ref)
	// if err != nil {
	// 	panic(fmt.Errorf("resolve secret: %w", err))
	// }
	// fmt.Println("secret: ", secret)

	// http.HandleFunc("/public", HandlerPubkey)
	// http.HandleFunc("/kv", kvHandler)
	http.ListenAndServe(":8111", nil)
}
