//go:build integration

package onepassword

import (
	"context"
	"log/slog"
	"testing"

	"github.com/grackleclub/log"
	"github.com/stretchr/testify/require"
)

func init() {
	log.Init(slog.LevelDebug)
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	t.Run("load 1password", func(t *testing.T) {
		client, err := newOpClient(ctx)
		v, err := Vault(ctx, client, "test")
		require.NoError(t, err)
		require.NotNil(t, v)
		require.NotEmpty(t, v)
		for _, vault := range v {
			t.Logf("vault: %+v", vault)
		}

	})

}

// func TestLoadVaults(t *testing.T) {
// 	ctx := context.Background()
// 	v, err := Vaults(ctx)
// 	require.NoError(t, err)
// 	require.NotNil(t, v)
// 	require.NotEmpty(t, v)
// 	for _, vault := range v {
// 		t.Logf("vault: %s", vault.Name)
// 		for _, v := range vault.Secrets {
// 			t.Logf("  %s=%s", v.Title, v.Value)
// 		}
// 	}
// }
