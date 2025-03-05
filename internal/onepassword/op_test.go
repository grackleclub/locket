// build +integration
package onepassword

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadVaults(t *testing.T) {
	ctx := context.Background()
	v, err := Vaults(ctx)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotEmpty(t, v)
	for _, vault := range v {
		t.Logf("vault: %s", vault.Name)
		for _, v := range vault.Secrets {
			t.Logf("  %s=%s", v.Title, v.Value)
		}
	}
}
