//go:build integration

package locket

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test1password(t *testing.T) {
	t.Run("load 1password", func(t *testing.T) {
		var op = onepass{
			vault: "test",
		}
		allSecrets, err := op.load()
		require.NoError(t, err)
		require.NotNil(t, allSecrets)
		require.NotEmpty(t, allSecrets)
		for service, secrets := range allSecrets {
			t.Logf("service: %s", service)
			for key, value := range secrets {
				t.Logf("  %s=%s", key, value)
			}
		}
	})

	// TODO "update 1password"
}
