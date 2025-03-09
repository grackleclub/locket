package locket

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var testEnvFile = path.Join("example", "example.env")

func TestLoadFile(t *testing.T) {
	var source = Dotenv{
		Paths: []string{path.Join(testEnvFile)},
	}
	secrets, err := source.Load()
	require.NoError(t, err)
	require.Greater(t, len(secrets), 0)
	for serviceName, secrets := range secrets {
		t.Logf("service: %s", serviceName)
		for k, v := range secrets {
			t.Logf("  %s=%s", k, v)
		}
	}
}

func TestLoadEnv(t *testing.T) {
	var source = Env{}
	secrets, err := source.Load()
	require.NoError(t, err)
	for k, _ := range secrets["env"] {
		t.Logf("loaded: %v", k)
	}
}
