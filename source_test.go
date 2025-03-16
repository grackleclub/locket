package locket

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testEnvFile  = path.Join("example", ".env")
	testServices = []string{"SERVICE1", "SERVICE2"}
)

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
}

func TestLoadFile(t *testing.T) {

	var source = Dotenv{
		Path:     testEnvFile,
		Services: testServices,
	}
	allSecrets, err := source.Load()
	require.NoError(t, err)
	t.Logf("allSecrets: %v", allSecrets)

	require.Greater(t, len(allSecrets), 0)
	for serviceName, secrets := range allSecrets {

		// each service in the example has
		// three valid secrets
		// require.Equal(t, 3, len(secrets))
		t.Logf("service: %s", serviceName)
		for k, v := range secrets {
			t.Logf("  %s=%s", k, v)
		}
	}
}

func TestLoadEnv(t *testing.T) {
	err := putFileToEnv()
	require.NoError(t, err)

	var source = Env{
		Services: testServices,
	}
	secrets, err := source.Load()
	require.NoError(t, err)
	require.Greater(t, len(secrets), 0)
	for service, kvs := range secrets {
		t.Logf("service: %s", service)
		for k, v := range kvs {
			t.Logf("  %s=%s", k, v)
		}
	}
}

// testing requires a file (part of .git) to be loaded into env
// to then test env loading
func putFileToEnv() error {
	var source = Dotenv{
		Path:     testEnvFile,
		Services: testServices,
	}
	allSecrets, err := source.Load()
	if err != nil {
		return fmt.Errorf("load secrets: %w", err)
	}
	for service, kvs := range allSecrets {
		for k, v := range kvs {
			err = os.Setenv(k, v)
			if err != nil {
				return fmt.Errorf("service: %v, key: %v: %w",
					service, k, err,
				)
			}
		}
	}
	return nil
}
