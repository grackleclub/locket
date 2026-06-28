package locket

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testEnvFile = path.Join("example", ".env")
	// testServices   = []string{"SERVICE1", "SERVICE2"}
	testServiceMap = map[string][]string{
		"SERVICE1": {"SERVICE1_FOO", "SERVICE1_BAT", "SERVICE1_FOOBAR", "SHARED_VAR"},
		"SERVICE2": {"SERVICE2_FOO", "SERVICE2_BAR", "SERVICE2_SYMBOLS", "SHARED_VAR"},
	}
)

func TestLoadFile(t *testing.T) {
	source := Dotenv{
		Path:           testEnvFile,
		ServiceSecrets: testServiceMap,
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

	for service, varNames := range testServiceMap {
		for i, varName := range varNames {
			placeholderValue := fmt.Sprintf("placeholder_value_%v", i)
			t.Logf("%s: %s=%s", service, varName, placeholderValue)
			err = os.Setenv(varName, placeholderValue)
			require.NoError(t, err)
		}
	}

	source := Env{
		ServiceSecrets: testServiceMap,
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

// TestLoadEnvMixedCaseService is the regression test for the Env.Load existence
// check: a mixed-case service name must retain every one of its secrets, not
// just the last one loaded (the bug reset the service map on each secret because
// it checked the original-case key against a lowercase-keyed map).
func TestLoadEnvMixedCaseService(t *testing.T) {
	secretNames := []string{"REGRESSION_A", "REGRESSION_B", "REGRESSION_C"}
	for i, name := range secretNames {
		require.NoError(t, os.Setenv(name, fmt.Sprintf("v%d", i)))
		t.Cleanup(func() { os.Unsetenv(name) })
	}

	source := Env{
		ServiceSecrets: map[string][]string{"MixedSvc": secretNames},
	}
	secrets, err := source.Load()
	require.NoError(t, err)

	// server looks services up lowercased
	svc, ok := secrets["mixedsvc"]
	require.True(t, ok, "mixed-case service should be present (lowercased)")
	require.Len(t, svc, len(secretNames), "all secrets for the service must be retained")
}

// testing requires a file (part of .git) to be loaded into env
// to then test env loading
func putFileToEnv() error {
	source := Dotenv{
		Path:           testEnvFile,
		ServiceSecrets: testServiceMap,
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
