package locket

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	// create signing keys for the soon to be client
	pub, priv, err := NewPairEd25519()
	require.NoError(t, err)

	reg := []RegEntry{{
		Name:   "SERVICE1",
		KeyPub: pub,
	}}
	testReg := path.Join("example", "testreg.yml")
	err = WriteRegistry(testReg, reg)
	require.NoError(t, err)

	source := Dotenv{
		ServiceSecrets: testServiceMap,
		Path:           path.Join("example", ".env"),
	}
	registry, err := ReadRegistryFile(testReg)
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Greater(t, len(registry), 0)

	server, err := NewServer(source, registry)
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	t.Log("private key generated")
	fmt.Println(priv)
	envVarName := "MY_PRIVATE_KEY"

	envVars := map[string]string{
		envVarName: priv,
	}
	text := MarshalDotenv(envVars)
	t.Logf("formatted env vars: %s", text)
	// write the env vars to a file
	f, err := os.CreateTemp("example", "temp-*.env")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString(text)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	// read the env var from file
	envFile, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	t.Logf("env file content: %s", envFile)
	// turn the single line from the file into a map and allow for newlines for private keys
	envVarsFromFile := make(map[string]string)
	for _, line := range strings.Split(string(envFile), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Remove surrounding quotes if they exist
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		// Replace escaped newlines with actual newlines
		value = strings.ReplaceAll(value, "\\n", "\n")
		envVarsFromFile[key] = value
	}
	readKey, ok := envVarsFromFile[envVarName]
	require.True(t, ok, "env var not found in file")
	require.Equal(t, priv, readKey, "private key from file does not match")

	client, err := NewClient(handler.URL, pub, readKey)
	require.NoError(t, err)
	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.FetchSecret("SERVICE1_FOO")
	require.NoError(t, err)
	require.Equal(t, "foovalue", resp)
	t.Logf("secret: %s", resp)
}

// marshalDotenv formats the environment variables for file.
// Systemd enviroment files and dotenv files are targeted for support.
func MarshalDotenv(envVars map[string]string) string {
	var formatted string
	for key, value := range envVars {
		// Escape newlines and double quotes for systemd compatibility
		escapedValue := strings.ReplaceAll(value, "\n", "\\n")
		escapedValue = strings.ReplaceAll(escapedValue, `"`, `\"`)
		formatted += fmt.Sprintf("%s=\"%s\"\n", key, escapedValue)
	}
	slog.Debug("formatted env vars")
	fmt.Println(formatted)
	return formatted
}

func UnmarshalDotenv(text string) map[string]string {
	envVars := make(map[string]string)
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip empty lines and comments
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // skip invalid lines
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"`)
		value = strings.ReplaceAll(value, "\\n", "\n") // restore newlines
		envVars[key] = value
	}
	return envVars
}
