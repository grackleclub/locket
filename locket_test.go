package locket

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	opts := serverOpts{
		source:         sourceFile,
		sourceFilePath: testEnvFile,
	}
	server, err := NewServer(opts)
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	client, err := NewClient(handler.URL)
	require.NoError(t, err)

	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.fetchSecret("FOO")
	require.NoError(t, err)
	t.Logf("secret: %s", resp)
}
