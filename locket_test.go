package locket

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	var source = dotenv{
		path: path.Join(testEnvFile),
	}
	server, err := NewServer(source)
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	pub, priv, err := newPairEd25519()
	require.NoError(t, err)

	client, err := NewClient(handler.URL, pub, priv)
	require.NoError(t, err)

	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.fetchSecret("FOO")
	require.NoError(t, err)
	t.Logf("secret: %s", resp)
}
