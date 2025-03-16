package locket

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	// create signing keys for the soon to be client
	pub, priv, err := NewPairEd25519()
	require.NoError(t, err)

	var reg = []RegEntry{{
		Name:   "SERVICE1",
		KeyPub: pub,
	}}
	testReg := path.Join("example", "testreg.yml")
	err = WriteRegistry(testReg, reg)
	require.NoError(t, err)

	var source = Dotenv{
		Services: []string{"SERVICE1"},
		Path:     path.Join("example", ".env"),
	}
	registry, err := ReadRegistryFile(testReg)
	require.NoError(t, err)
	require.NotNil(t, registry)
	require.Greater(t, len(registry), 0)

	server, err := NewServer(source, registry)
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	client, err := NewClient(handler.URL, pub, priv)
	require.NoError(t, err)

	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.fetchSecret("SERVICE1_FOO")
	require.NoError(t, err)
	require.Equal(t, "foovalue", resp)
	t.Logf("secret: %s", resp)
}
