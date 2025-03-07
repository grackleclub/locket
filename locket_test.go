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
		Name:   "foo-1",
		KeyPub: pub,
	}}
	testReg := path.Join("temp", "testreg.yml")
	err = WriteRegistry(testReg, reg)
	require.NoError(t, err)

	var source = dotenv{
		path: path.Join(testEnvFile),
	}
	server, err := NewServer(source, testReg)
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	client, err := NewClient(handler.URL, pub, priv)
	require.NoError(t, err)

	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.fetchSecret("FOO")
	require.NoError(t, err)
	t.Logf("secret: %s", resp)
}
