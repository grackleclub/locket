package locket

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	locket, err := NewServer()
	require.NoError(t, err)
	require.NotNil(t, locket)
	// t.Logf("locket: %+v", locket)
}

func TestNewClient(t *testing.T) {
	client, err := NewClient("localhost:fake")
	require.NoError(t, err)
	require.NotNil(t, client)
	// t.Logf("client: %+v", client)
}

func TestEverything(t *testing.T) {
	server, err := NewServer()
	require.NoError(t, err)

	handler := httptest.NewServer(http.HandlerFunc(server.Handler))
	defer handler.Close()

	client, err := NewClient(handler.URL)
	require.NoError(t, err)

	err = client.fetchServerPubkey()
	require.NoError(t, err)

	resp, err := client.fetchSecret("foo")
	require.NoError(t, err)
	t.Logf("secret: %s", resp)
}
