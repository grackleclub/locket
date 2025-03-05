package locket

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
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
