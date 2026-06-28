package locket

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testSecretName  = "SERVICE1_FOO"
	testSecretValue = "foovalue"
)

// newTestServer builds a server backed by the example .env and a single
// registered service, returning the running test server, the underlying
// *Server (for its encryption pubkey), and the service's ed25519 signing keys.
// No files are written, so example/testreg.yml is left untouched.
func newTestServer(t *testing.T) (*httptest.Server, *Server, string) {
	t.Helper()
	pub, priv, err := NewPairEd25519()
	require.NoError(t, err)

	registry := []RegEntry{{Name: "SERVICE1", KeyPub: pub}}
	source := Dotenv{
		Path:           testEnvFile,
		ServiceSecrets: testServiceMap,
	}
	server, err := NewServer(source, registry)
	require.NoError(t, err)
	t.Cleanup(server.Close)

	ts := httptest.NewServer(http.HandlerFunc(server.Handler))
	t.Cleanup(ts.Close)
	return ts, server, priv
}

// craftRequest builds a request body for secretName, signed by signingPriv,
// with the response to be encrypted to clientRSAPub. ts is exposed so tests can
// forge stale timestamps.
func craftRequest(t *testing.T, serverRSAPub, signingPriv, secretName, clientRSAPub string, ts int64) kvRequest {
	t.Helper()
	nonce, err := newNonce()
	require.NoError(t, err)
	payload, err := encryptRSA(serverRSAPub, secretName)
	require.NoError(t, err)
	sig, err := signEd25519(signingPriv, requestMessage(secretName, clientRSAPub, ts, nonce))
	require.NoError(t, err)
	return kvRequest{
		Payload:          payload,
		PayloadSignature: sig,
		ClientPubKey:     clientRSAPub,
		Timestamp:        ts,
		Nonce:            nonce,
	}
}

func postRequest(t *testing.T, url string, req kvRequest) (*http.Response, []byte) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, b
}

// assertSecretNotLeaked fails if a kvResponse anywhere in body decrypts to the
// secret with priv. It scans from the first '{' so it also catches the case
// where http.Error wrote "forbidden\n" before the handler wrongly appended the
// encrypted secret (the original missing-return CIDR bug).
func assertSecretNotLeaked(t *testing.T, body []byte, priv string) {
	t.Helper()
	idx := bytes.IndexByte(body, '{')
	if idx < 0 {
		return
	}
	var kv kvResponse
	if err := json.Unmarshal(body[idx:], &kv); err != nil || kv.Payload == "" {
		return
	}
	got, err := decryptRSA(priv, kv.Payload)
	if err != nil {
		return
	}
	require.NotEqual(t, testSecretValue, got, "secret leaked in non-200 response body")
}

// TestHandlerHappyPath confirms a correctly signed, in-CIDR, fresh request
// still returns the secret after the security hardening.
func TestHandlerHappyPath(t *testing.T) {
	ts, server, signingPriv := newTestServer(t)
	clientPub, clientPriv, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)

	req := craftRequest(t, server.keyRsaPublic, signingPriv, testSecretName, clientPub, time.Now().Unix())
	resp, body := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var kv kvResponse
	require.NoError(t, json.Unmarshal(body, &kv))
	got, err := decryptRSA(clientPriv, kv.Payload)
	require.NoError(t, err)
	require.Equal(t, testSecretValue, got)
}

// TestHandlerRejectsPubkeySubstitution is the regression test for the
// unauthenticated-ClientPubKey flaw: a captured, validly-signed request replayed
// with the attacker's own response key must be rejected, and must not leak the
// secret encrypted to the attacker's key.
func TestHandlerRejectsPubkeySubstitution(t *testing.T) {
	ts, server, signingPriv := newTestServer(t)
	clientPub, _, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)
	attackerPub, attackerPriv, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)

	// legitimate signed request, then swap in the attacker's response key
	// while keeping the original signature and payload.
	req := craftRequest(t, server.keyRsaPublic, signingPriv, testSecretName, clientPub, time.Now().Unix())
	req.ClientPubKey = attackerPub

	resp, body := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assertSecretNotLeaked(t, body, attackerPriv)
}

// TestHandlerRejectsOutOfCIDR is the regression test for the missing-return CIDR
// bug: a fully valid request from outside the allowed CIDR must be blocked and
// must not leak the secret.
func TestHandlerRejectsOutOfCIDR(t *testing.T) {
	ts, server, signingPriv := newTestServer(t)
	clientPub, clientPriv, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)

	// test requests originate from 127.0.0.1; exclude it from the allowlist.
	prev := Defaults.AllowCIDR
	Defaults.AllowCIDR = "10.0.0.0/24"
	t.Cleanup(func() { Defaults.AllowCIDR = prev })

	req := craftRequest(t, server.keyRsaPublic, signingPriv, testSecretName, clientPub, time.Now().Unix())
	resp, body := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assertSecretNotLeaked(t, body, clientPriv)
}

// TestHandlerRejectsReplay is the regression test for the seen-nonce cache: an
// identical, validly-signed, in-window request replayed verbatim is served once
// and rejected the second time.
func TestHandlerRejectsReplay(t *testing.T) {
	ts, server, signingPriv := newTestServer(t)
	clientPub, clientPriv, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)

	req := craftRequest(t, server.keyRsaPublic, signingPriv, testSecretName, clientPub, time.Now().Unix())

	resp1, _ := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, body2 := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
	assertSecretNotLeaked(t, body2, clientPriv)
}

// TestHandlerRejectsStaleTimestamp is the regression test for the replay
// window: a request whose signed timestamp is outside MaxClockSkew is rejected
// even though the signature itself is valid.
func TestHandlerRejectsStaleTimestamp(t *testing.T) {
	ts, server, signingPriv := newTestServer(t)
	clientPub, clientPriv, err := newPairRSA(Defaults.BitsizeRSA)
	require.NoError(t, err)

	stale := time.Now().Add(-1 * time.Hour).Unix()
	req := craftRequest(t, server.keyRsaPublic, signingPriv, testSecretName, clientPub, stale)
	resp, body := postRequest(t, ts.URL, req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assertSecretNotLeaked(t, body, clientPriv)
}
