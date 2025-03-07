package locket

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testCypher = []byte(
	`Sometimes we are blessed 
with being able to choose 
the time, and the arena, 
and the manner of our revolution, 
but more usually 
we must do battle 
where we are standing.
`)

func TestRSA(t *testing.T) {
	t.Logf("plaintext (original): \n%s", testCypher)
	publicKeyPEM, privateKeyPEM, err := newPairRSA(2048)
	require.NoError(t, err)
	t.Logf("public key:\n%s", publicKeyPEM)
	t.Logf("private key:\n%s", privateKeyPEM)

	ciphertext, err := encryptRSA(publicKeyPEM, string(testCypher))
	require.NoError(t, err)
	t.Logf("ciphertext:\n%s", ciphertext)

	plaintext, err := decryptRSA(privateKeyPEM, ciphertext)
	require.NoError(t, err)
	t.Logf("plaintext (decrypted):\n%s", plaintext)

	require.Equal(t, string(testCypher), plaintext)
}

func TestEd25519(t *testing.T) {
	t.Logf("plaintext (original): \n%s", testCypher)
	publicKey, privateKey, err := NewPairEd25519()
	require.NoError(t, err)
	t.Logf("public key:\n%s", publicKey)
	t.Logf("private key:\n%s", privateKey)

	signature, err := signEd25519(privateKey, string(testCypher))
	require.NoError(t, err)
	t.Logf("signature:\n%s", signature)

	match, err := verifyEd25519(publicKey, string(testCypher), signature)
	require.NoError(t, err)
	require.True(t, match)
	t.Logf("signature verified")
}
