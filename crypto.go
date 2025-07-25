package locket

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// newPairRSA generates a new RSA key pair with the given number of bits.
func newPairRSA(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("generate key pair: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

// encryptRSA encrypts plaintext with publicKeyPEM generated by NewPairRSA(),
func encryptRSA(publicKeyPEM, plaintext string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return "", errors.New("decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not RSA public key")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, []byte(plaintext), nil)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptRSA decrypts ciphertext with privateKeyPEM generated by NewPairRSA(),
func decryptRSA(privateKeyPEM, ciphertext string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// NewPairEd25519 generates a new Ed25519 key pair used to authenticate
// clients requests to the server.
// Returns: publicKeyPEM, privateKeyPEM, error.
func NewPairEd25519() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ked25519 ey pair: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey.Seed(),
	})

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKey,
	})

	return string(publicKeyPEM), string(privateKeyPEM), nil
}

// signEd25519 signs a message with privateKeyPEM generated by NewPairEd25519(),
// and returns a base64 encoded signature.
func signEd25519(privateKeyPEM, message string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privateKey := ed25519.NewKeyFromSeed(block.Bytes)

	signature := ed25519.Sign(privateKey, []byte(message))

	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyEd25519 verifies a message with publicKeyPEM, generated by NewPairEd25519(),
// and a base64 encoded signature produced by SignEd25519().
func verifyEd25519(publicKeyPEM, message, signature string) (bool, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "ED25519 PUBLIC KEY" {
		return false, errors.New("failed to decode PEM block containing public key")
	}

	publicKey := ed25519.PublicKey(block.Bytes)

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}

	valid := ed25519.Verify(publicKey, []byte(message), signatureBytes)

	return valid, nil
}
