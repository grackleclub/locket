package locket

import (
	"log/slog"
	"testing"
)

type service struct {
	name       string
	IPs        []string
	secrets    []string
	PubSignKey string
}

// type source string

// var (
// 	SourceEnv  source = "env"  // environment vars
// 	SourceOp   source = "op"   // 1password
// 	SourceFile source = "file" // file
// )

// kvRequest contains
type kvRequest struct {
	Payload          string `json:"payload"`       // client request for kv pairs
	ClientPubKey     string `json:"client_pubkey"` // public key used to encrypt payload
	PayloadSignature string `json:"signature"`     // ed25519 signature of payload
}

type kvResponse struct {
	Payload string `json:"payload"`
}

func init() {
	if testing.Testing() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
}
