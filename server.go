package locket

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

type Server struct {
	// source   source            // where serets originate
	secrets       map[string]string // secret k/v pairs
	registry      []service         // registered services
	keyRsaPublic  string            // encryption public key
	keyRsaPrivate string            // encryption private key
}

type service struct {
	name       string
	IPs        []string
	secrets    []string
	PubSignKey string
}

func NewServer() (*Server, error) {
	var server Server
	var err error
	server.keyRsaPublic, server.keyRsaPrivate, err = newPairRSA(2048)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	server.secrets = map[string]string{
		"foo": "bigsecret",
		"bar": "supersecret",
	}

	// TODO load registry

	return &server, nil
}

func (s *Server) Handler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("received request",
		"method", r.Method,
		"url", r.URL.String(),
		"ip", r.RemoteAddr,
	)
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Allow", fmt.Sprintf("%s, %s", http.MethodGet, http.MethodPost))
		return
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(s.keyRsaPublic))
		return
	case http.MethodPost:
		var request kvRequest
		// slog.Debug("decoding request", "body", r.Body)
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		slog.Debug("request",
			"payload", request.Payload,
			"client_pubkey", request.ClientPubKey,
			"signature", request.PayloadSignature,
		)
		payload, err := decryptRSA(s.keyRsaPrivate, request.Payload)
		if err != nil {
			slog.Error("decrypt payload", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		slog.Debug("decrypted payload", "payload", payload)
		// TOOD load another way
		s.registry = []service{
			{
				name:       "service1",
				IPs:        []string{"localhost"},
				secrets:    []string{"foo"},
				PubSignKey: os.Getenv(ClientSigningPubkey),
			},
		}
		// verify signature
		match, err := verifyEd25519(request.ClientPubKey, request.Payload, request.PayloadSignature)
		if err != nil {
			slog.Error("verify signature", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		if !match {
			slog.Error("signature mismatch")
			http.Error(w, "forbidden", http.StatusForbidden)
		}

		// TODO ensure secret is registered to service just verified
		// ecrypt secret with client public key
		// return

		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
