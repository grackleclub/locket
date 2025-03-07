package locket

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

var DefaultBitRSA = 2048 // default bit size for RSA keys

type Server struct {
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

type kvResponse struct {
	Payload string `json:"payload"`
}

func NewServer(opts source) (*Server, error) {
	var server Server
	var err error
	server.keyRsaPublic, server.keyRsaPrivate, err = newPairRSA(DefaultBitRSA)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	// TODO load register of allowed client keys
	switch opts := opts.(type) {
	case env:
		secrets, err := opts.load()
		if err != nil {
			return nil, fmt.Errorf("load env: %w", err)
		}
		server.secrets = secrets
		return &server, nil
	case dotenv:
		if opts.path == "" {
			return nil, fmt.Errorf("path required to .env file")
		}
		secrets, err := opts.load()
		if err != nil {
			return nil, fmt.Errorf("load .env file: %w", err)
		}
		server.secrets = secrets
		return &server, nil
	default:
		return nil, fmt.Errorf("invalid source")
	}
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
				IPs:        []string{"127.0.0.1"},
				secrets:    []string{"foo"},
				PubSignKey: os.Getenv(ClientSigningPubkey),
			},
		}
		// require IP to be in registry
		var requestingServiceName string
		var allowedIP bool
		for _, svc := range s.registry {
			for _, ip := range svc.IPs {
				parts := strings.Split(ip, ":")
				requestIP := r.RemoteAddr
				if len(parts) > 0 {
					requestIP = parts[0]
				}
				// slog.Debug("checking IP", "ip", parts[0])
				if ip == requestIP {
					requestingServiceName = svc.name
					slog.Debug("found service with allowed IP", "name", svc.name, "ip", ip)
					allowedIP = true
					break
				}
			}
		}
		if !allowedIP {
			slog.Error("IP not allowed", "ip", r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			slog.Debug("IP allowed", "ip", r.RemoteAddr, "service", requestingServiceName)
		}

		// verify signature
		var matches bool
		slog.Info("verifying signature", "key", s.registry[0].PubSignKey)
		for _, svc := range s.registry {
			match, err := verifyEd25519(svc.PubSignKey, payload, request.PayloadSignature)
			if err != nil {
				slog.Error("verify signature", "error", err)
				http.Error(w, "bad request", http.StatusBadRequest)
			}
			if match {
				matches = true
				break
			}
		}
		if !matches {
			slog.Error("signature mismatch")
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			slog.Debug("signature verified")
		}
		value, ok := s.secrets[payload]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// TODO ensure secret is registered to service just verified
		ecryptedSecret, err := encryptRSA(request.ClientPubKey, value)
		if err != nil {
			slog.Error("encrypt secret", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		response := kvResponse{
			Payload: ecryptedSecret,
		}
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			slog.Error("encode response", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		w.Header().Set("Content-Type", "application/json")

		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
