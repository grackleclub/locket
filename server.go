package locket

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

type Server struct {
	secrets       map[string]Secrets // secret k/v pairs
	registry      []RegEntry         // registered services
	keyRsaPublic  string             // encryption public key
	keyRsaPrivate string             // encryption private key
}

// kvResponse is the server's response to the client's request,
// containing the encrypted secret value.
type kvResponse struct {
	Payload string `json:"payload"`
}

// NewServer sets up a new secrets server when provided source options
// and registry of allowed services (and their public signing keys),
// expected to be read from file or embed before calling NewServer().
func NewServer(opts source, registry []RegEntry) (*Server, error) {
	rsaPublic, rsaPrivate, err := newPairRSA(Defaults.BitsizeRSA)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	server := Server{
		registry:      registry,
		keyRsaPublic:  rsaPublic,
		keyRsaPrivate: rsaPrivate,
	}

	switch opts := opts.(type) {
	case Env:
		secrets, err := opts.Load()
		if err != nil {
			return nil, fmt.Errorf("load env: %w", err)
		}
		server.secrets = secrets
		return &server, nil
	case Dotenv:
		if len(opts.ServiceSecrets) == 0 {
			return nil, fmt.Errorf("at least one service required to load *.env file")
		}
		if opts.Path == "" {
			return nil, fmt.Errorf("at least one path required to *.env file")
		}
		secrets, err := opts.Load()
		if err != nil {
			return nil, fmt.Errorf("load .env file: %w", err)
		}
		server.secrets = secrets
		return &server, nil
	case Onepass:
		secrets, err := opts.Load()
		if err != nil {
			return nil, fmt.Errorf("load onepass: %w", err)
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

		// require from CIDR range DefaultAllowCIDR
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			slog.Error("split host port", "error", err)
			// maybe a 5xx, but probably only because of malformed host addr
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		clientIP := net.ParseIP(ip)
		_, cidr, err := net.ParseCIDR(Defaults.AllowCird)
		if err != nil {
			slog.Error("parse CIDR", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !cidr.Contains(clientIP) {
			slog.Warn("IP rejected",
				"ip", r.RemoteAddr,
				"allowCIDR", Defaults.AllowCird,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			slog.Debug("IP allowed", "ip", r.RemoteAddr)
		}

		// verify signature against registry
		var matches bool
		var verifiedService string
		slog.Info("verifying signature")
		for _, svc := range s.registry {
			match, err := verifyEd25519(svc.KeyPub, payload, request.PayloadSignature)
			if err != nil {
				slog.Error("verify signature", "error", err)
				http.Error(w, "bad request", http.StatusBadRequest)
			}
			if match {
				matches = true
				verifiedService = svc.Name
				break
			}
		}
		if !matches {
			slog.Error("signature mismatch")
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			slog.Debug("signature verified")
		}
		secrets, ok := s.secrets[verifiedService]
		slog.Debug("secrets", "service", verifiedService, "secrets", s.secrets)
		if !ok {
			slog.Warn("service not found in secrets", "service", verifiedService)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		value, ok := secrets[payload]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

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
