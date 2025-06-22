package locket

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
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
	id := uuid.New().String()
	log.Info("received request",
		"method", r.Method,
		"url", r.URL.String(),
		"ip", r.RemoteAddr,
		"request_id", id,
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
		// log.Debug("decoding request", "body", r.Body)
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Debug("request",
			"payload", request.Payload,
			"client_pubkey", request.ClientPubKey,
			"signature", request.PayloadSignature,
			"request_id", id,
		)
		payload, err := decryptRSA(s.keyRsaPrivate, request.Payload)
		if err != nil {
			log.Error("decrypt payload", "request_id", id, "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		log.Debug("request payload decrypted", "payload", payload, "request_id", id)

		// require from CIDR range DefaultAllowCIDR
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Error("split host port", "request_id", id, "error", err)
			// maybe a 5xx, but probably only because of malformed host addr
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		clientIP := net.ParseIP(ip)
		_, cidr, err := net.ParseCIDR(Defaults.AllowCIDR)
		if err != nil {
			log.Error("parse CIDR", "request_id", id, "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !cidr.Contains(clientIP) {
			log.Warn("IP rejected",
				"request_id", id,
				"ip", r.RemoteAddr,
				"allowCIDR", Defaults.AllowCIDR,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			log.Debug("IP allowed",
				"request_id", id,
				"ip", r.RemoteAddr,
				"allowCIDR", Defaults.AllowCIDR,
			)
		}

		// verify signature against registry
		var matches bool
		var verifiedService string
		log.Debug("verifying signature", "request_id", id)
		for _, svc := range s.registry {
			match, err := verifyEd25519(svc.KeyPub, payload, request.PayloadSignature)
			if err != nil {
				log.Error("verify signature", "request_id", id, "error", err)
				http.Error(w, "bad request", http.StatusBadRequest)
			}
			if match {
				matches = true
				verifiedService = svc.Name
				break
			}
		}
		if !matches {
			log.Error("signature mismatch", "request_id", id)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		} else {
			log.Debug("signature verified",
				"service", verifiedService,
				"request_id", id,
			)
		}

		log.Debug("secrets for service", "service", verifiedService, "secrets_qty", len(s.secrets))
		secrets, ok := s.secrets[strings.ToLower(verifiedService)]
		if !ok {
			log.Warn("service not found in registry, check case sensitivity (expects lower)",
				"service_requesting", verifiedService,
				"request_id", id,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		value, ok := secrets[payload]
		if !ok {
			log.Warn("secret not found", "service", verifiedService, "key", payload, "request_id", id)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		ecryptedSecret, err := encryptRSA(request.ClientPubKey, value)
		if err != nil {
			log.Error("encrypt secret", "request_id", id, "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		response := kvResponse{
			Payload: ecryptedSecret,
		}
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.Error("encode response", "request_id", id, "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		log.Info("sending secret",
			"service", verifiedService,
			"name", payload,
			"ip", r.RemoteAddr,
			"request_id", id,
		)
		w.Header().Set("Content-Type", "application/json")
	default:
		log.Warn("method not allowed", "method", r.Method, "request_id", id, "ip", r.RemoteAddr)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
