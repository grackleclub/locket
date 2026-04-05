package locket

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AllowRequestFunc decides whether an HTTP request is permitted.
// Return nil to allow, or an error to deny with 403.
type AllowRequestFunc func(r *http.Request) error

// AllowCIDR returns an AllowRequestFunc that permits requests from
// the given CIDR range only. This is the default policy when
// none is provided to NewServer.
func AllowCIDR(cidr string) AllowRequestFunc {
	return func(r *http.Request) error {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return fmt.Errorf("parse remote addr: %w", err)
		}
		clientIP := net.ParseIP(ip)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}
		if !network.Contains(clientIP) {
			return fmt.Errorf("IP %s not in %s", ip, cidr)
		}
		return nil
	}
}

// Server serves secrets to authenticated clients over HTTP.
// It validates client requests against a Registry of authorized
// signing keys, refreshing the registry on a configurable interval.
type Server struct {
	secrets       map[string]Secrets
	reg           Registry
	entries       []RegEntry
	mu            sync.RWMutex
	allow         AllowRequestFunc
	keyRsaPublic  string
	keyRsaPrivate string
}

// kvResponse is the server's encrypted secret response.
type kvResponse struct {
	Payload string `json:"payload"`
}

// NewServer creates a Server, loading secrets from the given source
// and authorized clients from the given Registry. If pollInterval
// is positive, the server refreshes its registry in the background.
// If allow is nil, AllowCIDR(Defaults.AllowCIDR) is used.
func NewServer(
	opts source,
	reg Registry,
	pollInterval time.Duration,
	allow AllowRequestFunc,
) (*Server, error) {
	rsaPublic, rsaPrivate, err := newPairRSA(Defaults.BitsizeRSA)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	entries, err := reg.Entries()
	if err != nil {
		return nil, fmt.Errorf("initial registry fetch: %w", err)
	}
	log.Info("registry loaded", "entries", len(entries))

	if allow == nil {
		allow = AllowCIDR(Defaults.AllowCIDR)
	}

	server := &Server{
		reg:           reg,
		entries:       entries,
		allow:         allow,
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
	case Dotenv:
		if len(opts.ServiceSecrets) == 0 {
			return nil, fmt.Errorf(
				"at least one service required to load *.env file",
			)
		}
		if opts.Path == "" {
			return nil, fmt.Errorf(
				"at least one path required to *.env file",
			)
		}
		secrets, err := opts.Load()
		if err != nil {
			return nil, fmt.Errorf("load .env file: %w", err)
		}
		server.secrets = secrets
	case Onepass:
		secrets, err := opts.Load()
		if err != nil {
			return nil, fmt.Errorf("load onepass: %w", err)
		}
		server.secrets = secrets
	default:
		return nil, fmt.Errorf("invalid source")
	}

	if pollInterval > 0 {
		go server.poll(pollInterval)
	}

	return server, nil
}

// poll refreshes the registry on a fixed interval.
func (s *Server) poll(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		entries, err := s.reg.Entries()
		if err != nil {
			log.Error("registry poll failed", "error", err)
			continue
		}
		s.mu.Lock()
		s.entries = entries
		s.mu.Unlock()
		log.Debug("registry refreshed", "entries", len(entries))
	}
}

// registrySnapshot returns a point-in-time copy of the registry.
func (s *Server) registrySnapshot() []RegEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RegEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Handler is the HTTP handler for the locket secret server.
// GET returns the server's RSA public encryption key.
// POST accepts an encrypted, signed secret request and returns
// the encrypted secret value.
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
		w.Header().Set("Allow", fmt.Sprintf(
			"%s, %s", http.MethodGet, http.MethodPost,
		))
		return
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(s.keyRsaPublic))
		return
	case http.MethodPost:
		s.handlePost(w, r, id)
	default:
		log.Warn("method not allowed",
			"method", r.Method,
			"request_id", id,
			"ip", r.RemoteAddr,
		)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost processes an encrypted secret request.
func (s *Server) handlePost(
	w http.ResponseWriter, r *http.Request, id string,
) {
	var request kvRequest
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
		log.Error("decrypt payload",
			"request_id", id, "error", err,
		)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	log.Debug("request payload decrypted",
		"payload", payload, "request_id", id,
	)

	if err := s.allow(r); err != nil {
		log.Warn("request denied",
			"request_id", id,
			"ip", r.RemoteAddr,
			"error", err,
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// verify signature against registry
	registry := s.registrySnapshot()
	var verifiedService string
	for _, svc := range registry {
		match, err := verifyEd25519(
			svc.KeyPub, payload, request.PayloadSignature,
		)
		if err != nil {
			log.Error("verify signature",
				"request_id", id, "error", err,
			)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if match {
			verifiedService = svc.Name
			break
		}
	}
	if verifiedService == "" {
		log.Error("signature mismatch", "request_id", id)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	log.Debug("signature verified",
		"service", verifiedService, "request_id", id,
	)

	secrets, ok := s.secrets[strings.ToLower(verifiedService)]
	if !ok {
		log.Warn("service not found, check case (expects lower)",
			"service", verifiedService,
			"request_id", id,
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	value, ok := secrets[payload]
	if !ok {
		log.Warn("secret not found",
			"service", verifiedService,
			"key", payload,
			"request_id", id,
		)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	encrypted, err := encryptRSA(request.ClientPubKey, value)
	if err != nil {
		log.Error("encrypt secret",
			"request_id", id, "error", err,
		)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(kvResponse{Payload: encrypted})
	if err != nil {
		log.Error("encode response",
			"request_id", id, "error", err,
		)
		return
	}
	log.Info("sending secret",
		"service", verifiedService,
		"name", payload,
		"ip", r.RemoteAddr,
		"request_id", id,
	)
}
