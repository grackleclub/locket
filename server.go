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

type Server struct {
	secrets       map[string]Secrets // secret k/v pairs
	registry      []RegEntry         // registered services
	keyRsaPublic  string             // encryption public key
	keyRsaPrivate string             // encryption private key
	seen          *nonceCache        // request nonces seen within the replay window
}

// nonceCache tracks request nonces so the server can reject exact replays
// within the accepted clock-skew window. A background sweeper evicts entries
// once a replay of that request could no longer pass the timestamp freshness
// check, keeping the map bounded without scanning on the request path.
type nonceCache struct {
	mu       sync.Mutex
	seen     map[string]time.Time // nonce -> expiry
	stop     chan struct{}
	stopOnce sync.Once
}

// newNonceCache returns a cache whose sweeper evicts expired nonces every
// interval until close is called.
func newNonceCache(interval time.Duration) *nonceCache {
	c := &nonceCache{
		seen: make(map[string]time.Time),
		stop: make(chan struct{}),
	}
	go c.sweep(interval)
	return c
}

// observe records nonce with the given expiry and reports whether it was
// already present (i.e. a replay). Eviction happens out of band in sweep; a
// not-yet-swept expired nonce is harmless since stale requests are already
// rejected by the freshness check before reaching here.
func (c *nonceCache) observe(nonce string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[nonce]; ok {
		return true
	}
	c.seen[nonce] = expiry
	return false
}

// sweep periodically deletes expired nonces until the cache is closed.
func (c *nonceCache) sweep(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for n, exp := range c.seen {
				if now.After(exp) {
					delete(c.seen, n)
				}
			}
			c.mu.Unlock()
		}
	}
}

// close stops the sweeper goroutine. Safe to call more than once.
func (c *nonceCache) close() {
	c.stopOnce.Do(func() { close(c.stop) })
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
		seen:          newNonceCache(Defaults.MaxClockSkew),
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

// Close releases the server's background resources (the nonce-cache sweeper).
// The Server must not be used after Close.
func (s *Server) Close() {
	s.seen.close()
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
			return
		}
		log.Debug("request payload decrypted", "request_id", id)

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
			return
		}
		log.Debug("IP allowed",
			"request_id", id,
			"ip", r.RemoteAddr,
			"allowCIDR", Defaults.AllowCIDR,
		)

		// a nonce is required to detect replays
		if request.Nonce == "" {
			log.Warn("request missing nonce", "request_id", id)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// reject stale or future-dated requests to bound replay
		skew := time.Since(time.Unix(request.Timestamp, 0))
		if skew < 0 {
			skew = -skew
		}
		if skew > Defaults.MaxClockSkew {
			log.Warn("request timestamp outside allowed window",
				"request_id", id,
				"skew", skew,
				"max", Defaults.MaxClockSkew,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// verify signature against registry; the signed message binds the
		// client pubkey, timestamp, and nonce so a captured request cannot be
		// replayed with a substituted ClientPubKey to redirect the secret.
		var matches bool
		var verifiedService string
		message := requestMessage(payload, request.ClientPubKey, request.Timestamp, request.Nonce)
		log.Debug("verifying signature", "request_id", id)
		for _, svc := range s.registry {
			match, err := verifyEd25519(svc.KeyPub, message, request.PayloadSignature)
			if err != nil {
				log.Error("verify signature", "request_id", id, "error", err)
				continue
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

		// reject replays: a nonce is valid only until a replay could no longer
		// pass the freshness check above. Checked after signature verification
		// so unauthenticated requests cannot fill the cache.
		expiry := time.Unix(request.Timestamp, 0).Add(Defaults.MaxClockSkew)
		if s.seen.observe(request.Nonce, expiry) {
			log.Warn("replayed request rejected",
				"service", verifiedService,
				"request_id", id,
			)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
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
		// header must be set before the body is written to take effect
		w.Header().Set("Content-Type", "application/json")
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
	default:
		log.Warn("method not allowed", "method", r.Method, "request_id", id, "ip", r.RemoteAddr)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
