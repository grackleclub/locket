package locket

import (
	"context"
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
	_, network, cidrErr := net.ParseCIDR(cidr)

	return func(r *http.Request) error {
		if cidrErr != nil {
			return fmt.Errorf("parse CIDR: %w", cidrErr)
		}
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return fmt.Errorf("parse remote addr: %w", err)
		}
		clientIP := net.ParseIP(ip)
		if clientIP == nil {
			return fmt.Errorf("parse ip: %q", ip)
		}
		if !network.Contains(clientIP) {
			return fmt.Errorf("IP %s not in %s", ip, cidr)
		}
		return nil
	}
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
	seen          *nonceCache
	cancel        context.CancelFunc // stops the registry poll goroutine
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
	ctx context.Context,
	opts source,
	reg Registry,
	pollInterval time.Duration,
	allow AllowRequestFunc,
) (*Server, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if reg == nil {
		return nil, fmt.Errorf("registry must not be nil")
	}

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
		seen:          newNonceCache(Defaults.MaxClockSkew),
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
				"opts.Path must be set to the .env file path",
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
		// derive a child context so Close can stop polling independently of
		// the caller's context (which may be context.Background()).
		pollCtx, cancel := context.WithCancel(ctx)
		server.cancel = cancel
		go server.poll(pollCtx, pollInterval)
	}

	return server, nil
}

// Close releases the server's background resources: the registry poll
// goroutine (if any) and the nonce-cache sweeper. The Server must not be used
// after Close.
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.seen.close()
}

// poll refreshes the registry on a fixed interval until ctx is cancelled.
func (s *Server) poll(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
	if err := s.allow(r); err != nil {
		log.Warn("request denied",
			"request_id", id,
			"ip", r.RemoteAddr,
			"error", err,
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	const maxBody = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var request kvRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			http.Error(w,
				"request entity too large",
				http.StatusRequestEntityTooLarge,
			)
			return
		}
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
	log.Debug("request payload decrypted", "request_id", id)

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

	// verify signature against registry; the signed message binds the client
	// pubkey, timestamp, and nonce so a captured request cannot be replayed
	// with a substituted ClientPubKey to redirect the secret.
	registry := s.registrySnapshot()
	var verifiedService string
	message := requestMessage(
		payload, request.ClientPubKey, request.Timestamp, request.Nonce,
	)
	for _, svc := range registry {
		match, err := verifyEd25519(
			svc.KeyPub, message, request.PayloadSignature,
		)
		if err != nil {
			log.Error("verify signature",
				"request_id", id, "error", err,
			)
			continue
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
