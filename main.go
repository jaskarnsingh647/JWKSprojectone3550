package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This code was made with the assistance of AI.
// Name: Jaskarn Singh EUID: js2411

type RSAKey struct {
	Priv      *rsa.PrivateKey
	Kid       string
	ExpiresAt time.Time
}
type Manager struct {
	mu   sync.RWMutex
	list []*RSAKey
}

func NewManager() *Manager { return &Manager{} }
func (m *Manager) GenerateKey(ttl time.Duration) (*RSAKey, error) {
	p, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	h := sha1.Sum(p.PublicKey.N.Bytes())
	k := &RSAKey{
		Priv: p, Kid: hex.EncodeToString(h[:8]),
		ExpiresAt: time.Now().Add(ttl),
	}
	m.mu.Lock()
	m.list = append([]*RSAKey{k}, m.list...)
	m.mu.Unlock()
	return k, nil
}
func (m *Manager) ActiveKeys(now time.Time) []*RSAKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*RSAKey
	for _, k := range m.list {
		if now.Before(k.ExpiresAt) {
			out = append(out, k)
		}
	}
	return out
}
func (m *Manager) LatestActiveKey(now time.Time) *RSAKey {
	for _, k := range m.ActiveKeys(now) {
		return k
	}
	return nil
}
func (m *Manager) LatestExpiredKey(now time.Time) *RSAKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.list {
		if !now.Before(k.ExpiresAt) {
			return k
		}
	}
	return nil
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func RSAPublicToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: b64url(pub.N.Bytes()), E: b64url(big.NewInt(int64(pub.E)).Bytes())}
}

func registerRoutes(mux *http.ServeMux, km *Manager) {
	serveJWKS := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			active := km.ActiveKeys(time.Now())
			jwks := JWKS{Keys: make([]JWK, 0, len(active))}
			for _, k := range active {
				jwks.Keys = append(jwks.Keys, RSAPublicToJWK(&k.Priv.PublicKey, k.Kid))
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
	mux.HandleFunc("/.well-known/jwks.json", serveJWKS)
	mux.HandleFunc("/jwks", serveJWKS)

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		now := time.Now()
		var k *RSAKey
		if r.URL.Query().Has("expired") {
			k = km.LatestExpiredKey(now)
			if k == nil {
				http.Error(w, "no expired key available", http.StatusServiceUnavailable)
				return
			}
		} else {
			k = km.LatestActiveKey(now)
			if k == nil {
				http.Error(w, "no active key available", http.StatusServiceUnavailable)
				return
			}
		}
		claims := jwt.MapClaims{
			"sub": "mock-user-id-123", "iss": "go-jwks-server",
			"iat": jwt.NewNumericDate(now), "exp": jwt.NewNumericDate(k.ExpiresAt),
			"kid": k.Kid,
		}
		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		t.Header["kid"] = k.Kid
		signed, err := t.SignedString(k.Priv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": signed})
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// run() lets tests exercise startup/shutdown; main() remains tiny.
func run(ctx context.Context, addr string, km *Manager) error {
	mux := http.NewServeMux()
	registerRoutes(mux, km)
	srv := &http.Server{Addr: addr, Handler: logRequests(mux)}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func main() {
	km := NewManager()
	if _, err := km.GenerateKey(envDuration("ACTIVE_TTL", 24*time.Hour)); err != nil {
		log.Fatalf("active key: %v", err)
	}
	if _, err := km.GenerateKey(-envDuration("EXPIRED_AGE", 24*time.Hour)); err != nil {
		log.Fatalf("expired key: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("JWKS server listening on %s", ":8080")
	if err := run(ctx, ":8080", km); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
