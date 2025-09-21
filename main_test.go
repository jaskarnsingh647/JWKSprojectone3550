package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This code was made with the assistance of AI.
// Name: Jaskarn Singh EUID: js2411

type jwksPayload struct {
	Keys []JWK `json:"keys"`
}

func newTS(t *testing.T, withActive, withExpired bool) (*httptest.Server, *Manager) {
	t.Helper()
	km := NewManager()
	if withActive {
		if _, err := km.GenerateKey(1 * time.Hour); err != nil {
			t.Fatalf("active: %v", err)
		}
	}
	if withExpired {
		if _, err := km.GenerateKey(-1 * time.Hour); err != nil {
			t.Fatalf("expired: %v", err)
		}
	}
	mux := http.NewServeMux()
	registerRoutes(mux, km)
	return httptest.NewServer(mux), km
}

func TestJWKS_GET_HEAD_and_Methods(t *testing.T) {
	srv, km := newTS(t, true, true)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("jwks status: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct == "" {
		t.Fatalf("missing content-type")
	}
	var set jwksPayload
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatalf("expected >=1 active key")
	}
	if exp := km.LatestExpiredKey(time.Now()); exp != nil {
		for _, k := range set.Keys {
			if k.Kid == exp.Kid {
				t.Fatalf("expired kid leaked")
			}
		}
	}

	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/.well-known/jwks.json", nil)
	headRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer headRes.Body.Close()
	if headRes.StatusCode != http.StatusOK {
		t.Fatalf("jwks HEAD: %d", headRes.StatusCode)
	}

	reqBad, _ := http.NewRequest(http.MethodPost, srv.URL+"/.well-known/jwks.json", nil)
	badRes, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatal(err)
	}
	defer badRes.Body.Close()
	if badRes.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("jwks 405: %d", badRes.StatusCode)
	}
	if badRes.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("jwks Allow: %q", badRes.Header.Get("Allow"))
	}
}

func TestAuth_Active_and_Expired(t *testing.T) {
	srv, km := newTS(t, true, true)
	defer srv.Close()

	// Active token
	ar, err := http.Post(srv.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ar.Body.Close()
	if ar.StatusCode != http.StatusOK {
		t.Fatalf("auth status: %d", ar.StatusCode)
	}
	if ct := ar.Header.Get("Content-Type"); ct == "" {
		t.Fatalf("auth content-type missing")
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(ar.Body).Decode(&out); err != nil {
		t.Fatalf("auth decode: %v", err)
	}
	act := km.LatestActiveKey(time.Now())
	if act == nil {
		t.Fatalf("no active")
	}
	tok, err := jwt.Parse(out.Token, func(t *jwt.Token) (any, error) { return &act.Priv.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		t.Fatalf("active token invalid: %v", err)
	}
	cs, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type")
	}
	expND, err := cs.GetExpirationTime()
	if err != nil || expND == nil {
		t.Fatalf("active exp missing: %v", err)
	}
	if !expND.Time.After(time.Now()) {
		t.Fatalf("active exp not future: %v", expND.Time)
	}

	// 405 + Allow
	gr, err := http.Get(srv.URL + "/auth")
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Body.Close()
	if gr.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("auth 405: %d", gr.StatusCode)
	}
	if gr.Header.Get("Allow") != "POST" {
		t.Fatalf("auth Allow: %q", gr.Header.Get("Allow"))
	}

	// Expired token
	er, err := http.Post(srv.URL+"/auth?expired=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer er.Body.Close()
	if err := json.NewDecoder(er.Body).Decode(&out); err != nil {
		t.Fatalf("expired decode: %v", err)
	}
	expK := km.LatestExpiredKey(time.Now())
	if expK == nil {
		t.Fatalf("no expired")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	tok2, err := parser.Parse(out.Token, func(t *jwt.Token) (any, error) { return &expK.Priv.PublicKey, nil })
	if err != nil || !tok2.Valid {
		t.Fatalf("expired token invalid: %v", err)
	}
	cs2, ok := tok2.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type")
	}
	expND2, err := cs2.GetExpirationTime()
	if err != nil || expND2 == nil {
		t.Fatalf("expired exp missing: %v", err)
	}
	if expND2.Time.After(time.Now()) {
		t.Fatalf("expired exp not past: %v", expND2.Time)
	}
}

func TestRun_StartAndShutdown(t *testing.T) {
	km := NewManager()
	if _, err := km.GenerateKey(10 * time.Minute); err != nil {
		t.Fatalf("active: %v", err)
	}
	if _, err := km.GenerateKey(-10 * time.Minute); err != nil {
		t.Fatalf("expired: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, ":0", km) }()
	time.Sleep(50 * time.Millisecond) // let it start
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run error: %v", err)
	}
}

// ---- Extra minimal tests to push coverage >80% ----

func TestHelpers_Env_JWK_Logger(t *testing.T) {
	// envDuration: default, valid, invalid
	key := "TEST_DURATION_X"
	_ = os.Unsetenv(key)
	if got := envDuration(key, 42*time.Second); got != 42*time.Second {
		t.Fatalf("default mismatch: %v", got)
	}
	_ = os.Setenv(key, "90m")
	if got := envDuration(key, 1*time.Second); got != 90*time.Minute {
		t.Fatalf("parse mismatch: %v", got)
	}
	_ = os.Setenv(key, "not-a-duration")
	if got := envDuration(key, 7*time.Millisecond); got != 7*time.Millisecond {
		t.Fatalf("bad parse should default: %v", got)
	}
	_ = os.Unsetenv(key)

	// RSAPublicToJWK: exercise conversion once
	km := NewManager()
	k, err := km.GenerateKey(5 * time.Minute)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	j := RSAPublicToJWK(&k.Priv.PublicKey, k.Kid)
	if j.Kty != "RSA" || j.Kid != k.Kid || j.Alg != "RS256" || j.N == "" || j.E == "" {
		t.Fatalf("bad jwk: %+v", j)
	}

	// logRequests: just execute the wrapper once
	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestManager_LatestExpiredIsNewest(t *testing.T) {
	km := NewManager()
	// two expired keys; ensure we get the newest one
	first, err := km.GenerateKey(-2 * time.Hour)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	second, err := km.GenerateKey(-1 * time.Hour)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	got := km.LatestExpiredKey(time.Now())
	if got == nil || got.Kid != second.Kid {
		t.Fatalf("expected newest expired %s, got %+v (first %s)", second.Kid, got, first.Kid)
	}
}

func TestJWKS_CustomPath_EqualsWellKnown(t *testing.T) {
	srv, _ := newTS(t, true, false)
	defer srv.Close()

	a, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Body.Close()
	b, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Body.Close()

	var one, two jwksPayload
	if err := json.NewDecoder(a.Body).Decode(&one); err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(b.Body).Decode(&two); err != nil {
		t.Fatal(err)
	}
	if len(one.Keys) != len(two.Keys) {
		t.Fatalf("jwks mismatch: %d vs %d", len(one.Keys), len(two.Keys))
	}
}

func TestAuth_NoActiveKey_503(t *testing.T) {
	srv, _ := newTS(t, false, true) // only expired key
	defer srv.Close()

	res, err := http.Post(srv.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", res.StatusCode)
	}
}

func TestAuth_ExpiredRequested_NoExpiredKey_503(t *testing.T) {
	srv, _ := newTS(t, true, false) // only active key
	defer srv.Close()

	res, err := http.Post(srv.URL+"/auth?expired=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", res.StatusCode)
	}
}
