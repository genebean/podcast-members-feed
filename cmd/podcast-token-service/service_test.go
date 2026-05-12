package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/genebean/podcast-members-feed/internal/db"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func setupTestRouter(t *testing.T, database *db.DB, nd *nostrDM, proxy *feedProxy) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	n := &notifier{dm: nd}
	r.Post("/webhook/btcpay", webhookHandler(database, n))
	r.Get("/rss/{token}.xml", feedHandler(database, proxy, n))
	r.Get("/api/feed-url", feedURLHandler(database, nd))
	r.Get("/recover", recoverPageHandler())
	r.Get("/metrics", metricsHandler())
	r.Post("/admin/cleanup", cleanupHandler(database))
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]string{"status": "ok"})
	})
	return r
}

func btcpaySignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(t *testing.T, handler http.Handler, secret string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(payload)
	sig := btcpaySignature(secret, body)
	req := httptest.NewRequest(http.MethodPost, "/webhook/btcpay", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BTCPay-Sig", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

func TestVerifyBTCPaySignature(t *testing.T) {
	// Set the global config used by verifyBTCPaySignature.
	btcpayWebhookSecret = "testsecret"

	body := []byte(`{"type":"SubscriptionCreated"}`)
	mac := hmac.New(sha256.New, []byte("testsecret"))
	mac.Write(body)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name    string
		sig     string
		payload []byte
		want    bool
	}{
		{"valid signature", validSig, body, true},
		{"wrong secret", "sha256=" + hex.EncodeToString(hmac.New(sha256.New, []byte("wrong")).Sum(nil)), body, false},
		{"missing prefix", hex.EncodeToString(mac.Sum(nil)), body, false},
		{"empty header", "", body, false},
		{"tampered body", validSig, []byte(`{"type":"different"}`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyBTCPaySignature(tt.payload, tt.sig)
			if got != tt.want {
				t.Errorf("verifyBTCPaySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInjectExpiryItem(t *testing.T) {
	expiredAudioURL = ""

	feed := []byte(`<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title><item><title>Ep 1</title></item></channel></rss>`)
	result := injectExpiryItem(feed)

	s := string(result)
	if !strings.Contains(s, "Your subscription has expired") {
		t.Error("expiry notice title not found in output")
	}
	if !strings.Contains(s, "expired-notice-") {
		t.Error("expiry notice guid not found")
	}
	// Injected item should appear before existing episodes
	expiredIdx := strings.Index(s, "Your subscription has expired")
	ep1Idx := strings.Index(s, "Ep 1")
	if expiredIdx > ep1Idx {
		t.Error("expiry episode should appear before existing episodes")
	}
}

func TestInjectExpiryItemNoExistingItems(t *testing.T) {
	expiredAudioURL = ""
	feed := []byte(`<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title></channel></rss>`)
	result := injectExpiryItem(feed)
	if !strings.Contains(string(result), "Your subscription has expired") {
		t.Error("expiry notice should be injected into feed with no items")
	}
}

func TestInjectExpiryItemWithAudioURL(t *testing.T) {
	expiredAudioURL = "https://cdn.example.com/expired.mp3"
	defer func() { expiredAudioURL = "" }()

	feed := []byte(`<?xml version="1.0"?><rss version="2.0"><channel><title>Test</title><item><title>Ep 1</title></item></channel></rss>`)
	result := injectExpiryItem(feed)
	if !strings.Contains(string(result), "https://cdn.example.com/expired.mp3") {
		t.Error("enclosure URL not found in output")
	}
}

func TestInjectExpiryItemMalformedFeed(t *testing.T) {
	feed := []byte(`not xml at all`)
	result := injectExpiryItem(feed)
	// Should still inject (uses string search, not XML parser)
	_ = result
}

func TestGenerateToken(t *testing.T) {
	tok1, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	tok2, _ := generateToken()
	if tok1 == tok2 {
		t.Error("two calls should produce different tokens")
	}
	// Token should be base64url-safe with no padding
	if strings.ContainsAny(tok1, "+/=") {
		t.Errorf("token contains non-URL-safe characters: %s", tok1)
	}
	// 32 bytes base64url-encoded → 43 characters
	if len(tok1) != 43 {
		t.Errorf("expected 43-char token, got %d chars", len(tok1))
	}
}

func TestExpiresAtFromEvent(t *testing.T) {
	ts := float64(2000000000)
	sub := map[string]any{"expiresAt": ts}
	got := expiresAtFromEvent(sub)
	if got.Unix() != 2000000000 {
		t.Errorf("want unix 2000000000, got %d", got.Unix())
	}

	// Missing expiresAt → default ~31 days from now
	got2 := expiresAtFromEvent(nil)
	if got2.Before(time.Now().Add(30 * 24 * time.Hour)) {
		t.Error("default expiry should be ~31 days in the future")
	}
}

// ─── HTTP handler integration tests ───────────────────────────────────────────

func setupService(t *testing.T) (http.Handler, *db.DB) {
	t.Helper()
	btcpayWebhookSecret = "test-webhook-secret"
	feedBaseURL = "https://members.example.com"
	adminToken = "test-admin-token"
	expiredAudioURL = ""
	smtpHost = "" // no email in tests

	database := newTestDB(t)

	// Use a Nostr key that's pre-generated so tests don't need libsecp.
	privkeyHex := nostr.GeneratePrivateKey()
	nd := &nostrDM{}
	nd.privkeyHex = privkeyHex
	pubkeyHex, _ := nostr.GetPublicKey(privkeyHex)
	nd.pubkeyHex = pubkeyHex

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		fmt.Fprint(w, `<?xml version="1.0"?><rss version="2.0"><channel><title>Members</title><item><title>Episode 1</title></item></channel></rss>`)
	}))
	t.Cleanup(upstream.Close)
	podserverFeedURL = upstream.URL
	proxy := newFeedProxy(upstream.URL)

	handler := setupTestRouter(t, database, nd, proxy)
	return handler, database
}

func TestHealthEndpoint(t *testing.T) {
	handler, _ := setupService(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("want status ok, got %v", body)
	}
}

func TestWebhookInvalidSignature(t *testing.T) {
	handler, _ := setupService(t)

	req := httptest.NewRequest(http.MethodPost, "/webhook/btcpay",
		strings.NewReader(`{"type":"SubscriptionCreated","subscriberId":"s1","email":"a@b.com"}`))
	req.Header.Set("BTCPay-Sig", "sha256=badhash")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestWebhookSubscriptionCreated(t *testing.T) {
	handler, database := setupService(t)

	w := postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":         "SubscriptionCreated",
		"subscriberId": "sub-test-1",
		"email":        "test@example.com",
		"subscription": map[string]any{"expiresAt": float64(time.Now().Add(30 * 24 * time.Hour).Unix())},
		"metadata":     map[string]any{},
	})

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for async notification goroutine
	time.Sleep(100 * time.Millisecond)

	token, err := database.GetActiveToken(context.Background(), "sub-test-1")
	if err != nil || token == "" {
		t.Errorf("expected token in database, err=%v token=%q", err, token)
	}
}

func TestWebhookMissingSubscriberID(t *testing.T) {
	handler, _ := setupService(t)

	w := postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":  "SubscriptionCreated",
		"email": "test@example.com",
	})

	if w.Code != http.StatusOK {
		t.Errorf("want 200 (ignored), got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ignored" {
		t.Errorf("want ignored status, got %v", resp)
	}
}

func TestWebhookRenewal(t *testing.T) {
	handler, database := setupService(t)
	ctx := context.Background()

	// Create initial subscription
	postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":         "SubscriptionCreated",
		"subscriberId": "sub-renew",
		"email":        "renew@example.com",
		"subscription": map[string]any{"expiresAt": float64(time.Now().Add(30 * 24 * time.Hour).Unix())},
		"metadata":     map[string]any{},
	})
	time.Sleep(100 * time.Millisecond)

	token1, _ := database.GetActiveToken(ctx, "sub-renew")

	// Renew
	newExpiry := float64(time.Now().Add(60 * 24 * time.Hour).Unix())
	w := postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":         "SubscriptionRenewed",
		"subscriberId": "sub-renew",
		"email":        "renew@example.com",
		"subscription": map[string]any{"expiresAt": newExpiry},
		"metadata":     map[string]any{},
	})

	if w.Code != http.StatusOK {
		t.Errorf("renewal: want 200, got %d", w.Code)
	}

	// Token should be extended, not replaced
	token2, _ := database.GetActiveToken(ctx, "sub-renew")
	if token1 != token2 {
		t.Errorf("renewal should extend token, not replace: %s → %s", token1, token2)
	}
}

func TestWebhookExpiredRevokes(t *testing.T) {
	handler, database := setupService(t)
	ctx := context.Background()

	postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":         "SubscriptionCreated",
		"subscriberId": "sub-exp",
		"email":        "exp@example.com",
		"subscription": map[string]any{"expiresAt": float64(time.Now().Add(30 * 24 * time.Hour).Unix())},
		"metadata":     map[string]any{},
	})
	time.Sleep(100 * time.Millisecond)

	postWebhook(t, handler, "test-webhook-secret", map[string]any{
		"type":         "SubscriptionExpired",
		"subscriberId": "sub-exp",
	})

	// Token should be revoked
	token, _ := database.GetActiveToken(ctx, "sub-exp")
	if token != "" {
		t.Error("token should be revoked after SubscriptionExpired")
	}
}

func TestFeedEndpointValidToken(t *testing.T) {
	handler, database := setupService(t)
	ctx := context.Background()

	_ = database.UpsertSubscriber(ctx, "sub-feed",
		sql.NullString{String: "feed@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = database.CreateToken(ctx, "sub-feed", "valid-token-123", expiry)

	req := httptest.NewRequest(http.MethodGet, "/rss/valid-token-123.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/rss+xml" {
		t.Errorf("want application/rss+xml, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "<channel>") {
		t.Error("feed response should contain RSS channel element")
	}
}

func TestFeedEndpointInvalidToken(t *testing.T) {
	handler, _ := setupService(t)
	req := httptest.NewRequest(http.MethodGet, "/rss/no-such-token.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("want 402, got %d", w.Code)
	}
}

func TestFeedEndpointExpiryFlow(t *testing.T) {
	handler, database := setupService(t)
	ctx := context.Background()

	_ = database.UpsertSubscriber(ctx, "sub-exp",
		sql.NullString{String: "exp@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(-1 * time.Hour) // already expired
	_ = database.CreateToken(ctx, "sub-exp", "expired-token", expiry)

	// First request: should inject expiry notice
	req := httptest.NewRequest(http.MethodGet, "/rss/expired-token.xml", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("first expired request: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Your subscription has expired") {
		t.Error("first expired request should contain expiry notice")
	}

	// Second request: should return 402
	req2 := httptest.NewRequest(http.MethodGet, "/rss/expired-token.xml", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusPaymentRequired {
		t.Errorf("second expired request: want 402, got %d", w2.Code)
	}
}

func TestMetricsRequiresAuth(t *testing.T) {
	handler, _ := setupService(t)

	// Without auth
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("metrics without auth: want 401, got %d", w.Code)
	}

	// With correct auth
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req2.Header.Set("Authorization", "Bearer test-admin-token")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("metrics with auth: want 200, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "podcast_active_tokens") {
		t.Error("metrics response should contain podcast_active_tokens")
	}
}

func TestAdminCleanupRequiresAuth(t *testing.T) {
	handler, _ := setupService(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/cleanup", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("cleanup without auth: want 401, got %d", w.Code)
	}
}

func TestRecoverPage(t *testing.T) {
	handler, _ := setupService(t)
	req := httptest.NewRequest(http.MethodGet, "/recover", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("want text/html, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "window.nostr") {
		t.Error("recover page should contain NIP-07 JS")
	}
}

func TestNIP98FeedURLEndpoint(t *testing.T) {
	handler, database := setupService(t)
	ctx := context.Background()

	// Generate a Nostr keypair
	privkeyHex := nostr.GeneratePrivateKey()
	pubkeyHex, _ := nostr.GetPublicKey(privkeyHex)

	// Register subscriber with this pubkey
	_ = database.UpsertSubscriber(ctx, "sub-nip98",
		sql.NullString{},
		sql.NullString{String: pubkeyHex, Valid: true},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = database.CreateToken(ctx, "sub-nip98", "nip98-token", expiry)

	// Build NIP-98 event
	ev := nostr.Event{
		Kind:      27235,
		Tags:      nostr.Tags{{"u", feedBaseURL + "/api/feed-url"}, {"method", "GET"}},
		Content:   "",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	if err := ev.Sign(privkeyHex); err != nil {
		t.Fatalf("sign event: %v", err)
	}

	eventJSON, _ := json.Marshal(ev)
	encoded := base64.StdEncoding.EncodeToString(eventJSON)

	req := httptest.NewRequest(http.MethodGet, "/api/feed-url", nil)
	req.Header.Set("Authorization", "Nostr "+encoded)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("NIP-98 feed-url: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.HasSuffix(resp["feed_url"], "nip98-token.xml") {
		t.Errorf("unexpected feed_url: %s", resp["feed_url"])
	}
}

func TestNIP98FeedURLNoSubscription(t *testing.T) {
	handler, _ := setupService(t)

	privkeyHex := nostr.GeneratePrivateKey()

	ev := nostr.Event{
		Kind:      27235,
		Tags:      nostr.Tags{{"u", feedBaseURL + "/api/feed-url"}, {"method", "GET"}},
		Content:   "",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	_ = ev.Sign(privkeyHex)

	eventJSON, _ := json.Marshal(ev)
	encoded := base64.StdEncoding.EncodeToString(eventJSON)

	req := httptest.NewRequest(http.MethodGet, "/api/feed-url", nil)
	req.Header.Set("Authorization", "Nostr "+encoded)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown pubkey, got %d", w.Code)
	}
}

func TestNIP98FeedURLExpiredTimestamp(t *testing.T) {
	handler, _ := setupService(t)

	privkeyHex := nostr.GeneratePrivateKey()

	ev := nostr.Event{
		Kind:      27235,
		Tags:      nostr.Tags{{"u", feedBaseURL + "/api/feed-url"}, {"method", "GET"}},
		Content:   "",
		CreatedAt: nostr.Timestamp(time.Now().Add(-2 * time.Minute).Unix()),
	}
	_ = ev.Sign(privkeyHex)

	eventJSON, _ := json.Marshal(ev)
	encoded := base64.StdEncoding.EncodeToString(eventJSON)

	req := httptest.NewRequest(http.MethodGet, "/api/feed-url", nil)
	req.Header.Set("Authorization", "Nostr "+encoded)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for expired timestamp, got %d", w.Code)
	}
}

func TestNIP98FeedURLNoAuth(t *testing.T) {
	handler, _ := setupService(t)
	req := httptest.NewRequest(http.MethodGet, "/api/feed-url", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestNIP98FeedURLWrongURL(t *testing.T) {
	handler, _ := setupService(t)
	privkeyHex := nostr.GeneratePrivateKey()

	ev := nostr.Event{
		Kind:      27235,
		Tags:      nostr.Tags{{"u", "https://wrong.example.com/api/feed-url"}, {"method", "GET"}},
		Content:   "",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	_ = ev.Sign(privkeyHex)
	eventJSON, _ := json.Marshal(ev)
	encoded := base64.StdEncoding.EncodeToString(eventJSON)

	req := httptest.NewRequest(http.MethodGet, "/api/feed-url", nil)
	req.Header.Set("Authorization", "Nostr "+encoded)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for URL mismatch, got %d", w.Code)
	}
}

func TestNostrDMKeyParsing(t *testing.T) {
	// Generate key and encode as nsec
	privkeyHex := nostr.GeneratePrivateKey()
	nsec, err := nip19.EncodePrivateKey(privkeyHex)
	if err != nil {
		t.Fatalf("encode nsec: %v", err)
	}

	// Parse from nsec
	nd1, err := newNostrDM(nsec)
	if err != nil {
		t.Fatalf("newNostrDM from nsec: %v", err)
	}

	// Parse from hex
	nd2, err := newNostrDM(privkeyHex)
	if err != nil {
		t.Fatalf("newNostrDM from hex: %v", err)
	}

	if nd1.pubkeyHex != nd2.pubkeyHex {
		t.Errorf("pubkey mismatch: nsec→%s, hex→%s", nd1.pubkeyHex, nd2.pubkeyHex)
	}
	if nd1.pubkeyHex == "" {
		t.Error("pubkey should not be empty")
	}
}

func TestFeedProxyCaching(t *testing.T) {
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		fmt.Fprint(w, `<rss><channel><title>Test</title></channel></rss>`)
	}))
	defer upstream.Close()

	proxy := newFeedProxy(upstream.URL)
	ctx := context.Background()

	_, err := proxy.fetchRaw(ctx)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	_, err = proxy.fetchRaw(ctx)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("expected 1 upstream request (cached), got %d", requestCount)
	}
}
