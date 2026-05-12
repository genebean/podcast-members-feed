/*
Podcast members feed token service.
Bridges BTCPay Server subscriptions to private RSS feed access.

Deploy behind nginx with TLS termination.
Run via systemd/NixOS service or Podman container.

Environment variables (see podman/.env.example):
  BTCPAY_WEBHOOK_SECRET   shared secret configured in BTCPay webhook settings
  PODSERVER_FEED_URL      internal URL of the PodServer members RSS feed
  FEED_BASE_URL           public base URL for subscriber feed URLs
  DATABASE_PATH           path to SQLite database file
  ADMIN_TOKEN             bearer token for /metrics and /admin/ endpoints
  EXPIRED_AUDIO_URL       public URL of the subscription-expired audio clip
  SMTP_HOST/PORT/USER/PASSWORD/FROM  SMTP credentials
  NOSTR_PRIVATE_KEY       nsec or hex private key for the service keypair
*/
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/genebean/podcast-members-feed/internal/db"
)

// ─── Configuration ───────────────────────────────────────────────────────────

var (
	btcpayWebhookSecret string
	podserverFeedURL    string
	feedBaseURL         string
	databasePath        string
	adminToken          string
	expiredAudioURL     string
	smtpHost            string
	smtpPort            int
	smtpUser            string
	smtpPassword        string
	smtpFrom            string
	nostrPrivateKey     string
)

const (
	tokenBytes = 32
	// feedCacheTTL is how long the upstream RSS feed response is cached in memory.
	// Reduces load on PodServer; all subscribers share one cached copy.
	feedCacheTTL = 5 * time.Minute
	// gracePeriodDays is how many days past expires_at a subscriber still receives
	// the normal feed before the expiry notice episode is injected.
	// This prevents cutting off subscribers the instant their billing cycle turns over.
	gracePeriodDays = 3
)

var nostrRelays = []string{
	"wss://relay.damus.io",
	"wss://nos.lol",
	"wss://relay.primal.net",
	"wss://nostr.data.haus",
}

func loadConfig() {
	_ = godotenv.Load()

	btcpayWebhookSecret = mustEnv("BTCPAY_WEBHOOK_SECRET")
	podserverFeedURL = mustEnv("PODSERVER_FEED_URL")
	feedBaseURL = strings.TrimRight(mustEnv("FEED_BASE_URL"), "/")
	databasePath = envOr("DATABASE_PATH", "tokens.db")
	adminToken = mustEnv("ADMIN_TOKEN")
	expiredAudioURL = os.Getenv("EXPIRED_AUDIO_URL")
	smtpHost = os.Getenv("SMTP_HOST")
	smtpPort = envInt("SMTP_PORT", 587)
	smtpUser = os.Getenv("SMTP_USER")
	smtpPassword = os.Getenv("SMTP_PASSWORD")
	smtpFrom = os.Getenv("SMTP_FROM")
	nostrPrivateKey = mustEnv("NOSTR_PRIVATE_KEY")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "required environment variable %s is not set\n", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// ─── Prometheus metrics ───────────────────────────────────────────────────────

var (
	metricActiveTokens = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "podcast_active_tokens",
		Help: "Current number of non-revoked non-expired tokens",
	})
	metricTotalSubscribers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "podcast_total_subscribers",
		Help: "Total subscribers ever registered",
	})
	metricWebhooksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_webhooks_total",
		Help: "BTCPay webhook events processed successfully",
	}, []string{"event_type"})
	metricWebhookErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_webhook_errors_total",
		Help: "BTCPay webhook processing errors",
	}, []string{"reason"})
	metricFeedRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_feed_requests_total",
		Help: "Feed endpoint requests by result",
	}, []string{"result"})
	metricFeedUpstreamErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "podcast_feed_upstream_errors_total",
		Help: "Failures fetching the upstream PodServer feed",
	})
	metricExpiryNotificationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "podcast_expiry_notifications_total",
		Help: "Expired-subscription audio episodes injected into feeds",
	})
	metricNostrDMTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_nostr_dm_total",
		Help: "Nostr DM delivery attempts by result",
	}, []string{"result"})
	metricNostrDMRelayTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_nostr_dm_relay_total",
		Help: "Nostr relay publish attempts by relay and result",
	}, []string{"relay", "result"})
	metricEmailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_email_total",
		Help: "Email delivery attempts by result",
	}, []string{"result"})
	metricNIP98RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "podcast_nip98_requests_total",
		Help: "NIP-98 feed URL retrieval attempts by result",
	}, []string{"result"})
	metricRecoveryPageVisitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "podcast_recovery_page_visits_total",
		Help: "Visits to the /recover page",
	})
)

// ─── BTCPay webhook verification ─────────────────────────────────────────────

func verifyBTCPaySignature(payload []byte, sigHeader string) bool {
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(btcpayWebhookSecret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	provided := strings.TrimPrefix(sigHeader, "sha256=")
	return hmac.Equal([]byte(expected), []byte(provided))
}

// ─── Feed proxy ───────────────────────────────────────────────────────────────

type feedProxy struct {
	url       string
	mu        sync.Mutex
	cache     []byte
	cacheTime time.Time
}

func newFeedProxy(url string) *feedProxy {
	return &feedProxy{url: url}
}

func (p *feedProxy) fetchRaw(ctx context.Context) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cache != nil && time.Since(p.cacheTime) < feedCacheTTL {
		return p.cache, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	buf := make([]byte, 0, 1<<20)
	tmp := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}

	p.cache = buf
	p.cacheTime = time.Now()
	return buf, nil
}

// fetchWithExpiryNotice injects a synthetic episode at the top of the feed.
// This is served once per token; subsequent requests return 402.
func (p *feedProxy) fetchWithExpiryNotice(ctx context.Context) ([]byte, error) {
	raw, err := p.fetchRaw(ctx)
	if err != nil {
		return nil, err
	}
	return injectExpiryItem(raw), nil
}

// injectExpiryItem inserts a synthetic <item> before the first existing <item>
// in the RSS feed. Uses string manipulation to avoid mangling CDATA sections.
func injectExpiryItem(feedXML []byte) []byte {
	now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000")
	guid := fmt.Sprintf("expired-notice-%d", time.Now().Unix())

	enclosureTag := ""
	if expiredAudioURL != "" {
		enclosureTag = fmt.Sprintf(
			`<enclosure url="%s" type="audio/mpeg" length="0"/>`, expiredAudioURL,
		)
	}

	item := fmt.Sprintf(`<item>
<title>Your subscription has expired</title>
<description>Your members subscription has expired. Visit the members page to renew and continue receiving bonus content.</description>
<pubDate>%s</pubDate>
<guid isPermaLink="false">%s</guid>
%s</item>
`, now, guid, enclosureTag)

	s := string(feedXML)

	// Insert before first <item>; fall back to before </channel>.
	for _, marker := range []string{"<item>", "<item >"} {
		if idx := strings.Index(s, marker); idx != -1 {
			return []byte(s[:idx] + item + s[idx:])
		}
	}
	if idx := strings.Index(s, "</channel>"); idx != -1 {
		return []byte(s[:idx] + item + s[idx:])
	}
	return feedXML
}

// ─── Nostr DM (NIP-04) ───────────────────────────────────────────────────────

type nostrDM struct {
	privkeyHex string
	pubkeyHex  string
}

func newNostrDM(rawKey string) (*nostrDM, error) {
	privkeyHex := rawKey
	if strings.HasPrefix(rawKey, "nsec") {
		prefix, val, err := nip19.Decode(rawKey)
		if err != nil {
			return nil, fmt.Errorf("decode nsec: %w", err)
		}
		if prefix != "nsec" {
			return nil, fmt.Errorf("expected nsec prefix, got %s", prefix)
		}
		switch v := val.(type) {
		case string:
			privkeyHex = v
		case []byte:
			privkeyHex = hex.EncodeToString(v)
		default:
			return nil, fmt.Errorf("unexpected nsec decode type %T", val)
		}
	}
	pubkeyHex, err := nostr.GetPublicKey(privkeyHex)
	if err != nil {
		return nil, fmt.Errorf("derive pubkey: %w", err)
	}
	return &nostrDM{privkeyHex: privkeyHex, pubkeyHex: pubkeyHex}, nil
}

func (n *nostrDM) npub() string {
	enc, _ := nip19.EncodePublicKey(n.pubkeyHex)
	return enc
}

func (n *nostrDM) send(ctx context.Context, recipientRaw, message string) error {
	recipientHex := recipientRaw
	if strings.HasPrefix(recipientRaw, "npub") {
		prefix, val, err := nip19.Decode(recipientRaw)
		if err != nil {
			return fmt.Errorf("decode npub: %w", err)
		}
		if prefix != "npub" {
			return fmt.Errorf("expected npub, got %s", prefix)
		}
		switch v := val.(type) {
		case string:
			recipientHex = v
		case []byte:
			recipientHex = hex.EncodeToString(v)
		}
	}

	// nip04.ComputeSharedSecret signature is (pub, sk) — public key first, private key second.
	// Swapping these produces a "not on the secp256k1 curve" error because the library
	// prepends "02" to its first argument assuming it is an x-only public key.
	sharedSecret, err := nip04.ComputeSharedSecret(recipientHex, n.privkeyHex)
	if err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}
	encrypted, err := nip04.Encrypt(message, sharedSecret)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	ev := nostr.Event{
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{{"p", recipientHex}},
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	if err := ev.Sign(n.privkeyHex); err != nil {
		return fmt.Errorf("sign event: %w", err)
	}

	type result struct {
		relay string
		ok    bool
	}
	results := make(chan result, len(nostrRelays))
	for _, relayURL := range nostrRelays {
		go func(url string) {
			ok := publishToRelay(ctx, url, ev)
			results <- result{relay: url, ok: ok}
		}(relayURL)
	}

	successes := 0
	for range nostrRelays {
		r := <-results
		label := "failure"
		if r.ok {
			successes++
			label = "success"
		}
		metricNostrDMRelayTotal.WithLabelValues(r.relay, label).Inc()
	}

	if successes == 0 {
		metricNostrDMTotal.WithLabelValues("failure").Inc()
		return fmt.Errorf("DM publish failed on all relays")
	}
	metricNostrDMTotal.WithLabelValues("success").Inc()
	slog.Info("Nostr DM published", "successes", successes, "total", len(nostrRelays))
	return nil
}

func publishToRelay(ctx context.Context, relayURL string, ev nostr.Event) bool {
	// Two separate timeouts: one for the TCP+WebSocket handshake, one for the
	// actual publish. A relay can accept the connection and then stall on the
	// publish, so a single timeout on the outer context is not sufficient.
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	relay, err := nostr.RelayConnect(connectCtx, relayURL)
	if err != nil {
		slog.Warn("relay connect failed", "relay", relayURL, "err", err)
		return false
	}
	defer relay.Close()

	pubCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()

	if err := relay.Publish(pubCtx, ev); err != nil {
		slog.Warn("relay rejected event", "relay", relayURL, "err", err)
		return false
	}
	return true
}

// ─── Notification service ────────────────────────────────────────────────────

type subscriberInfo struct {
	feedURL     string
	email       string
	nostrPubkey string
}

type notifier struct {
	dm *nostrDM
}

func (n *notifier) deliver(ctx context.Context, info subscriberInfo) {
	var wg sync.WaitGroup
	if info.email != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sendEmail(info.email, "Your members podcast feed", buildFeedEmail(info)); err != nil {
				slog.Error("email delivery failed", "to", info.email, "err", err)
				metricEmailTotal.WithLabelValues("failure").Inc()
			} else {
				metricEmailTotal.WithLabelValues("success").Inc()
			}
		}()
	}
	if info.nostrPubkey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := buildFeedDM(info)
			if err := n.dm.send(ctx, info.nostrPubkey, msg); err != nil {
				slog.Error("Nostr DM failed", "err", err)
			}
		}()
	}
	wg.Wait()
}

func (n *notifier) deliverExpiryNotice(ctx context.Context, info subscriberInfo) {
	if info.nostrPubkey == "" {
		return
	}
	msg := fmt.Sprintf(
		"Your members podcast subscription has expired.\n\n"+
			"Renew at %s to continue receiving bonus content. "+
			"Once renewed, your existing feed URL will keep working — no changes needed in your app.",
		feedBaseURL,
	)
	if err := n.dm.send(ctx, info.nostrPubkey, msg); err != nil {
		slog.Error("Nostr expiry DM failed", "err", err)
	}
}

func buildFeedEmail(info subscriberInfo) string {
	body := fmt.Sprintf(
		"Thanks for subscribing!\n\n"+
			"Your private podcast feed URL:\n\n"+
			"  %s\n\n"+
			"Add this to Fountain, Castamatic, or any podcast app "+
			"that accepts a custom RSS feed. Keep it private — "+
			"it is unique to your subscription.\n\n"+
			"If you lose this URL, reply to this email and we will resend it.",
		info.feedURL,
	)
	if info.nostrPubkey != "" {
		body += fmt.Sprintf(
			"\n\nYou can also retrieve it self-service at:\n  %s/recover",
			feedBaseURL,
		)
	}
	return body
}

func buildFeedDM(info subscriberInfo) string {
	return fmt.Sprintf(
		"Your members podcast feed URL:\n\n"+
			"%s\n\n"+
			"Add this to Fountain, Castamatic, or any podcast app. "+
			"Keep it private — it is unique to your subscription.\n\n"+
			"Retrieve this URL at any time: %s/recover",
		info.feedURL, feedBaseURL,
	)
}

func sendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)
	msg := []byte("To: " + to + "\r\n" +
		"From: " + smtpFrom + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body)
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)
	return smtp.SendMail(addr, auth, smtpFrom, []string{to}, msg)
}

// ─── Token generation ─────────────────────────────────────────────────────────

func generateToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─── Admin auth helper ────────────────────────────────────────────────────────

// requireAdmin checks the Authorization header for a valid bearer token.
// hmac.Equal is used for constant-time comparison to prevent timing attacks
// that could reveal the token through response latency differences.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, `{"detail":"Valid bearer token required"}`, http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", "Bearer")
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if !hmac.Equal([]byte(provided), []byte(adminToken)) {
		http.Error(w, `{"detail":"Valid bearer token required"}`, http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", "Bearer")
		return false
	}
	return true
}

// ─── Gauge refresh ────────────────────────────────────────────────────────────

func updateGauges(ctx context.Context, database *db.DB) {
	stats, err := database.SubscriberStats(ctx)
	if err != nil {
		slog.Warn("failed to refresh gauges", "err", err)
		return
	}
	metricActiveTokens.Set(float64(stats.ActiveTokens))
	metricTotalSubscribers.Set(float64(stats.TotalSubscribers))
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

func webhookHandler(database *db.DB, n *notifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r, 1<<20)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		sig := r.Header.Get("BTCPay-Sig")
		if !verifyBTCPaySignature(body, sig) {
			metricWebhookErrorsTotal.WithLabelValues("invalid_signature").Inc()
			slog.Warn("rejected webhook: invalid signature")
			http.Error(w, `{"detail":"Invalid signature"}`, http.StatusUnauthorized)
			return
		}

		var event map[string]any
		if err := json.Unmarshal(body, &event); err != nil {
			metricWebhookErrorsTotal.WithLabelValues("exception").Inc()
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		eventType, _ := event["type"].(string)
		subscriberID, _ := event["subscriberId"].(string)

		if subscriberID == "" {
			metricWebhookErrorsTotal.WithLabelValues("missing_subscriber_id").Inc()
			jsonOK(w, map[string]string{"status": "ignored", "reason": "no subscriberId"})
			return
		}

		emailStr, _ := event["email"].(string)
		metadata, _ := event["metadata"].(map[string]any)
		nostrPubkeyStr, _ := metadata["nostrPubkey"].(string)

		emailNull := sql.NullString{String: emailStr, Valid: emailStr != ""}
		nostrNull := sql.NullString{String: nostrPubkeyStr, Valid: nostrPubkeyStr != ""}

		subscription, _ := event["subscription"].(map[string]any)
		expiresAt := expiresAtFromEvent(subscription)

		ctx := r.Context()

		var handlerErr error
		switch eventType {
		case "SubscriptionCreated":
			handlerErr = handleCreated(ctx, database, n, subscriberID, emailNull, nostrNull, expiresAt)
		case "SubscriptionRenewed":
			handlerErr = handleRenewed(ctx, database, n, subscriberID, emailNull, nostrNull, expiresAt)
		case "SubscriptionExpired", "SubscriptionSuspended":
			handlerErr = database.RevokeTokens(ctx, subscriberID)
			label := strings.ToLower(strings.TrimPrefix(eventType, "Subscription"))
			metricWebhooksTotal.WithLabelValues(label).Inc()
			slog.Info("revoked", "subscriber", subscriberID, "event", eventType)
		}

		if handlerErr != nil {
			metricWebhookErrorsTotal.WithLabelValues("exception").Inc()
			slog.Error("webhook handler error", "err", handlerErr)
			http.Error(w, handlerErr.Error(), http.StatusBadRequest)
			return
		}

		updateGauges(ctx, database)
		jsonOK(w, map[string]string{"status": "ok"})
	}
}

func handleCreated(ctx context.Context, database *db.DB, n *notifier, subscriberID string, email, nostrPubkey sql.NullString, expiresAt time.Time) error {
	if err := database.UpsertSubscriber(ctx, subscriberID, email, nostrPubkey); err != nil {
		return err
	}
	token, err := generateToken()
	if err != nil {
		return err
	}
	if err := database.CreateToken(ctx, subscriberID, token, expiresAt); err != nil {
		return err
	}
	feedURL := feedBaseURL + "/rss/" + token + ".xml"
	// Fire notifications in a detached goroutine with context.Background() so
	// they are not cancelled when the HTTP request ends. Failure is logged but
	// must not cause an error response to BTCPay — a 4xx/5xx would make BTCPay
	// retry the webhook and issue a duplicate token.
	go n.deliver(context.Background(), subscriberInfo{
		feedURL:     feedURL,
		email:       email.String,
		nostrPubkey: nostrPubkey.String,
	})
	metricWebhooksTotal.WithLabelValues("created").Inc()
	slog.Info("new subscriber", "id", subscriberID)
	return nil
}

func handleRenewed(ctx context.Context, database *db.DB, n *notifier, subscriberID string, email, nostrPubkey sql.NullString, expiresAt time.Time) error {
	existing, err := database.GetActiveToken(ctx, subscriberID)
	if err != nil {
		return err
	}
	if existing != "" {
		// Extend in-place rather than issuing a new token. Podcast apps cache feed
		// URLs, so replacing the token would silently break any subscriber whose app
		// hasn't re-fetched their URL since the renewal.
		if err := database.ExtendToken(ctx, subscriberID, expiresAt); err != nil {
			return err
		}
		metricWebhooksTotal.WithLabelValues("renewed").Inc()
		slog.Info("renewed", "id", subscriberID)
		return nil
	}
	// Lapsed then re-subscribed — issue new token and re-deliver.
	if err := database.UpsertSubscriber(ctx, subscriberID, email, nostrPubkey); err != nil {
		return err
	}
	token, err := generateToken()
	if err != nil {
		return err
	}
	if err := database.CreateToken(ctx, subscriberID, token, expiresAt); err != nil {
		return err
	}
	feedURL := feedBaseURL + "/rss/" + token + ".xml"
	go n.deliver(context.Background(), subscriberInfo{
		feedURL:     feedURL,
		email:       email.String,
		nostrPubkey: nostrPubkey.String,
	})
	metricWebhooksTotal.WithLabelValues("renewed").Inc()
	slog.Info("re-subscribed", "id", subscriberID)
	return nil
}

func expiresAtFromEvent(subscription map[string]any) time.Time {
	if subscription != nil {
		if ts, ok := subscription["expiresAt"].(float64); ok && ts > 0 {
			return time.Unix(int64(ts), 0).UTC()
		}
	}
	return time.Now().UTC().Add(31 * 24 * time.Hour)
}

func feedHandler(database *db.DB, proxy *feedProxy, n *notifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "token")
		row, err := database.ValidateToken(r.Context(), token)
		if err != nil {
			slog.Error("token validation error", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if row == nil {
			metricFeedRequestsTotal.WithLabelValues("expired").Inc()
			http.Error(w, "Subscription required or expired.", http.StatusPaymentRequired)
			return
		}

		now := time.Now().UTC()
		// Give the subscriber a grace period after their expiry date before
		// cutting them off. This covers billing-cycle timing gaps and avoids
		// surprising a subscriber who renewed moments after midnight.
		graceDeadline := row.ExpiresAt.Add(gracePeriodDays * 24 * time.Hour)
		isExpired := graceDeadline.Before(now)

		if isExpired {
			if row.ExpiryNotifiedAt.Valid {
				metricFeedRequestsTotal.WithLabelValues("expired").Inc()
				http.Error(w, "Subscription expired.", http.StatusPaymentRequired)
				return
			}

			content, err := proxy.fetchWithExpiryNotice(r.Context())
			if err != nil {
				metricFeedUpstreamErrorsTotal.Inc()
				slog.Error("feed fetch failed", "err", err)
				http.Error(w, "Could not fetch feed", http.StatusBadGateway)
				return
			}

			if err := database.MarkExpiryNotified(r.Context(), token); err != nil {
				slog.Error("mark expiry notified failed", "err", err)
			}
			metricExpiryNotificationsTotal.Inc()

			if row.NostrPubkey.Valid && row.NostrPubkey.String != "" {
				go n.deliverExpiryNotice(context.Background(), subscriberInfo{
					feedURL:     feedBaseURL + "/rss/" + token + ".xml",
					nostrPubkey: row.NostrPubkey.String,
				})
			}

			slog.Info("expiry notice served", "token_suffix", token[max(0, len(token)-8):])
			metricFeedRequestsTotal.WithLabelValues("expired").Inc()
			w.Header().Set("Content-Type", "application/rss+xml")
			w.Write(content)
			return
		}

		content, err := proxy.fetchRaw(r.Context())
		if err != nil {
			metricFeedUpstreamErrorsTotal.Inc()
			slog.Error("feed fetch failed", "err", err)
			http.Error(w, "Could not fetch feed", http.StatusBadGateway)
			return
		}

		metricFeedRequestsTotal.WithLabelValues("valid").Inc()
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write(content)
	}
}

func feedURLHandler(database *db.DB, nd *nostrDM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Nostr ") {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"NIP-98 auth required"}`, http.StatusUnauthorized)
			return
		}

		b64 := strings.TrimPrefix(auth, "Nostr ")
		eventJSON, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"Invalid NIP-98 token"}`, http.StatusUnauthorized)
			return
		}

		var ev nostr.Event
		if err := json.Unmarshal(eventJSON, &ev); err != nil {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"Invalid NIP-98 token"}`, http.StatusUnauthorized)
			return
		}

		if ev.Kind != 27235 {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"Invalid event kind"}`, http.StatusUnauthorized)
			return
		}

		if abs64(time.Now().Unix()-int64(ev.CreatedAt)) > 60 {
			metricNIP98RequestsTotal.WithLabelValues("expired").Inc()
			http.Error(w, `{"detail":"Event timestamp expired"}`, http.StatusUnauthorized)
			return
		}

		tags := ev.Tags.GetFirst([]string{"method"})
		uTag := ev.Tags.GetFirst([]string{"u"})
		if tags == nil || (*tags)[1] != "GET" {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"Method mismatch"}`, http.StatusUnauthorized)
			return
		}
		expectedURL := feedBaseURL + "/api/feed-url"
		if uTag == nil || (*uTag)[1] != expectedURL {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"URL mismatch"}`, http.StatusUnauthorized)
			return
		}
		if ev.PubKey == "" {
			metricNIP98RequestsTotal.WithLabelValues("malformed").Inc()
			http.Error(w, `{"detail":"Missing pubkey"}`, http.StatusUnauthorized)
			return
		}

		ok, err := ev.CheckSignature()
		if err != nil || !ok {
			metricNIP98RequestsTotal.WithLabelValues("invalid_sig").Inc()
			http.Error(w, `{"detail":"Invalid signature"}`, http.StatusUnauthorized)
			return
		}

		token, err := database.GetTokenForPubkey(r.Context(), ev.PubKey)
		if err != nil {
			slog.Error("db error in feed-url", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if token == "" {
			metricNIP98RequestsTotal.WithLabelValues("not_found").Inc()
			http.Error(w, `{"detail":"No active subscription found for this pubkey"}`, http.StatusNotFound)
			return
		}

		metricNIP98RequestsTotal.WithLabelValues("success").Inc()
		jsonOK(w, map[string]string{"feed_url": feedBaseURL + "/rss/" + token + ".xml"})
	}
}

func recoverPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metricRecoveryPageVisitsTotal.Inc()
		apiURL := feedBaseURL + "/api/feed-url"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, recoverHTML, apiURL, apiURL)
	}
}

func metricsHandler() http.HandlerFunc {
	h := promhttp.Handler()
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	}
}

func cleanupHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		n, err := database.CleanupExpired(r.Context())
		if err != nil {
			slog.Error("cleanup failed", "err", err)
			http.Error(w, "cleanup failed", http.StatusInternalServerError)
			return
		}
		updateGauges(r.Context(), database)
		slog.Info("cleanup complete", "removed", n)
		jsonOK(w, map[string]string{"status": "ok"})
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func readBody(r *http.Request, maxBytes int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Recovery page HTML ───────────────────────────────────────────────────────

// recoverHTML is the self-service feed URL recovery page.
// Two %s format verbs: first for API URL in JS const, second in the fetch call.
const recoverHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Retrieve your podcast feed URL</title>
  <style>
    body {
      font-family: system-ui, sans-serif; max-width: 480px;
      margin: 4rem auto; padding: 0 1.5rem;
      line-height: 1.6; color: #222;
    }
    h1   { font-size: 1.4rem; margin-bottom: 0.5rem; }
    button {
      display: block; width: 100%%; padding: 0.75rem;
      font-size: 1rem; background: #f7931a; color: white;
      border: none; border-radius: 6px; cursor: pointer;
      margin-top: 1.5rem;
    }
    button:disabled { background: #ccc; cursor: not-allowed; }
    #result {
      margin-top: 1.5rem; padding: 1rem; background: #f5f5f5;
      border-radius: 6px; word-break: break-all; display: none;
    }
    #error  { margin-top: 1rem; color: #c00; display: none; }
    .note   {
      margin-top: 2rem; font-size: 0.9rem; color: #555;
      border-top: 1px solid #ddd; padding-top: 1rem;
    }
  </style>
</head>
<body>
  <h1>Retrieve your podcast feed URL</h1>
  <p>
    Sign in with your Nostr key to retrieve your private members feed URL.
    This requires a NIP-07 browser extension such as
    <a href="https://getalby.com" target="_blank">Alby</a> or
    <a href="https://github.com/fiatjaf/nos2x" target="_blank">nos2x</a>.
  </p>
  <p>
    <strong>On mobile:</strong> most phone browsers do not support
    extensions. If you are on a phone or do not have a NIP-07 extension,
    use the email fallback below.
  </p>
  <button id="btn" onclick="retrieve()">
    Sign with Nostr to retrieve feed URL
  </button>
  <div id="error"></div>
  <div id="result">
    <strong>Your feed URL:</strong><br>
    <span id="url"></span><br><br>
    <button onclick="copy()" style="margin-top:0.5rem">
      Copy to clipboard
    </button>
  </div>
  <div class="note">
    <strong>No extension?</strong> Reply to your subscription confirmation
    email and we will resend your feed URL.
  </div>
  <script>
    const API = "%s";
    async function retrieve() {
      const btn = document.getElementById("btn");
      showError("");
      if (!window.nostr) {
        showError(
          "No NIP-07 extension detected. Install Alby or nos2x on " +
          "a desktop browser, or reply to your confirmation email."
        );
        return;
      }
      btn.disabled    = true;
      btn.textContent = "Signing…";
      try {
        const pubkey = await window.nostr.getPublicKey();
        const event  = {
          kind: 27235,
          created_at: Math.floor(Date.now() / 1000),
          tags: [["u", "%s"], ["method", "GET"]],
          content: "",
        };
        const signed  = await window.nostr.signEvent(event);
        const encoded = btoa(JSON.stringify(signed));
        const resp    = await fetch(API, {
          headers: {"Authorization": "Nostr " + encoded},
        });
        if (!resp.ok) {
          const body = await resp.json().catch(() => ({}));
          showError(body.detail ||
            (resp.status === 404
              ? "No active subscription found for this Nostr key."
              : "Request failed. Try again or use the email fallback."));
          return;
        }
        const data = await resp.json();
        document.getElementById("url").textContent = data.feed_url;
        document.getElementById("result").style.display = "block";
      } catch(e) {
        showError("Error: " + e.message);
      } finally {
        btn.disabled    = false;
        btn.textContent = "Sign with Nostr to retrieve feed URL";
      }
    }
    function copy() {
      navigator.clipboard
        .writeText(document.getElementById("url").textContent)
        .then(() => alert("Copied!"));
    }
    function showError(msg) {
      const el = document.getElementById("error");
      el.textContent   = msg;
      el.style.display = msg ? "block" : "none";
    }
  </script>
</body>
</html>`

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	var host string
	var port int
	flag.StringVar(&host, "host", "127.0.0.1", "listen address")
	flag.IntVar(&port, "port", 8765, "listen port")
	flag.Parse()

	loadConfig()

	database, err := db.Open(databasePath)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	nd, err := newNostrDM(nostrPrivateKey)
	if err != nil {
		slog.Error("failed to initialise Nostr keypair", "err", err)
		os.Exit(1)
	}

	proxy := newFeedProxy(podserverFeedURL)
	n := &notifier{dm: nd}

	updateGauges(context.Background(), database)
	slog.Info("token service started", "nostr_pubkey", nd.npub())

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/webhook/btcpay", webhookHandler(database, n))
	r.Get("/rss/{token}.xml", feedHandler(database, proxy, n))
	r.Get("/api/feed-url", feedURLHandler(database, nd))
	r.Get("/recover", recoverPageHandler())
	r.Get("/metrics", metricsHandler())
	r.Post("/admin/cleanup", cleanupHandler(database))
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]string{"status": "ok"})
	})

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
