/*
podcast-members-manage — management and testing CLI for the podcast token service.

Commands:
  subscribers       List subscribers, optionally filtered by status
  feed-url          Look up a subscriber's feed URL
  revoke            Revoke all tokens for a subscriber
  stats             Print subscriber and token summary
  cleanup           Call /admin/cleanup to remove old expired tokens
  test-webhook      Run a full end-to-end validation of the token service

Usage:
  podcast-members-manage [--db PATH] <command> [options]

Environment:
  DATABASE_PATH   path to the SQLite database (overridden by --db)
  FEED_BASE_URL   used to construct feed URLs in output
  ADMIN_TOKEN     bearer token for API calls
  SERVICE_URL     base URL of the token service (default: http://127.0.0.1:8765)
*/
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/genebean/podcast-members-feed/internal/db"
)

// ─── Configuration ────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func fmtDT(s sql.NullString) string {
	if !s.Valid || s.String == "" {
		return "never"
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s.String); err == nil {
			return t.UTC().Format("2006-01-02 15:04 UTC")
		}
	}
	return s.String
}

func fmtDTStr(s string) string {
	return fmtDT(sql.NullString{String: s, Valid: s != ""})
}

func fmtFeedURL(token sql.NullString) string {
	feedBase := strings.TrimRight(os.Getenv("FEED_BASE_URL"), "/")
	if !token.Valid || token.String == "" {
		return "(no active token)"
	}
	if feedBase != "" {
		return feedBase + "/rss/" + token.String + ".xml"
	}
	return "<token: " + token.String + ">"
}

func fmtFeedURLStr(token string) string {
	return fmtFeedURL(sql.NullString{String: token, Valid: true})
}

func nullStr(s sql.NullString, def string) string {
	if s.Valid && s.String != "" {
		return s.String
	}
	return def
}

func printField(width int, label, value string) {
	fmt.Printf("  %-*s %s\n", width, label, value)
}

func divider() {
	fmt.Println(strings.Repeat("─", 60))
}

func ctx() context.Context {
	return context.Background()
}

// ─── Commands ─────────────────────────────────────────────────────────────────

func cmdSubscribers(database *db.DB, active, neverAccessed bool, expiringDays int) {
	rows, err := database.ListSubscribers(ctx(), active, neverAccessed, expiringDays)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("No subscribers found.")
		return
	}

	divider()
	for _, row := range rows {
		printField(16, "ID:", row.BTCPaySubscriberID)
		printField(16, "Email:", nullStr(row.Email, "(none)"))
		printField(16, "Nostr:", nullStr(row.NostrPubkey, "(none)"))
		printField(16, "Subscribed:", fmtDTStr(row.CreatedAt))
		printField(16, "Expires:", fmtDT(row.ExpiresAt))
		printField(16, "Last access:", fmtDT(row.LastUsedAt))
		printField(16, "Feed URL:", fmtFeedURL(row.Token))
		divider()
	}
	fmt.Printf("\nTotal: %d\n", len(rows))
}

func cmdFeedURL(database *db.DB, email, npub string) {
	var token string
	var err error
	if email != "" {
		token, err = database.GetTokenByEmail(ctx(), email)
	} else {
		token, err = database.GetTokenByNpub(ctx(), npub)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	if token == "" {
		fmt.Println("No active subscription found.")
		return
	}
	fmt.Println(fmtFeedURLStr(token))
}

func cmdRevoke(database *db.DB, subscriberID string, skipConfirm bool) {
	email, found, err := database.GetSubscriberEmail(ctx(), subscriberID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	if !found {
		fmt.Printf("Subscriber %s not found.\n", subscriberID)
		return
	}

	if !skipConfirm {
		name := subscriberID
		if email != "" {
			name = email
		}
		fmt.Printf("Revoke all tokens for %s? [y/N] ", name)
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	if err := database.RevokeTokens(ctx(), subscriberID); err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	fmt.Printf("Tokens revoked for %s.\n", subscriberID)
}

func cmdStats(database *db.DB) {
	stats, err := database.CLIStats(ctx())
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	fmt.Printf("  Total subscribers:      %d\n", stats.TotalSubscribers)
	fmt.Printf("  Active tokens:          %d\n", stats.ActiveTokens)
	fmt.Printf("  Never accessed feed:    %d\n", stats.NeverAccessed)
	fmt.Printf("  Expired (unnotified):   %d\n", stats.ExpiredUnnotified)
}

func cmdCleanup() {
	adminToken := os.Getenv("ADMIN_TOKEN")
	svcURL := strings.TrimRight(envOr("SERVICE_URL", "http://127.0.0.1:8765"), "/")
	if adminToken == "" {
		fmt.Fprintln(os.Stderr, "Error: ADMIN_TOKEN not set.")
		os.Exit(1)
	}
	url := svcURL + "/admin/cleanup"
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: %d %s\n", resp.StatusCode, resp.Status)
		os.Exit(1)
	}
	fmt.Printf("Cleanup complete: %s\n", body)
}

func cmdTestWebhook(database *db.DB, svcURL, webhookSecret, npub, email, feedURL string, runExpiryTest bool) {
	passed, failed := 0, 0

	ok := func(msg string) {
		passed++
		fmt.Printf("  ✓ %s\n", msg)
	}
	fail := func(msg string) {
		failed++
		fmt.Printf("  ✗ %s\n", msg)
	}
	section := func(title string) {
		fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len(title)))
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Stage 1: Health
	section("Stage 1: Health check")
	resp, err := client.Get(svcURL + "/health")
	if err != nil {
		fail("Could not reach service: " + err.Error())
		fmt.Println("\nAborted — service unreachable.")
		os.Exit(1)
	}
	var health map[string]string
	json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && health["status"] == "ok" {
		ok("Health endpoint returned ok")
	} else {
		fail(fmt.Sprintf("Health returned %d", resp.StatusCode))
		os.Exit(1)
	}

	// Stage 2: Metrics
	section("Stage 2: Metrics endpoint")
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		fail("ADMIN_TOKEN not set — skipping")
	} else {
		req, _ := http.NewRequest(http.MethodGet, svcURL+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err != nil {
			fail("Metrics check failed: " + err.Error())
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "podcast_active_tokens") {
				ok("Metrics returned Prometheus data")
			} else {
				fail(fmt.Sprintf("Metrics returned %d", resp.StatusCode))
			}
		}

		resp2, err := client.Get(svcURL + "/metrics")
		if err == nil {
			resp2.Body.Close()
			if resp2.StatusCode == http.StatusUnauthorized {
				ok("Unauthenticated request correctly rejected (401)")
			} else {
				fail(fmt.Sprintf("Unauthenticated request returned %d, expected 401", resp2.StatusCode))
			}
		}
	}

	// Stage 3: Webhook
	section("Stage 3: Webhook")
	subscriberID := fmt.Sprintf("test-%d", time.Now().Unix())

	metadata := map[string]any{}
	if npub != "" {
		metadata["nostrPubkey"] = npub
	}
	var testEmail any
	if email != "" {
		testEmail = email
	}

	payload, _ := json.Marshal(map[string]any{
		"type":         "SubscriptionCreated",
		"subscriberId": subscriberID,
		"email":        testEmail,
		"subscription": map[string]any{"expiresAt": 9999999999},
		"metadata":     metadata,
	})

	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest(http.MethodPost, svcURL+"/webhook/btcpay", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BTCPay-Sig", sig)
	resp, err = client.Do(req)
	if err != nil {
		fail("Webhook failed: " + err.Error())
		os.Exit(1)
	}
	var wh map[string]string
	json.NewDecoder(resp.Body).Decode(&wh)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && wh["status"] == "ok" {
		ok(fmt.Sprintf("Webhook accepted for subscriber %s", subscriberID))
	} else {
		fail(fmt.Sprintf("Webhook returned %d", resp.StatusCode))
		os.Exit(1)
	}

	// Stage 4: Token and feed
	section("Stage 4: Token and feed")
	time.Sleep(500 * time.Millisecond)

	field := "email"
	value := email
	if email == "" {
		field = "nostr_pubkey"
		value = npub
	}
	token, err := database.GetTokenByLookupField(ctx(), field, value)
	if err != nil || token == "" {
		fail("Token not found in database after webhook")
		os.Exit(1)
	}

	ok(fmt.Sprintf("Token created: ...%s", token[max(0, len(token)-12):]))
	testFeedURL := svcURL + "/rss/" + token + ".xml"
	fmt.Printf("  Feed URL: %s\n", testFeedURL)

	resp, err = client.Get(testFeedURL)
	if err != nil {
		fail("Feed request failed: " + err.Error())
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)
		switch {
		case resp.StatusCode == http.StatusOK && (strings.Contains(bodyStr, "<channel>") || strings.Contains(strings.ToLower(bodyStr), "rss")):
			ok("Feed URL returns valid RSS content")
		case resp.StatusCode == http.StatusBadGateway:
			fail("Feed returned 502 — upstream unreachable. Check PODSERVER_FEED_URL.")
		default:
			fail(fmt.Sprintf("Feed returned %d", resp.StatusCode))
		}
	}

	if feedURL != "" {
		resp, err := client.Get(feedURL)
		if err != nil {
			fail("Could not fetch upstream feed: " + err.Error())
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "<item>") {
				ok("Upstream feed is valid RSS")
			} else {
				fail(fmt.Sprintf("Upstream feed at %s did not look like RSS", feedURL))
			}
		}
	}

	// Stage 5: Expiry flow
	if runExpiryTest {
		section("Stage 5: Expiry flow")

		if err := database.SetTokenExpiry(ctx(), token, "2020-01-01T00:00:00+00:00"); err != nil {
			fail("Could not expire token: " + err.Error())
		} else {
			ok("Token expired in database")
		}

		resp, err := client.Get(testFeedURL)
		if err != nil {
			fail("First expiry fetch failed: " + err.Error())
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusOK && strings.Contains(string(body), "Your subscription has expired"):
				ok("First fetch: 200 with expiry episode injected")
			case resp.StatusCode == http.StatusOK:
				fail("First fetch: 200 but expiry episode not found in feed")
			default:
				fail(fmt.Sprintf("First fetch: %d, expected 200", resp.StatusCode))
			}
		}

		resp, err = client.Get(testFeedURL)
		if err != nil {
			fail("Second expiry fetch failed: " + err.Error())
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusPaymentRequired {
				ok("Second fetch: 402 Payment Required")
			} else {
				fail(fmt.Sprintf("Second fetch: %d, expected 402", resp.StatusCode))
			}
		}

		newExpiry := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
		_ = database.SetTokenExpiry(ctx(), token, newExpiry)
		_ = database.ClearExpiryNotified(ctx(), token)
		ok("Token restored to active state")
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("─", 40))
	fmt.Printf("  Passed: %d  Failed: %d\n", passed, failed)
	if failed > 0 {
		fmt.Println("  Some checks failed — review output above")
		os.Exit(1)
	}
	fmt.Println("  All checks passed")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	_ = godotenv.Load()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	defaultDB := envOr("DATABASE_PATH", "/var/lib/podcast-token-service/tokens.db")

	// Global --db flag parsed before sub-command.
	globalFlags := flag.NewFlagSet("global", flag.ContinueOnError)
	globalFlags.SetOutput(io.Discard)
	dbPath := globalFlags.String("db", defaultDB, "path to SQLite database")
	_ = globalFlags.Parse(os.Args[1:])

	args := globalFlags.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	command := args[0]

	openDB := func() *db.DB {
		if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"Error: database not found at %s\nStart the token service first, then re-run.\n",
				*dbPath,
			)
			os.Exit(1)
		}
		database, err := db.Open(*dbPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening database:", err)
			os.Exit(1)
		}
		return database
	}

	switch command {
	case "subscribers":
		fs := flag.NewFlagSet("subscribers", flag.ExitOnError)
		active := fs.Bool("active", false, "only active subscribers")
		neverAccessed := fs.Bool("never-accessed", false, "never accessed their feed")
		expiringDays := fs.Int("expiring-days", 0, "expiring within N days")
		fs.Parse(args[1:])
		database := openDB()
		defer database.Close()
		cmdSubscribers(database, *active, *neverAccessed, *expiringDays)

	case "feed-url":
		fs := flag.NewFlagSet("feed-url", flag.ExitOnError)
		email := fs.String("email", "", "subscriber email")
		npub := fs.String("npub", "", "subscriber Nostr npub or hex pubkey")
		fs.Parse(args[1:])
		if *email == "" && *npub == "" {
			fmt.Fprintln(os.Stderr, "Error: --email or --npub required")
			os.Exit(1)
		}
		database := openDB()
		defer database.Close()
		cmdFeedURL(database, *email, *npub)

	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		yes := fs.Bool("yes", false, "skip confirmation")
		fs.Parse(args[1:])
		if fs.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Error: subscriber_id required")
			os.Exit(1)
		}
		database := openDB()
		defer database.Close()
		cmdRevoke(database, fs.Arg(0), *yes)

	case "stats":
		database := openDB()
		defer database.Close()
		cmdStats(database)

	case "cleanup":
		cmdCleanup()

	case "test-webhook":
		defaultSvcURL := envOr("SERVICE_URL", "http://127.0.0.1:8765")
		fs := flag.NewFlagSet("test-webhook", flag.ExitOnError)
		svcURL := fs.String("service-url", defaultSvcURL, "token service URL")
		webhookSecret := fs.String("webhook-secret", "", "BTCPAY_WEBHOOK_SECRET")
		npub := fs.String("npub", "", "Nostr npub or hex pubkey for test subscriber")
		email := fs.String("email", "", "email for test subscriber")
		feedURL := fs.String("feed-url", "", "URL of a real podcast RSS feed (optional validation)")
		runExpiry := fs.Bool("run-expiry-test", false, "also test expiry episode injection and 402 flow")
		fs.Parse(args[1:])

		if *webhookSecret == "" {
			fmt.Fprintln(os.Stderr, "Error: --webhook-secret required")
			os.Exit(1)
		}
		if *npub == "" && *email == "" {
			fmt.Fprintln(os.Stderr, "Error: --npub or --email required")
			os.Exit(1)
		}
		database := openDB()
		defer database.Close()
		cmdTestWebhook(database, strings.TrimRight(*svcURL, "/"), *webhookSecret, *npub, *email, *feedURL, *runExpiry)

	case "help", "--help", "-h":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`Usage: podcast-members-manage [--db PATH] <command> [options]

Commands:
  subscribers       List subscribers
    --active              only active subscribers
    --never-accessed      never accessed their feed
    --expiring-days N     expiring within N days
  feed-url          Look up a subscriber's feed URL
    --email ADDR          subscriber email
    --npub KEY            subscriber Nostr npub or hex pubkey
  revoke <id>       Revoke all tokens for a subscriber
    --yes                 skip confirmation prompt
  stats             Print subscriber and token summary
  cleanup           Call /admin/cleanup to remove old expired tokens
  test-webhook      End-to-end validation of the running token service
    --webhook-secret S    BTCPAY_WEBHOOK_SECRET (required)
    --npub KEY            Nostr npub for test subscriber
    --email ADDR          email for test subscriber
    --feed-url URL        validate upstream feed content
    --run-expiry-test     also test expiry injection and 402 flow

Global options:
  --db PATH         path to SQLite database
                    (default: $DATABASE_PATH or /var/lib/podcast-token-service/tokens.db)

Environment:
  DATABASE_PATH     override default database path
  FEED_BASE_URL     construct feed URLs in output
  ADMIN_TOKEN       bearer token for API calls
  SERVICE_URL       token service URL (default: http://127.0.0.1:8765)
`)
}
