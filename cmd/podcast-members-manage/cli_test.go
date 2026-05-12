package main

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/genebean/podcast-members-feed/internal/db"
)

// openTestDB creates a temp-file SQLite database and registers cleanup.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// seedSubscriber inserts one subscriber and one token into d.
func seedSubscriber(t *testing.T, d *db.DB, id, email, npub, token string, expiresAt time.Time) {
	t.Helper()
	emailNS := sql.NullString{String: email, Valid: email != ""}
	npubNS := sql.NullString{String: npub, Valid: npub != ""}
	if err := d.UpsertSubscriber(context.Background(), id, emailNS, npubNS); err != nil {
		t.Fatalf("upsert subscriber: %v", err)
	}
	if err := d.CreateToken(context.Background(), id, token, expiresAt); err != nil {
		t.Fatalf("create token: %v", err)
	}
}

// ─── Helper function tests ────────────────────────────────────────────────────

func TestFmtDT(t *testing.T) {
	cases := []struct {
		input sql.NullString
		want  string
	}{
		{sql.NullString{}, "never"},
		{sql.NullString{String: "", Valid: true}, "never"},
		{sql.NullString{String: "2025-06-01T12:00:00Z", Valid: true}, "2025-06-01 12:00 UTC"},
		{sql.NullString{String: "2025-06-01T12:00:00.000000000Z", Valid: true}, "2025-06-01 12:00 UTC"},
		{sql.NullString{String: "not-a-date", Valid: true}, "not-a-date"},
	}
	for _, c := range cases {
		got := fmtDT(c.input)
		if got != c.want {
			t.Errorf("fmtDT(%q) = %q, want %q", c.input.String, got, c.want)
		}
	}
}

func TestNullStr(t *testing.T) {
	cases := []struct {
		s    sql.NullString
		def  string
		want string
	}{
		{sql.NullString{String: "hello", Valid: true}, "default", "hello"},
		{sql.NullString{}, "default", "default"},
		{sql.NullString{String: "", Valid: true}, "default", "default"},
	}
	for _, c := range cases {
		got := nullStr(c.s, c.def)
		if got != c.want {
			t.Errorf("nullStr(%q, %q) = %q, want %q", c.s.String, c.def, got, c.want)
		}
	}
}

func TestFmtFeedURL(t *testing.T) {
	tok := sql.NullString{String: "abc123", Valid: true}

	t.Run("with_base_url", func(t *testing.T) {
		t.Setenv("FEED_BASE_URL", "https://example.com")
		got := fmtFeedURL(tok)
		if got != "https://example.com/rss/abc123.xml" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("trailing_slash_stripped", func(t *testing.T) {
		t.Setenv("FEED_BASE_URL", "https://example.com/")
		got := fmtFeedURL(tok)
		if got != "https://example.com/rss/abc123.xml" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("without_base_url", func(t *testing.T) {
		t.Setenv("FEED_BASE_URL", "")
		got := fmtFeedURL(tok)
		if !strings.Contains(got, "abc123") {
			t.Errorf("token not in output: %q", got)
		}
	})

	t.Run("empty_token", func(t *testing.T) {
		got := fmtFeedURL(sql.NullString{})
		if got != "(no active token)" {
			t.Errorf("got %q", got)
		}
	})
}

// ─── cmdStats ─────────────────────────────────────────────────────────────────

func TestCmdStats(t *testing.T) {
	d := openTestDB(t)
	future := time.Now().UTC().Add(24 * time.Hour)
	past := time.Now().UTC().Add(-24 * time.Hour)

	seedSubscriber(t, d, "sub-1", "a@example.com", "", "tok-active", future)
	seedSubscriber(t, d, "sub-2", "b@example.com", "", "tok-expired", past)

	out := captureStdout(t, func() { cmdStats(d) })

	for _, want := range []string{"Total subscribers:", "Active tokens:", "Never accessed", "Expired"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in stats output:\n%s", want, out)
		}
	}
	// Two subscribers total, one active token.
	if !strings.Contains(out, "2") {
		t.Errorf("expected count 2 in output:\n%s", out)
	}
}

func TestCmdStats_Empty(t *testing.T) {
	d := openTestDB(t)
	out := captureStdout(t, func() { cmdStats(d) })
	if !strings.Contains(out, "0") {
		t.Errorf("expected zeros in empty stats:\n%s", out)
	}
}

// ─── cmdSubscribers ───────────────────────────────────────────────────────────

func TestCmdSubscribers_All(t *testing.T) {
	d := openTestDB(t)
	future := time.Now().UTC().Add(24 * time.Hour)
	seedSubscriber(t, d, "sub-1", "alice@example.com", "", "tok1", future)
	seedSubscriber(t, d, "sub-2", "bob@example.com", "", "tok2", future)

	out := captureStdout(t, func() { cmdSubscribers(d, false, false, 0) })

	if !strings.Contains(out, "alice@example.com") {
		t.Errorf("missing alice:\n%s", out)
	}
	if !strings.Contains(out, "bob@example.com") {
		t.Errorf("missing bob:\n%s", out)
	}
	if !strings.Contains(out, "Total: 2") {
		t.Errorf("expected 'Total: 2':\n%s", out)
	}
}

func TestCmdSubscribers_Empty(t *testing.T) {
	d := openTestDB(t)
	out := captureStdout(t, func() { cmdSubscribers(d, false, false, 0) })
	if !strings.Contains(out, "No subscribers found") {
		t.Errorf("expected empty message:\n%s", out)
	}
}

func TestCmdSubscribers_ActiveFilter(t *testing.T) {
	d := openTestDB(t)
	future := time.Now().UTC().Add(24 * time.Hour)
	past := time.Now().UTC().Add(-24 * time.Hour)
	seedSubscriber(t, d, "sub-active", "active@example.com", "", "tok1", future)
	seedSubscriber(t, d, "sub-expired", "expired@example.com", "", "tok2", past)

	out := captureStdout(t, func() { cmdSubscribers(d, true, false, 0) })

	if !strings.Contains(out, "active@example.com") {
		t.Errorf("active subscriber missing:\n%s", out)
	}
	if strings.Contains(out, "expired@example.com") {
		t.Errorf("expired subscriber should be filtered out:\n%s", out)
	}
}

func TestCmdSubscribers_NeverAccessed(t *testing.T) {
	d := openTestDB(t)
	future := time.Now().UTC().Add(24 * time.Hour)
	seedSubscriber(t, d, "sub-1", "never@example.com", "", "tok-never", future)

	out := captureStdout(t, func() { cmdSubscribers(d, false, true, 0) })

	if !strings.Contains(out, "never@example.com") {
		t.Errorf("never-accessed subscriber missing:\n%s", out)
	}
}

func TestCmdSubscribers_ExpiringDays(t *testing.T) {
	d := openTestDB(t)
	soon := time.Now().UTC().Add(2 * 24 * time.Hour)
	far := time.Now().UTC().Add(30 * 24 * time.Hour)
	seedSubscriber(t, d, "sub-soon", "soon@example.com", "", "tok1", soon)
	seedSubscriber(t, d, "sub-far", "far@example.com", "", "tok2", far)

	out := captureStdout(t, func() { cmdSubscribers(d, false, false, 7) })

	if !strings.Contains(out, "soon@example.com") {
		t.Errorf("expiring-soon subscriber missing:\n%s", out)
	}
	if strings.Contains(out, "far@example.com") {
		t.Errorf("non-expiring subscriber should be filtered out:\n%s", out)
	}
}

// ─── cmdFeedURL ───────────────────────────────────────────────────────────────

func TestCmdFeedURL_ByEmail(t *testing.T) {
	t.Setenv("FEED_BASE_URL", "https://example.com")
	d := openTestDB(t)
	seedSubscriber(t, d, "sub-1", "user@example.com", "", "mytoken123", time.Now().UTC().Add(24*time.Hour))

	out := captureStdout(t, func() { cmdFeedURL(d, "user@example.com", "") })

	if !strings.Contains(out, "https://example.com/rss/mytoken123.xml") {
		t.Errorf("feed URL not in output:\n%s", out)
	}
}

func TestCmdFeedURL_ByNpub(t *testing.T) {
	t.Setenv("FEED_BASE_URL", "https://example.com")
	d := openTestDB(t)
	seedSubscriber(t, d, "sub-1", "", "abc123pubkey", "mytoken456", time.Now().UTC().Add(24*time.Hour))

	out := captureStdout(t, func() { cmdFeedURL(d, "", "abc123pubkey") })

	if !strings.Contains(out, "mytoken456") {
		t.Errorf("token not in output:\n%s", out)
	}
}

func TestCmdFeedURL_NotFound(t *testing.T) {
	d := openTestDB(t)
	out := captureStdout(t, func() { cmdFeedURL(d, "nobody@example.com", "") })
	if !strings.Contains(out, "No active subscription found") {
		t.Errorf("expected not-found message:\n%s", out)
	}
}

// ─── cmdRevoke ────────────────────────────────────────────────────────────────

func TestCmdRevoke(t *testing.T) {
	d := openTestDB(t)
	seedSubscriber(t, d, "sub-1", "user@example.com", "", "tok1", time.Now().UTC().Add(24*time.Hour))

	tok, err := d.GetTokenByEmail(context.Background(), "user@example.com")
	if err != nil || tok == "" {
		t.Fatalf("expected active token before revoke, got %q %v", tok, err)
	}

	out := captureStdout(t, func() { cmdRevoke(d, "sub-1", true) })
	if !strings.Contains(out, "revoked") {
		t.Errorf("expected revoked message:\n%s", out)
	}

	tok, err = d.GetTokenByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("post-revoke lookup: %v", err)
	}
	if tok != "" {
		t.Errorf("expected no active token after revoke, got %q", tok)
	}
}

func TestCmdRevoke_NotFound(t *testing.T) {
	d := openTestDB(t)
	out := captureStdout(t, func() { cmdRevoke(d, "nonexistent", true) })
	if !strings.Contains(out, "not found") {
		t.Errorf("expected not-found message:\n%s", out)
	}
}
