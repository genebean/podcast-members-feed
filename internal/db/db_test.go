package db_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/genebean/podcast-members-feed/internal/db"
)

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

func TestUpsertSubscriberAndStats(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// Upsert with email only
	err := d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	stats, err := d.SubscriberStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalSubscribers != 1 {
		t.Errorf("want 1 subscriber, got %d", stats.TotalSubscribers)
	}

	// Update with Nostr pubkey (COALESCE keeps email)
	err = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{},
		sql.NullString{String: "deadbeef", Valid: true},
	)
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	stats, _ = d.SubscriberStats(ctx)
	if stats.TotalSubscribers != 1 {
		t.Errorf("upsert should not create duplicate; want 1, got %d", stats.TotalSubscribers)
	}
}

func TestUpsertSubscriberRequiresContact(t *testing.T) {
	d := openTestDB(t)
	err := d.UpsertSubscriber(context.Background(), "sub-x",
		sql.NullString{}, sql.NullString{},
	)
	if err == nil {
		t.Fatal("expected error for subscriber with no email or pubkey")
	}
}

func TestCreateAndValidateToken(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)

	expiry := time.Now().UTC().Add(24 * time.Hour)
	if err := d.CreateToken(ctx, "sub-1", "tok-abc", expiry); err != nil {
		t.Fatalf("create token: %v", err)
	}

	row, err := d.ValidateToken(ctx, "tok-abc")
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if row == nil {
		t.Fatal("expected token row, got nil")
	}
	if row.Token != "tok-abc" {
		t.Errorf("want tok-abc, got %s", row.Token)
	}
	if row.Email.String != "a@example.com" {
		t.Errorf("want a@example.com, got %s", row.Email.String)
	}
}

func TestValidateTokenUnknown(t *testing.T) {
	d := openTestDB(t)
	row, err := d.ValidateToken(context.Background(), "no-such-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row != nil {
		t.Errorf("expected nil for unknown token, got %+v", row)
	}
}

func TestValidateTokenRevoked(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-revoked", expiry)
	_ = d.RevokeTokens(ctx, "sub-1")

	row, err := d.ValidateToken(ctx, "tok-revoked")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row != nil {
		t.Errorf("expected nil for revoked token, got %+v", row)
	}
}

func TestGetActiveToken(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-1", expiry)

	got, err := d.GetActiveToken(ctx, "sub-1")
	if err != nil {
		t.Fatalf("get active token: %v", err)
	}
	if got != "tok-1" {
		t.Errorf("want tok-1, got %s", got)
	}
}

func TestGetActiveTokenNone(t *testing.T) {
	d := openTestDB(t)
	got, err := d.GetActiveToken(context.Background(), "no-sub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestExtendToken(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-1", expiry)

	newExpiry := time.Now().UTC().Add(60 * 24 * time.Hour)
	if err := d.ExtendToken(ctx, "sub-1", newExpiry); err != nil {
		t.Fatalf("extend token: %v", err)
	}

	row, err := d.ValidateToken(ctx, "tok-1")
	if err != nil || row == nil {
		t.Fatalf("validate after extend: %v", err)
	}
	if !row.ExpiresAt.After(expiry) {
		t.Errorf("expected extended expiry, got %v (original %v)", row.ExpiresAt, expiry)
	}
	// expiry_notified_at should be cleared
	if row.ExpiryNotifiedAt.Valid {
		t.Errorf("expiry_notified_at should be NULL after extend")
	}
}

func TestMarkExpiryNotified(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(-1 * time.Hour) // already expired
	_ = d.CreateToken(ctx, "sub-1", "tok-exp", expiry)

	if err := d.MarkExpiryNotified(ctx, "tok-exp"); err != nil {
		t.Fatalf("mark expiry notified: %v", err)
	}

	row, _ := d.ValidateToken(ctx, "tok-exp")
	if row == nil || !row.ExpiryNotifiedAt.Valid {
		t.Error("expiry_notified_at should be set")
	}
}

func TestCleanupExpired(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	// Create a token expired more than 90 days ago
	oldExpiry := time.Now().UTC().Add(-100 * 24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-old", oldExpiry)

	// Create a recent active token
	freshExpiry := time.Now().UTC().Add(30 * 24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-new", freshExpiry)

	n, err := d.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 deleted token, got %d", n)
	}

	// Fresh token should survive
	row, _ := d.ValidateToken(ctx, "tok-new")
	if row == nil {
		t.Error("fresh token should survive cleanup")
	}
}

func TestGetTokenForPubkey(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{},
		sql.NullString{String: "pubkey-hex", Valid: true},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-1", expiry)

	got, err := d.GetTokenForPubkey(ctx, "pubkey-hex")
	if err != nil {
		t.Fatalf("get token for pubkey: %v", err)
	}
	if got != "tok-1" {
		t.Errorf("want tok-1, got %s", got)
	}
}

func TestGetTokenForPubkeyExpiredToken(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{},
		sql.NullString{String: "pubkey-hex", Valid: true},
	)
	// Expired token — should NOT be returned
	expiry := time.Now().UTC().Add(-1 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-exp", expiry)

	got, err := d.GetTokenForPubkey(ctx, "pubkey-hex")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty for expired token, got %q", got)
	}
}

func TestListSubscribers(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-1", expiry)

	_ = d.UpsertSubscriber(ctx, "sub-2",
		sql.NullString{String: "b@example.com", Valid: true},
		sql.NullString{},
	)
	// sub-2 has no token

	rows, err := d.ListSubscribers(ctx, false, false, 0)
	if err != nil {
		t.Fatalf("list subscribers: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("want 2 subscribers, got %d", len(rows))
	}

	rows, err = d.ListSubscribers(ctx, true, false, 0)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("want 1 active subscriber, got %d", len(rows))
	}
}

func TestCLIStats(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-active", expiry)

	_ = d.UpsertSubscriber(ctx, "sub-2",
		sql.NullString{String: "b@example.com", Valid: true},
		sql.NullString{},
	)
	expiredAt := time.Now().UTC().Add(-1 * time.Hour)
	_ = d.CreateToken(ctx, "sub-2", "tok-exp", expiredAt)

	stats, err := d.CLIStats(ctx)
	if err != nil {
		t.Fatalf("cli stats: %v", err)
	}
	if stats.TotalSubscribers != 2 {
		t.Errorf("want 2 total, got %d", stats.TotalSubscribers)
	}
	if stats.ActiveTokens != 1 {
		t.Errorf("want 1 active, got %d", stats.ActiveTokens)
	}
	if stats.NeverAccessed != 2 {
		t.Errorf("want 2 never accessed, got %d", stats.NeverAccessed)
	}
	if stats.ExpiredUnnotified != 1 {
		t.Errorf("want 1 expired unnotified, got %d", stats.ExpiredUnnotified)
	}
}

func TestSetTokenExpiryAndClearNotified(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	_ = d.UpsertSubscriber(ctx, "sub-1",
		sql.NullString{String: "a@example.com", Valid: true},
		sql.NullString{},
	)
	expiry := time.Now().UTC().Add(24 * time.Hour)
	_ = d.CreateToken(ctx, "sub-1", "tok-1", expiry)
	_ = d.MarkExpiryNotified(ctx, "tok-1")

	// Expire it
	if err := d.SetTokenExpiry(ctx, "tok-1", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	// Clear notification flag
	if err := d.ClearExpiryNotified(ctx, "tok-1"); err != nil {
		t.Fatalf("clear notified: %v", err)
	}

	row, _ := d.ValidateToken(ctx, "tok-1")
	if row == nil {
		t.Fatal("token should still exist (revoked=0)")
	}
	if row.ExpiryNotifiedAt.Valid {
		t.Error("expiry_notified_at should be NULL")
	}
}

// TestMain ensures the test binary can find the SQLite driver.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
