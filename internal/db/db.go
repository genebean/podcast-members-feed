// Package db provides the SQLite-backed store for subscribers and feed tokens.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS subscribers (
    btcpay_subscriber_id  TEXT PRIMARY KEY,
    email                 TEXT,
    nostr_pubkey          TEXT,
    created_at            TEXT NOT NULL,
    CHECK (email IS NOT NULL OR nostr_pubkey IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS tokens (
    token                 TEXT PRIMARY KEY,
    btcpay_subscriber_id  TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    last_used_at          TEXT,
    revoked               INTEGER NOT NULL DEFAULT 0,
    expiry_notified_at    TEXT,
    FOREIGN KEY (btcpay_subscriber_id)
        REFERENCES subscribers(btcpay_subscriber_id)
);

CREATE INDEX IF NOT EXISTS idx_tokens_subscriber
    ON tokens(btcpay_subscriber_id);
`

// DB wraps a SQLite connection.
type DB struct {
	conn *sql.DB
}

// TokenRow holds the columns returned by ValidateToken.
type TokenRow struct {
	Token              string
	BTCPaySubscriberID string
	ExpiresAt          time.Time
	CreatedAt          time.Time
	LastUsedAt         sql.NullTime
	Revoked            bool
	ExpiryNotifiedAt   sql.NullTime
	Email              sql.NullString
	NostrPubkey        sql.NullString
}

// Stats holds aggregate counts returned by SubscriberStats.
type Stats struct {
	TotalSubscribers int
	ActiveTokens     int
}

// Open opens or creates the SQLite database at path and initialises the schema.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite supports only one concurrent writer. Limiting to one connection
	// serialises all reads and writes through a single handle, which prevents
	// "database is locked" errors under concurrent HTTP requests.
	conn.SetMaxOpenConns(1)
	d := &DB{conn: conn}
	if err := d.init(context.Background()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return d, nil
}

func (d *DB) init(ctx context.Context) error {
	_, err := d.conn.ExecContext(ctx, schema)
	return err
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// UpsertSubscriber inserts or updates a subscriber record.
// At least one of email or nostrPubkey must be non-nil.
func (d *DB) UpsertSubscriber(ctx context.Context, id string, email, nostrPubkey sql.NullString) error {
	if !email.Valid && !nostrPubkey.Valid {
		return fmt.Errorf("subscriber must provide email or Nostr npub")
	}
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO subscribers (btcpay_subscriber_id, email, nostr_pubkey, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(btcpay_subscriber_id) DO UPDATE SET
		    email        = COALESCE(excluded.email, email),
		    nostr_pubkey = COALESCE(excluded.nostr_pubkey, nostr_pubkey)
	`, id, email, nostrPubkey, nowISO())
	return err
}

// CreateToken writes a new token record and returns an error on conflict.
func (d *DB) CreateToken(ctx context.Context, subscriberID, token string, expiresAt time.Time) error {
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO tokens (token, btcpay_subscriber_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`, token, subscriberID, expiresAt.UTC().Format(time.RFC3339Nano), nowISO())
	return err
}

// GetActiveToken returns the most recent non-revoked token for a subscriber,
// or ("", nil) if none exists.
func (d *DB) GetActiveToken(ctx context.Context, subscriberID string) (string, error) {
	var token string
	err := d.conn.QueryRowContext(ctx, `
		SELECT token FROM tokens
		WHERE btcpay_subscriber_id = ? AND revoked = 0
		ORDER BY created_at DESC LIMIT 1
	`, subscriberID).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// ExtendToken updates the expiry on the active token and clears expiry_notified_at
// so a renewed token works cleanly without issuing a new feed URL.
func (d *DB) ExtendToken(ctx context.Context, subscriberID string, newExpiresAt time.Time) error {
	_, err := d.conn.ExecContext(ctx, `
		UPDATE tokens SET expires_at = ?, expiry_notified_at = NULL
		WHERE btcpay_subscriber_id = ?
		  AND revoked = 0
		  AND token = (
		    SELECT token FROM tokens
		    WHERE btcpay_subscriber_id = ? AND revoked = 0
		    ORDER BY created_at DESC LIMIT 1
		  )
	`, newExpiresAt.UTC().Format(time.RFC3339Nano), subscriberID, subscriberID)
	return err
}

// RevokeTokens marks all tokens for a subscriber as revoked.
func (d *DB) RevokeTokens(ctx context.Context, subscriberID string) error {
	_, err := d.conn.ExecContext(ctx,
		"UPDATE tokens SET revoked = 1 WHERE btcpay_subscriber_id = ?",
		subscriberID,
	)
	return err
}

// ValidateToken looks up a non-revoked token and updates last_used_at.
// Returns (nil, nil) for unknown or revoked tokens.
func (d *DB) ValidateToken(ctx context.Context, token string) (*TokenRow, error) {
	var expiresAtStr, createdAtStr string
	var lastUsedAtStr, expiryNotifiedAtStr sql.NullString
	var revokedInt int

	row := &TokenRow{}
	err := d.conn.QueryRowContext(ctx, `
		SELECT t.token, t.btcpay_subscriber_id, t.expires_at, t.created_at,
		       t.last_used_at, t.revoked, t.expiry_notified_at,
		       s.email, s.nostr_pubkey
		FROM tokens t
		JOIN subscribers s USING (btcpay_subscriber_id)
		WHERE t.token = ? AND t.revoked = 0
	`, token).Scan(
		&row.Token, &row.BTCPaySubscriberID, &expiresAtStr, &createdAtStr,
		&lastUsedAtStr, &revokedInt, &expiryNotifiedAtStr,
		&row.Email, &row.NostrPubkey,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	row.Revoked = revokedInt != 0
	row.ExpiresAt = parseISO(expiresAtStr)
	row.CreatedAt = parseISO(createdAtStr)
	if lastUsedAtStr.Valid {
		row.LastUsedAt = sql.NullTime{Time: parseISO(lastUsedAtStr.String), Valid: true}
	}
	if expiryNotifiedAtStr.Valid {
		row.ExpiryNotifiedAt = sql.NullTime{Time: parseISO(expiryNotifiedAtStr.String), Valid: true}
	}

	_, _ = d.conn.ExecContext(ctx,
		"UPDATE tokens SET last_used_at = ? WHERE token = ?",
		nowISO(), token,
	)
	return row, nil
}

// MarkExpiryNotified sets expiry_notified_at to now for the given token.
func (d *DB) MarkExpiryNotified(ctx context.Context, token string) error {
	_, err := d.conn.ExecContext(ctx,
		"UPDATE tokens SET expiry_notified_at = ? WHERE token = ?",
		nowISO(), token,
	)
	return err
}

// CleanupExpired removes tokens that were revoked or expired more than 90 days ago.
func (d *DB) CleanupExpired(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour).Format(time.RFC3339Nano)
	result, err := d.conn.ExecContext(ctx,
		"DELETE FROM tokens WHERE (revoked = 1 AND created_at < ?) OR expires_at < ?",
		cutoff, cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// SubscriberStats returns aggregate subscriber and active-token counts.
func (d *DB) SubscriberStats(ctx context.Context) (Stats, error) {
	var s Stats
	if err := d.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM subscribers",
	).Scan(&s.TotalSubscribers); err != nil {
		return s, err
	}
	if err := d.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ?",
		nowISO(),
	).Scan(&s.ActiveTokens); err != nil {
		return s, err
	}
	return s, nil
}

// GetTokenForPubkey returns the most recent active token for a Nostr pubkey (hex).
func (d *DB) GetTokenForPubkey(ctx context.Context, pubkeyHex string) (string, error) {
	var token string
	err := d.conn.QueryRowContext(ctx, `
		SELECT t.token FROM tokens t
		JOIN subscribers s USING (btcpay_subscriber_id)
		WHERE s.nostr_pubkey = ?
		  AND t.revoked = 0
		  AND t.expires_at > ?
		ORDER BY t.created_at DESC LIMIT 1
	`, pubkeyHex, nowISO()).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// ─── CLI-only helpers ───────────────────────────────────────────────────────

// SubscriberRow is the full view used by the management CLI.
type SubscriberRow struct {
	BTCPaySubscriberID string
	Email              sql.NullString
	NostrPubkey        sql.NullString
	CreatedAt          string
	Token              sql.NullString
	ExpiresAt          sql.NullString
	LastUsedAt         sql.NullString
	ExpiryNotifiedAt   sql.NullString
}

// ListSubscribers returns subscribers matching the given filter conditions.
// active, neverAccessed, and expiringWithinDays are mutually exclusive filters.
func (d *DB) ListSubscribers(ctx context.Context, active, neverAccessed bool, expiringWithinDays int) ([]SubscriberRow, error) {
	now := nowISO()
	where := "1=1"
	args := []any{}

	switch {
	case active:
		where = "EXISTS (SELECT 1 FROM tokens t WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id AND t.revoked = 0 AND t.expires_at > ?)"
		args = append(args, now)
	case neverAccessed:
		where = "EXISTS (SELECT 1 FROM tokens t WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id AND t.last_used_at IS NULL AND t.revoked = 0)"
	case expiringWithinDays > 0:
		cutoff := time.Now().UTC().Add(time.Duration(expiringWithinDays) * 24 * time.Hour).Format(time.RFC3339Nano)
		where = "EXISTS (SELECT 1 FROM tokens t WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id AND t.revoked = 0 AND t.expires_at > ? AND t.expires_at < ?)"
		args = append(args, now, cutoff)
	}

	query := fmt.Sprintf(`
		SELECT s.btcpay_subscriber_id, s.email, s.nostr_pubkey, s.created_at,
		       t.token, t.expires_at, t.last_used_at, t.expiry_notified_at
		FROM subscribers s
		LEFT JOIN tokens t ON t.btcpay_subscriber_id = s.btcpay_subscriber_id
		    AND t.revoked = 0
		    AND t.token = (
		        SELECT token FROM tokens t2
		        WHERE t2.btcpay_subscriber_id = s.btcpay_subscriber_id
		          AND t2.revoked = 0
		        ORDER BY t2.created_at DESC LIMIT 1
		    )
		WHERE %s
		ORDER BY s.created_at DESC
	`, where)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []SubscriberRow
	for rows.Next() {
		var r SubscriberRow
		if err := rows.Scan(
			&r.BTCPaySubscriberID, &r.Email, &r.NostrPubkey, &r.CreatedAt,
			&r.Token, &r.ExpiresAt, &r.LastUsedAt, &r.ExpiryNotifiedAt,
		); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// GetTokenByEmail looks up a subscriber's most recent active token by email.
func (d *DB) GetTokenByEmail(ctx context.Context, email string) (string, error) {
	var token string
	err := d.conn.QueryRowContext(ctx, `
		SELECT t.token FROM tokens t
		JOIN subscribers s USING (btcpay_subscriber_id)
		WHERE s.email = ? AND t.revoked = 0
		ORDER BY t.created_at DESC LIMIT 1
	`, email).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// GetTokenByNpub looks up a subscriber's most recent active token by Nostr pubkey.
func (d *DB) GetTokenByNpub(ctx context.Context, npub string) (string, error) {
	var token string
	err := d.conn.QueryRowContext(ctx, `
		SELECT t.token FROM tokens t
		JOIN subscribers s USING (btcpay_subscriber_id)
		WHERE s.nostr_pubkey = ? AND t.revoked = 0
		ORDER BY t.created_at DESC LIMIT 1
	`, npub).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// RevokeBySubscriberID revokes all tokens for the given subscriber ID.
// Returns false if the subscriber was not found.
func (d *DB) GetSubscriberEmail(ctx context.Context, subscriberID string) (string, bool, error) {
	var email sql.NullString
	err := d.conn.QueryRowContext(ctx,
		"SELECT email FROM subscribers WHERE btcpay_subscriber_id = ?",
		subscriberID,
	).Scan(&email)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return email.String, true, nil
}

// CLIStats returns the extended statistics used by the manage CLI.
type CLIStats struct {
	TotalSubscribers int
	ActiveTokens     int
	NeverAccessed    int
	ExpiredUnnotified int
}

func (d *DB) CLIStats(ctx context.Context) (CLIStats, error) {
	now := nowISO()
	var s CLIStats

	if err := d.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscribers").Scan(&s.TotalSubscribers); err != nil {
		return s, err
	}
	if err := d.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ?", now,
	).Scan(&s.ActiveTokens); err != nil {
		return s, err
	}
	if err := d.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND last_used_at IS NULL",
	).Scan(&s.NeverAccessed); err != nil {
		return s, err
	}
	if err := d.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at < ? AND expiry_notified_at IS NULL", now,
	).Scan(&s.ExpiredUnnotified); err != nil {
		return s, err
	}
	return s, nil
}

// SetTokenExpiry directly updates a token's expiry (used by the test-webhook command).
func (d *DB) SetTokenExpiry(ctx context.Context, token, expiresAt string) error {
	_, err := d.conn.ExecContext(ctx,
		"UPDATE tokens SET expires_at = ? WHERE token = ?",
		expiresAt, token,
	)
	return err
}

// ClearExpiryNotified clears expiry_notified_at on a token.
func (d *DB) ClearExpiryNotified(ctx context.Context, token string) error {
	_, err := d.conn.ExecContext(ctx,
		"UPDATE tokens SET expiry_notified_at = NULL WHERE token = ?",
		token,
	)
	return err
}

// GetTokenByLookup finds the most recent non-revoked token for a subscriber identified
// by either email or nostr_pubkey (whichever is non-empty).
func (d *DB) GetTokenByLookupField(ctx context.Context, field, value string) (string, error) {
	query := fmt.Sprintf(`
		SELECT t.token FROM tokens t
		JOIN subscribers s USING (btcpay_subscriber_id)
		WHERE s.%s = ? AND t.revoked = 0
		ORDER BY t.created_at DESC LIMIT 1
	`, field)
	var token string
	err := d.conn.QueryRowContext(ctx, query, value).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseISO(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
