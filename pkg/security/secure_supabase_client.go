//go:build saas

// Package security - Secure Supabase Client with Automatic PQC Encryption
//
// This client transparently encrypts ALL data before INSERT and decrypts after SELECT.
// Applications using this client get automatic PQC protection without code changes.
//
// Example Usage:
//
//	keys, _ := license.GenerateProtectionKeys("Eban")
//	client := security.NewSecureSupabaseClient(supabase.Config{
//	    ProjectURL:     os.Getenv("SUPABASE_URL"),
//	    ServiceRoleKey: os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
//	}, keys)
//
//	// INSERT - automatically encrypted
//	user := &UserProfile{Email: "alice@example.com", SSN: "123-45-6789"}
//	client.Insert(ctx, "users", user)
//
//	// SELECT - automatically decrypted
//	result, _ := client.Select(ctx, "users", "id", userID)
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/supabase"
)

// SecureSupabaseClient wraps Supabase with automatic PQC encryption.
type SecureSupabaseClient struct {
	client *supabase.Client
	keys   *license.ProtectionKeys

	// Metrics
	encryptedInserts int64
	decryptedSelects int64
	encryptionErrors int64
}

// NewSecureSupabaseClient creates a new PQC-encrypted Supabase client.
func NewSecureSupabaseClient(cfg supabase.Config, keys *license.ProtectionKeys) *SecureSupabaseClient {
	return &SecureSupabaseClient{
		client: supabase.NewClient(cfg),
		keys:   keys,
	}
}

// ─── INSERT Operations (Auto-Encrypt) ─────────────────────────────────────────

// Insert encrypts data and inserts a single row into a Supabase table.
func (sc *SecureSupabaseClient) Insert(ctx context.Context, table string, data interface{}) (string, error) {
	protected, err := license.ProtectSupabaseRecord(data, table, sc.keys, time.Time{})
	if err != nil {
		sc.encryptionErrors++
		return "", fmt.Errorf("encrypt %s: %w", table, err)
	}

	body, err := sc.client.Insert(ctx, table, protected)
	if err != nil {
		return "", fmt.Errorf("supabase insert %s: %w", table, err)
	}

	// Parse the returned row to confirm the server-assigned ID (may differ from client-generated ID).
	var inserted []license.SupabaseEncryptedRow
	if jsonErr := json.Unmarshal(body, &inserted); jsonErr == nil && len(inserted) > 0 && inserted[0].ID != "" {
		sc.encryptedInserts++
		return inserted[0].ID, nil
	}

	sc.encryptedInserts++
	return protected.ID, nil
}

// InsertBatch encrypts multiple records and inserts them in bulk.
func (sc *SecureSupabaseClient) InsertBatch(ctx context.Context, table string, records []interface{}) ([]string, error) {
	protectedRows, errs := license.ProtectSupabaseBatch(records, table, sc.keys)
	for i, err := range errs {
		if err != nil {
			sc.encryptionErrors++
			return nil, fmt.Errorf("encrypt record %d for %s: %w", i, table, err)
		}
	}

	body, err := sc.client.Insert(ctx, table, protectedRows)
	if err != nil {
		return nil, fmt.Errorf("supabase batch insert %s: %w", table, err)
	}

	// Parse server-returned IDs when available.
	var inserted []license.SupabaseEncryptedRow
	if jsonErr := json.Unmarshal(body, &inserted); jsonErr == nil && len(inserted) == len(protectedRows) {
		ids := make([]string, len(inserted))
		for i, row := range inserted {
			ids[i] = row.ID
		}
		sc.encryptedInserts += int64(len(records))
		return ids, nil
	}

	// Fall back to client-generated IDs.
	ids := make([]string, len(protectedRows))
	for i, row := range protectedRows {
		ids[i] = row.ID
	}
	sc.encryptedInserts += int64(len(records))
	return ids, nil
}

// ─── SELECT Operations (Auto-Decrypt) ─────────────────────────────────────────

// Select fetches and decrypts a single row matching column=value.
func (sc *SecureSupabaseClient) Select(ctx context.Context, table string, column string, value interface{}) (map[string]interface{}, error) {
	filter := fmt.Sprintf("%s=eq.%v", column, value)
	body, err := sc.client.Select(ctx, table, filter, "*")
	if err != nil {
		return nil, fmt.Errorf("supabase select %s: %w", table, err)
	}

	var rows []license.SupabaseEncryptedRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("unmarshal select %s: %w", table, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("record not found in %s where %s=%v", table, column, value)
	}

	decrypted, err := license.UnprotectSupabaseRecord(&rows[0], sc.keys)
	if err != nil {
		sc.encryptionErrors++
		return nil, fmt.Errorf("decrypt %s: %w", table, err)
	}

	sc.decryptedSelects++
	return decrypted, nil
}

// SelectBatch fetches and decrypts all rows where column is in values.
func (sc *SecureSupabaseClient) SelectBatch(ctx context.Context, table string, column string, values []interface{}) ([]map[string]interface{}, error) {
	// Build PostgREST "in" filter: column=in.(v1,v2,v3)
	valStrs := make([]string, len(values))
	for i, v := range values {
		valStrs[i] = fmt.Sprintf("%v", v)
	}
	filter := fmt.Sprintf("%s=in.(%s)", column, strings.Join(valStrs, ","))

	body, err := sc.client.Select(ctx, table, filter, "*")
	if err != nil {
		return nil, fmt.Errorf("supabase select batch %s: %w", table, err)
	}

	var encryptedRows []license.SupabaseEncryptedRow
	if err := json.Unmarshal(body, &encryptedRows); err != nil {
		return nil, fmt.Errorf("unmarshal select batch %s: %w", table, err)
	}

	ptrs := make([]*license.SupabaseEncryptedRow, len(encryptedRows))
	for i := range encryptedRows {
		ptrs[i] = &encryptedRows[i]
	}

	decrypted, decErrs := license.UnprotectSupabaseBatch(ptrs, sc.keys)
	for i, err := range decErrs {
		if err != nil {
			sc.encryptionErrors++
			return nil, fmt.Errorf("decrypt record %d from %s: %w", i, table, err)
		}
	}

	sc.decryptedSelects += int64(len(decrypted))
	return decrypted, nil
}

// ─── UPDATE Operations (Encrypt-then-Update) ──────────────────────────────────

// Update encrypts newData and updates the row identified by id.
func (sc *SecureSupabaseClient) Update(ctx context.Context, table string, id string, newData interface{}) error {
	protected, err := license.ProtectSupabaseRecord(newData, table, sc.keys, time.Time{})
	if err != nil {
		sc.encryptionErrors++
		return fmt.Errorf("encrypt for update %s: %w", table, err)
	}

	filter := fmt.Sprintf("id=eq.%s", id)
	if _, err := sc.client.Update(ctx, table, filter, protected); err != nil {
		return fmt.Errorf("supabase update %s id=%s: %w", table, id, err)
	}

	sc.encryptedInserts++
	return nil
}

// ─── DELETE Operations (with Audit Trail) ─────────────────────────────────────

// Delete removes the row identified by id and writes an encrypted audit entry.
func (sc *SecureSupabaseClient) Delete(ctx context.Context, table string, id string) error {
	// Fetch current data for audit trail (best-effort; ignore error on missing record).
	currentData, _ := sc.Select(ctx, table, "id", id)

	// Delete from Supabase.
	filter := fmt.Sprintf("id=eq.%s", id)
	if err := sc.client.Delete(ctx, table, filter); err != nil {
		return fmt.Errorf("supabase delete %s id=%s: %w", table, id, err)
	}

	// Write encrypted audit trail entry.
	auditEntry := map[string]interface{}{
		"action":     "DELETE",
		"table":      table,
		"row_id":     id,
		"deleted_at": time.Now().UTC(),
		"data":       currentData,
	}
	protectedAudit, err := license.ProtectAuditLog(auditEntry, sc.keys)
	if err == nil {
		// Store in audit_trail table; log failure but don't block the delete.
		if _, insertErr := sc.client.Insert(ctx, "audit_trail", protectedAudit); insertErr != nil {
			// Non-fatal: audit persistence failure should be monitored but not block operations.
			_ = insertErr
		}
	}

	return nil
}

// ─── Metrics & Monitoring ──────────────────────────────────────────────────────

// GetMetrics returns encryption/decryption statistics.
func (sc *SecureSupabaseClient) GetMetrics() map[string]int64 {
	return map[string]int64{
		"encrypted_inserts": sc.encryptedInserts,
		"decrypted_selects": sc.decryptedSelects,
		"encryption_errors": sc.encryptionErrors,
		"total_operations":  sc.encryptedInserts + sc.decryptedSelects,
	}
}

// ─── Key Rotation ──────────────────────────────────────────────────────────────

// RotateKeys generates new PQC keys and re-encrypts all data in the given tables.
// WARNING: This is a heavy operation; run during a maintenance window.
// pageSize controls how many rows are fetched per request (default 100).
func (sc *SecureSupabaseClient) RotateKeys(ctx context.Context, newSymbol string, tables []string, pageSize int) error {
	newKeys, err := license.GenerateProtectionKeys(newSymbol)
	if err != nil {
		return fmt.Errorf("generate new keys: %w", err)
	}

	if pageSize <= 0 {
		pageSize = 100
	}

	for _, table := range tables {
		if err := sc.rotateKeysForTable(ctx, table, newKeys, pageSize); err != nil {
			return err
		}
	}

	sc.keys = newKeys
	return nil
}

func (sc *SecureSupabaseClient) rotateKeysForTable(ctx context.Context, table string, newKeys *license.ProtectionKeys, pageSize int) error {
	offset := 0
	for {
		filter := fmt.Sprintf("limit=%d&offset=%d", pageSize, offset)
		body, err := sc.client.Select(ctx, table, filter, "*")
		if err != nil {
			return fmt.Errorf("fetch page offset=%d from %s: %w", offset, table, err)
		}

		var encryptedRows []license.SupabaseEncryptedRow
		if err := json.Unmarshal(body, &encryptedRows); err != nil {
			return fmt.Errorf("unmarshal page from %s: %w", table, err)
		}
		if len(encryptedRows) == 0 {
			break // No more pages.
		}

		if err := sc.processEncryptedRows(ctx, table, encryptedRows, newKeys); err != nil {
			return err
		}

		if len(encryptedRows) < pageSize {
			break // Last page.
		}
		offset += pageSize
	}
	return nil
}

func (sc *SecureSupabaseClient) processEncryptedRows(ctx context.Context, table string, encryptedRows []license.SupabaseEncryptedRow, newKeys *license.ProtectionKeys) error {
	for i := range encryptedRows {
		row := &encryptedRows[i]

		plaintext, err := license.UnprotectSupabaseRecord(row, sc.keys)
		if err != nil {
			return fmt.Errorf("decrypt row %s in %s: %w", row.ID, table, err)
		}

		reencrypted, err := license.ProtectSupabaseRecord(plaintext, table, newKeys, row.ExpiresAt)
		if err != nil {
			return fmt.Errorf("re-encrypt row %s in %s: %w", row.ID, table, err)
		}
		// Preserve the original ID so the UPDATE filter matches.
		reencrypted.ID = row.ID

		if err := sc.Update(ctx, table, row.ID, reencrypted); err != nil {
			return fmt.Errorf("update row %s in %s: %w", row.ID, table, err)
		}
	}
	return nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────
