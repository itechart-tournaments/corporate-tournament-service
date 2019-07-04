package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/itechart-tournaments/corporate-tournament-service/pkg/cts"
)

// AddToken adds email with token to db and sets expiration time.
func (db *DB) AddToken(ctx context.Context, token string, email string, expTime time.Time) error {
	insert, err := db.conn.ExecContext(ctx, `
INSERT INTO emails_tokens (token,email,exp_at)
	 VALUES(?,?,+)
	`, token, email, expTime)
	if err != nil {
		return err
	}
	rows, err := insert.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no rows affected")
	}
	return nil
}

// VerifyToken checks for token in db and deletes it. It returns email. If token wasn't found, it returns ErrNotFound.
func (db *DB) VerifyToken(ctx context.Context, token string) (string, error) {
	tx, err := db.conn.BeginTxx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("couldn't start transation: %s", err)
	}
	defer tx.Rollback()
	var email string
	err = tx.GetContext(ctx, email, `
SELECT email 
  FROM emails_tokens
 WHERE token = ? `, token)
	if err == sql.ErrNoRows {
		return "", cts.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("couldn't get token: %s", err)
	}
	_, err = tx.ExecContext(ctx, `
DELETE FROM emails_tokens
      WHERE token = ?
	`, token)
	if err != nil {
		return "", fmt.Errorf("couldn't delete token: %s", err)
	}
	return email, tx.Commit()
}

// DeleteTokensByExpTime deletes all tokens, that expired.
func (db *DB) DeleteTokensByExpTime(ctx context.Context, token string) error {
	delete, err := db.conn.ExecContext(ctx, `
	DELETE FROM emails_tokens
	WHERE CURRENT_TIMESTAMP >= exp_at
	`)
	if err != nil {
		return err
	}
	rows, err := delete.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return cts.ErrNotFound
	}
	return nil
}
