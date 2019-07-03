package storage

import (
	"context"
	"errors"
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
		return errors.New("No rows affected")
	}
	return nil
}

// DeleteToken deletes token from db. If token wasn't found, it returns ErrNotFound.
func (db *DB) DeleteToken(ctx context.Context, token string) error {
	delete, err := db.conn.ExecContext(ctx, `
	DELETE FROM emails_tokens
	WHERE token = ?
	`, token)
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

// DeleteTokensByExpTime deletes all tokens, that expired.
func (db *DB) DeleteTokensByExpTime(ctx context.Context, token string) error {
	delete, err := db.conn.ExecContext(ctx, `
	DELETE FROM emails_tokens
	WHERE CURRENT_TIMESTAMP>=exp_at
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
