package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/itechart-tournaments/corporate-tournament-service/pkg/cts"
)

// AddToken adds email with token to db and sets expiration time.
func (db *DB) AddToken(token string, email string, expTime time.Time) error {
	insert, err := db.conn.Exec(`
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

func (db *DB) GetEmail(token string) (string, error) {
	var email string
	err := db.conn.QueryRowx(`
SELECT email 
	 FROM emails_tokens
	 WHERE token = ? `, token).Scan(&email)
	if err == sql.ErrNoRows {
		return "", cts.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("couldn't get email: %s", err)
	}
	return email, nil
}

func (db *DB) DeleteToken(token string) error {
	delete, err := db.conn.Exec(` 
DELETE FROM emails_tokens
     WHERE token = ?
	`, token)
	if err != nil {
		return fmt.Errorf("couldn't delete token: %s", err)
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
func (db *DB) DeleteTokensByExpTime() error {
	delete, err := db.conn.Exec(`
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
