package storage

import (
	"context"
	"errors"
)

// AddAccount adds account email to db. It returns id of this account.
func (db *DB) AddAccount(ctx context.Context, email string) (uint, error) {
	insert, err := db.conn.ExecContext(ctx, `
INSERT INTO accounts (email)
	 VALUES(?,?)
	`, email)
	if err != nil {
		return 0, err
	}
	rows, err := insert.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows == 0 {
		return 0, errors.New("No rows affected")
	}
	return 0, nil
}
