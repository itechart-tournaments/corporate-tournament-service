package storage

import (
	"context"
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
	id, err := insert.LastInsertId()
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}
