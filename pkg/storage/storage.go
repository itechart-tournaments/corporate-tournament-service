package storage

import (
	"github.com/jmoiron/sqlx"
)

// DB holds connection to sql DB.
type DB struct {
	conn *sqlx.DB
}

// New constructs new DB according to passed connection.
func New(db *sqlx.DB) *DB {
	return &DB{
		conn: db,
	}
}

// Close closes connection to db.
func (db *DB) Close() {
	db.conn.Close()
}
