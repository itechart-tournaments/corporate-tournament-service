package storage

import (
	"errors"

	"github.com/itechart-tournaments/corporate-tournament-service/pkg/cts"
	"github.com/jmoiron/sqlx"
)

// DB holds connection to sql DB.
type DB struct {
	conn sqlx.Ext
}

// New constructs new DB according to passed connection.
func New(db *sqlx.DB) *DB {
	return &DB{
		conn: db,
	}
}

// Close closes connection to db.
func (db *DB) Close() {
	db.conn.(*sqlx.DB).Close()
}

func (db *DB) Transactional(f func(s cts.Service) error) error {
	sqlDB, ok := db.conn.(*sqlx.DB)
	if !ok {
		return errors.New("couldn't bring to DB")
	}
	tx, err := sqlDB.Beginx()
	if err != nil {
		return errors.New("couldn't start transaction")
	}

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	return f(&DB{conn: tx})

}
