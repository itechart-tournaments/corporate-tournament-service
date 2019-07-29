package storage

// AddAccount adds account email to db. It returns id of this account.
func (db *DB) AddAccount(email string) (uint, error) {
	insert, err := db.conn.Exec(`
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
