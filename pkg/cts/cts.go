package cts

import (
	"context"
	"errors"
)

// Account represents account in corporate tournament service
type Account struct {
	ID    uint
	Email string
}

// ErrNotFound is returned when item wasn't found.
var ErrNotFound = errors.New("Not found")

// Service is the interface that wraps all interaction methods with db.
type Service interface {
	// AddToken adds email with token to db and sets expiration time.
	AddToken(ctx context.Context, token string, email string) error

	// DeleteToken deletes token from db. If token wasn't found, it returns ErrNotFound.
	DeleteToken(ctx context.Context, token string) error

	// DeleteTokensByExpTimee deletes all tokens, that expired.
	DeleteTokensByExpTime(ctx context.Context, token string) error

	// AddAccount adds account email to db. It returns id of this account.
	AddAccount(ctx context.Context, email string) (uint, error)
}
