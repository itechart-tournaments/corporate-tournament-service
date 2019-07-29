package cts

import (
	"context"
	"errors"
	"time"
)

// Account represents account in corporate tournament service
type Account struct {
	ID    uint
	Email string
}

// ErrNotFound is returned when item wasn't found.
var ErrNotFound = errors.New("not found")

// Service is the interface that wraps all interaction methods with db.
type Service interface {
	// Transactional is wrapper function for executing db queries in one transaction.
	Transactional(ctx context.Context, f func(s Service) error) error

	// AddToken adds email with token to db and sets expiration time.
	AddToken(token string, email string, expTime time.Time) error

	DeleteToken(token string) error

	// GetEmail finds email connected with given token.
	// If email wasn't found, it returns ErrNotFound.
	GetEmail(token string) (string, error)

	// DeleteTokensByExpTime deletes all tokens, that expired.
	DeleteTokensByExpTime() error

	// AddAccount adds account email to db.
	// It returns id of the added account if succeed.
	AddAccount(email string) (uint, error)
}
