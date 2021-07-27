package code

//go:generate mockgen -destination=mocks/mock_persistence.go -package=mocks github.com/ory/kratos/selfservice/strategy/code CodePersister

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
)

type CodePersister interface {
	CreateCode(ctx context.Context, code *Code) error
	UpdateCode(ctx context.Context, code *Code) error

	// DeleteCodes deletes all codes with the given identifier
	DeleteCodes(ctx context.Context, identifier string) error

	// FindActiveCode selects code by login flow id and expiration date/time.
	FindActiveCode(ctx context.Context, flowId uuid.UUID, expiresAfter time.Time) (*Code, error)
	CountByIdentifier(ctx context.Context, identifier string, createdAfter time.Time) (int, error)
	CountByIdentifierLike(ctx context.Context, identifier string, createdAfter time.Time) (int, error)
}

type CodePersistenceProvider interface {
	CodePersister() CodePersister
}
