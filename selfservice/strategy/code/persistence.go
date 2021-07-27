// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

//go:generate mockgen -destination=mocks/mock_persistence.go -package=mocks github.com/ory/kratos/selfservice/strategy/code CodePersister

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
)

type (
	RecoveryCodePersister interface {
		CreateRecoveryCode(ctx context.Context, dto *CreateRecoveryCodeParams) (*RecoveryCode, error)
		UseRecoveryCode(ctx context.Context, fID uuid.UUID, code string) (*RecoveryCode, error)
		DeleteRecoveryCodesOfFlow(ctx context.Context, fID uuid.UUID) error
	}

	RecoveryCodePersistenceProvider interface {
		RecoveryCodePersister() RecoveryCodePersister
	}

	VerificationCodePersister interface {
		CreateVerificationCode(context.Context, *CreateVerificationCodeParams) (*VerificationCode, error)
		UseVerificationCode(context.Context, uuid.UUID, string) (*VerificationCode, error)
		DeleteVerificationCodesOfFlow(context.Context, uuid.UUID) error
	}

	VerificationCodePersistenceProvider interface {
		VerificationCodePersister() VerificationCodePersister
	}

	CodePersister interface {
		CreateCode(ctx context.Context, code *Code) error
		UpdateCode(ctx context.Context, code *Code) error

		// DeleteCodes deletes all codes with the given identifier
		DeleteCodes(ctx context.Context, identifier string) error

		// FindActiveCode selects code by login flow id and expiration date/time.
		FindActiveCode(ctx context.Context, flowId uuid.UUID, expiresAfter time.Time) (*Code, error)
		CheckCodeExistsByFlowId(ctx context.Context, flowId uuid.UUID) (bool, error)
		CountByIdentifier(ctx context.Context, identifier string, createdAfter time.Time) (int, error)
		CountByIdentifierLike(ctx context.Context, identifier string, createdAfter time.Time) (int, error)
	}

	CodePersistenceProvider interface {
		CodePersister() CodePersister
	}
)
