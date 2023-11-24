// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"context"
	"github.com/ory/x/sqlxx"
	"time"

	"github.com/gofrs/uuid"
)

type (
	FlowPersister interface {
		UpdateLoginFlow(context.Context, *Flow) error
		CreateLoginFlow(context.Context, *Flow) error
		GetLoginFlow(context.Context, uuid.UUID) (*Flow, error)
		ForceLoginFlow(ctx context.Context, id uuid.UUID) error
		DeleteExpiredLoginFlows(context.Context, time.Time, int) error
		GetInternalContext(context.Context, uuid.UUID) (sqlxx.JSONRawMessage, error)
	}
	FlowPersistenceProvider interface {
		LoginFlowPersister() FlowPersister
	}
)
