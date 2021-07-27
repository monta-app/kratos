// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"fmt"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/x/sqlcon"
)

var _ code.CodePersister = new(Persister)

func (p *Persister) CreateCode(ctx context.Context, code *code.Code) error {
	return p.GetConnection(ctx).Create(code)
}

func (p *Persister) UpdateCode(ctx context.Context, code *code.Code) error {
	return p.GetConnection(ctx).Update(code)
}

func (p *Persister) FindActiveCode(ctx context.Context, flowId uuid.UUID, expiresAfter time.Time) (*code.Code, error) {
	var r []code.Code
	if err := p.GetConnection(ctx).Where("flow_id = ? AND expires_at > ?", flowId, expiresAfter).All(&r); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	if len(r) > 0 {
		return &r[0], nil
	}
	return nil, nil
}

func (p *Persister) CheckCodeExistsByFlowId(ctx context.Context, flowId uuid.UUID) (bool, error) {
	var r []code.Code
	exists, err := p.GetConnection(ctx).Where("flow_id = ?", flowId).Exists(&r)
	if err != nil {
		return false, sqlcon.HandleError(err)
	}
	return exists, nil
}

func (p *Persister) DeleteCodes(ctx context.Context, identifier string) error {
	return p.GetConnection(ctx).RawQuery(fmt.Sprintf(
		"DELETE FROM %s WHERE identifier=?", new(code.Code).TableName(ctx)), identifier).Exec()
}

func (p *Persister) CountByIdentifier(ctx context.Context, identifier string, createdAfter time.Time) (int, error) {
	return p.GetConnection(ctx).Where("identifier = ? AND created_at > ?", identifier, createdAfter).Count(&code.Code{})
}

func (p *Persister) CountByIdentifierLike(ctx context.Context, identifier string, createdAfter time.Time) (int, error) {
	return p.GetConnection(ctx).Where("identifier LIKE ? AND created_at > ?", identifier, createdAfter).Count(&code.Code{})
}
