// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package continuity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
)

type ManagementProvider interface {
	ContinuityManager() Manager
}

type Manager interface {
	Pause(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, opts ...ManagerOption) error
	Continue(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, opts ...ManagerOption) (*Container, error)
	Abort(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, opts ...ManagerOption) error
}

type managerOptions struct {
	iid           uuid.UUID
	ttl           time.Duration
	setExpiresIn  time.Duration
	payload       json.RawMessage
	payloadRaw    interface{}
	useRelayState bool
}

type ManagerOption func(*managerOptions) error

func newManagerOptions(opts []ManagerOption) (*managerOptions, error) {
	var o = &managerOptions{
		ttl: time.Minute * 10,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func WithIdentity(i *identity.Identity) ManagerOption {
	return func(o *managerOptions) error {
		if i != nil {
			o.iid = i.ID
		}
		return nil
	}
}

func WithLifespan(ttl time.Duration) ManagerOption {
	return func(o *managerOptions) error {
		o.ttl = ttl
		return nil
	}
}

func WithPayload(payload interface{}) ManagerOption {
	return func(o *managerOptions) error {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(payload); err != nil {
			return errors.WithStack(err)
		}
		o.payload = b.Bytes()
		o.payloadRaw = payload
		return nil
	}
}

func WithExpireInsteadOfDelete(duration time.Duration) ManagerOption {
	return func(o *managerOptions) error {
		o.setExpiresIn = duration
		return nil
	}
}

func UseRelayState() ManagerOption {
	return func(o *managerOptions) error {
		o.useRelayState = true
		return nil
	}
}
