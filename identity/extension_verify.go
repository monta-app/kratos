// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"fmt"
	"sync"
	"time"

	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/schema"
)

type SchemaExtensionVerification struct {
	lifespan        time.Duration
	codeTestNumbers []string
	l               sync.Mutex
	v               []VerifiableAddress
	i               *Identity
}

func NewSchemaExtensionVerification(i *Identity, lifespan time.Duration, codeTestNumbers []string) *SchemaExtensionVerification {
	return &SchemaExtensionVerification{i: i, lifespan: lifespan, codeTestNumbers: codeTestNumbers}
}

func (r *SchemaExtensionVerification) Run(ctx jsonschema.ValidationContext, s schema.ExtensionConfig, value interface{}) error {
	r.l.Lock()
	defer r.l.Unlock()

	if s.Credentials.Code.Identifier {
		if err := r.checkTelFormat(ctx, value); err != nil {
			return err
		}
		address := NewVerifiablePhoneAddress(fmt.Sprintf("%s", value), r.i.ID)
		r.appendAddress(address)
	}

	switch s.Verification.Via {
	case AddressTypeEmail:
		if !jsonschema.Formats["email"](value) {
			return ctx.Error("format", "%q is not valid %q", value, "email")
		}

		address := NewVerifiableEmailAddress(fmt.Sprintf("%s", value), r.i.ID)

		r.appendAddress(address)

		return nil

	case AddressTypePhone:
		if err := r.checkTelFormat(ctx, value); err != nil {
			return err
		}

		address := NewVerifiablePhoneAddress(fmt.Sprintf("%s", value), r.i.ID)

		r.appendAddress(address)

		return nil

	case "":
		return nil
	}

	return ctx.Error("", "verification.via has unknown value %q", s.Verification.Via)
}

func (r *SchemaExtensionVerification) Finish() error {
	r.i.VerifiableAddresses = r.v
	return nil
}

func (r *SchemaExtensionVerification) appendAddress(address *VerifiableAddress) {
	if h := has(r.i.VerifiableAddresses, address); h != nil {
		if has(r.v, address) == nil {
			r.v = append(r.v, *h)
		}
		return
	}

	if has(r.v, address) == nil {
		r.v = append(r.v, *address)
	}
}

func has(haystack []VerifiableAddress, needle *VerifiableAddress) *VerifiableAddress {
	for _, has := range haystack {
		if has.Value == needle.Value && has.Via == needle.Via {
			return &has
		}
	}
	return nil
}

func (r *SchemaExtensionVerification) checkTelFormat(ctx jsonschema.ValidationContext, value interface{}) error {
	validationError := ctx.Error("format", "%q is not valid %q", value, "phone")
	num, ok := value.(string)
	if !ok {
		return validationError
	}
	for _, n := range r.codeTestNumbers {
		if num == n {
			return nil
		}
	}
	if !jsonschema.Formats["tel"](num) {
		return validationError
	}
	return nil
}
