// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"fmt"
	"strings"
	"sync"

	"github.com/nyaruka/phonenumbers"

	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/jsonschema/v3"
	"github.com/ory/x/sqlxx"

	"github.com/ory/kratos/schema"
)

type SchemaExtensionCredentials struct {
	i *Identity
	v map[CredentialsType][]string
	l sync.Mutex
}

func NewSchemaExtensionCredentials(i *Identity) *SchemaExtensionCredentials {
	return &SchemaExtensionCredentials{i: i, v: make(map[CredentialsType][]string)}
}

func (r *SchemaExtensionCredentials) setIdentifier(ct CredentialsType, value interface{}) {
	r.v[ct] = stringslice.Unique(append(r.v[ct], strings.ToLower(fmt.Sprintf("%s", value))))
}

func (r *SchemaExtensionCredentials) Run(ctx jsonschema.ValidationContext, s schema.ExtensionConfig, value interface{}) error {
	r.l.Lock()
	defer r.l.Unlock()

	if s.Credentials.Password.Identifier {
		r.setIdentifier(CredentialsTypePassword, value)
	}

	if s.Credentials.WebAuthn.Identifier {
		r.setIdentifier(CredentialsTypeWebAuthn, value)
	}

	if s.Credentials.Code.Identifier {
		phoneNumber, err := phonenumbers.Parse(fmt.Sprintf("%s", value), "")
		if err != nil {
			validationError := ctx.Error("format", "%s", err)
			return validationError
		}
		e164 := fmt.Sprintf("+%d%d", *phoneNumber.CountryCode, *phoneNumber.NationalNumber)
		r.setIdentifier(CredentialsTypeCode, e164)
	}

	return nil
}

func (r *SchemaExtensionCredentials) Finish() error {
	r.l.Lock()
	defer r.l.Unlock()

	for ct := range r.i.Credentials {
		_, ok := r.v[ct]
		if !ok {
			r.v[ct] = []string{}
		}
	}
	for ct, identifiers := range r.v {
		cred, ok := r.i.GetCredentials(ct)
		if !ok {
			cred = &Credentials{
				Type:        ct,
				Identifiers: []string{},
				Config:      sqlxx.JSONRawMessage{},
			}
		}

		if ct == CredentialsTypePassword || ct == CredentialsTypeCode || ct == CredentialsTypeWebAuthn {
			cred.Identifiers = identifiers
			r.i.SetCredentials(ct, *cred)
		}
	}

	return nil
}
