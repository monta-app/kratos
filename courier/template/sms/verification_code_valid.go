// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sms

import (
	"context"
	"encoding/json"
	"github.com/ory/kratos/courier/template"
	"os"
)

type (
	VerificationCodeValid struct {
		d template.Dependencies
		m *VerificationCodeValidModel
	}
	VerificationCodeValidModel struct {
		To               string
		VerificationURL  string
		VerificationCode string
		Identity         map[string]interface{}
		TransientPayload json.RawMessage
	}
)

func NewVerificationCodeValid(d template.Dependencies, m *VerificationCodeValidModel) *VerificationCodeValid {
	return &VerificationCodeValid{d: d, m: m}
}

func (t *VerificationCodeValid) PhoneNumber() (string, error) {
	return t.m.To, nil
}

func (t *VerificationCodeValid) SMSBody(ctx context.Context) (string, error) {
	return template.LoadText(ctx, t.d, os.DirFS(t.d.CourierConfig().CourierTemplatesRoot(ctx)), "verification_code/valid/sms.body.gotmpl", "verification_code/valid/sms.body*", t.m, t.d.CourierConfig().CourierTemplatesVerificationValidSMS(ctx))
}

func (t *VerificationCodeValid) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.m)
}
