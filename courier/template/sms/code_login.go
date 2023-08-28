// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sms

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ory/kratos/courier/template"
)

type (
	CodeMessage struct {
		d template.Dependencies
		m *CodeMessageModel
	}
	CodeMessageModel struct {
		To               string
		Code             string
		UseStandbySender bool
		TransientPayload json.RawMessage
	}
)

func NewCodeMessage(d template.Dependencies, m *CodeMessageModel) *CodeMessage {
	return &CodeMessage{d: d, m: m}
}

func (t *CodeMessage) PhoneNumber() (string, error) {
	return t.m.To, nil
}

func (t *CodeMessage) UseStandbySender() bool {
	return t.m.UseStandbySender
}

func (t *CodeMessage) SMSBody(ctx context.Context) (string, error) {
	return template.LoadText(ctx, t.d, os.DirFS(t.d.CourierConfig().CourierTemplatesRoot(ctx)), "login/sms.body.gotmpl", "login/sms.body*", t.m, t.d.CourierConfig().CourierTemplatesVerificationValidSMS(ctx))
}

func (t *CodeMessage) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.m)
}
