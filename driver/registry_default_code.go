// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"github.com/ory/kratos/selfservice/strategy/code"
)

func (m *RegistryDefault) CodeAuthenticationService() code.AuthenticationService {
	if m.selfserviceCodeAuthenticationService == nil {
		m.selfserviceCodeAuthenticationService = code.NewCodeAuthenticationService(m)
	}

	return m.selfserviceCodeAuthenticationService
}

func (m *RegistryDefault) RandomCodeGenerator() code.RandomCodeGenerator {
	if m.selfserviceRandomCodeGenerator == nil {
		m.selfserviceRandomCodeGenerator = code.NewRandomCodeGenerator()
	}

	return m.selfserviceRandomCodeGenerator
}
