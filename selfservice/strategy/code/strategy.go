// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"net/http"

	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/randx"
)

var _ recovery.Strategy = new(Strategy)
var _ recovery.AdminHandler = new(Strategy)
var _ recovery.PublicHandler = new(Strategy)

var _ verification.Strategy = new(Strategy)
var _ verification.AdminHandler = new(Strategy)
var _ verification.PublicHandler = new(Strategy)

type (
	// FlowMethod contains the configuration for this selfservice strategy.
	FlowMethod struct {
		*container.Container
	}

	strategyDependencies interface {
		x.CSRFProvider
		x.CSRFTokenGeneratorProvider
		x.WriterProvider
		x.LoggingProvider

		config.Provider

		session.HandlerProvider
		session.ManagementProvider
		settings.HandlerProvider
		settings.FlowPersistenceProvider

		identity.ValidationProvider
		identity.ManagementProvider
		identity.PoolProvider
		identity.PrivilegedPoolProvider

		courier.Provider

		errorx.ManagementProvider

		recovery.ErrorHandlerProvider
		recovery.FlowPersistenceProvider
		recovery.StrategyProvider
		recovery.HookExecutorProvider

		registration.HandlerProvider

		verification.FlowPersistenceProvider
		verification.StrategyProvider
		verification.HookExecutorProvider

		AuthenticationServiceProvider
		CodePersistenceProvider
		RecoveryCodePersistenceProvider
		VerificationCodePersistenceProvider
		SenderProvider

		schema.IdentityTraitsProvider
	}

	Strategy struct {
		deps strategyDependencies
		dx   *decoderx.HTTP
	}
)

func NewStrategy(deps strategyDependencies) *Strategy {
	return &Strategy{deps: deps, dx: decoderx.NewHTTP()}
}

func (s *Strategy) RecoveryNodeGroup() node.UiNodeGroup {
	return node.CodeGroup
}

func (s *Strategy) VerificationNodeGroup() node.UiNodeGroup {
	return node.CodeGroup
}

const CodeLength = 6

func GenerateCode() string {
	return randx.MustString(CodeLength, randx.Numeric)
}

func (s *Strategy) ID() identity.CredentialsType {
	return identity.CredentialsTypeCode
}

func (s *Strategy) CompletedAuthenticationMethod(ctx context.Context) session.AuthenticationMethod {
	return session.AuthenticationMethod{
		Method: s.ID(),
		AAL:    identity.AuthenticatorAssuranceLevel1,
	}
}

func (s *Strategy) NodeGroup() node.UiNodeGroup {
	return node.CodeGroup
}

func (s *Strategy) RegisterLoginRoutes(*x.RouterPublic) {

}

func (s *Strategy) populateMethod(r *http.Request, c *container.Container, message *text.Message) error {
	c.SetCSRF(s.deps.GenerateCSRFToken(r))
	c.GetNodes().Append(node.NewInputField("method", "code", node.CodeGroup,
		node.InputAttributeTypeSubmit).WithMetaLabel(message))
	return nil
}
