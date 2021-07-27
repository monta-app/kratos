package code

import (
	"context"
	"net/http"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
)

type strategyDependencies interface {
	config.Provider
	x.CSRFProvider
	x.CSRFTokenGeneratorProvider
	session.ManagementProvider
	identity.PoolProvider
	identity.PrivilegedPoolProvider
	identity.ManagementProvider
	identity.ValidationProvider
	x.LoggingProvider
	AuthenticationServiceProvider

	registration.HandlerProvider

	verification.FlowPersistenceProvider
	verification.HookExecutorProvider
}

type Strategy struct {
	d  strategyDependencies
	hd *decoderx.HTTP
}

func NewStrategy(d strategyDependencies) *Strategy {
	return &Strategy{
		d: d,
	}
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

func (s *Strategy) NodeGroup() node.Group {
	return node.CodeGroup
}

func (s *Strategy) RegisterLoginRoutes(*x.RouterPublic) {

}

func (s *Strategy) populateMethod(r *http.Request, c *container.Container, message *text.Message) error {
	c.SetCSRF(s.d.GenerateCSRFToken(r))
	c.GetNodes().Append(node.NewInputField("method", "code", node.CodeGroup,
		node.InputAttributeTypeSubmit).WithMetaLabel(message))
	return nil
}
