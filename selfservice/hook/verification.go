// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"encoding/json"
	"github.com/ory/x/decoderx"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

var _ registration.PostHookPostPersistExecutor = new(Verifier)
var _ settings.PostHookPostPersistExecutor = new(Verifier)

type (
	verifierDependencies interface {
		config.Provider
		x.CSRFTokenGeneratorProvider
		verification.StrategyProvider
		verification.FlowPersistenceProvider
		identity.PrivilegedPoolProvider
		code.AuthenticationServiceProvider
	}
	Verifier struct {
		r  verifierDependencies
		dx *decoderx.HTTP
	}
	transientPayloadBody struct {
		TransientPayload json.RawMessage `json:"transient_payload" form:"transient_payload"`
	}
)

func NewVerifier(r verifierDependencies) *Verifier {
	return &Verifier{r: r}
}

func (e *Verifier) ExecutePostRegistrationPostPersistHook(_ http.ResponseWriter, r *http.Request, f *registration.Flow, s *session.Session) error {
	return e.do(r, s.Identity, f)
}

func (e *Verifier) ExecuteSettingsPostPersistHook(w http.ResponseWriter, r *http.Request, a *settings.Flow, i *identity.Identity) error {
	return e.do(r, i, a)
}

func (e *Verifier) do(r *http.Request, i *identity.Identity, f flow.Flow) error {
	// This is called after the identity has been created so we can safely assume that all addresses are available
	// already.

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(verificationMethodSchema)
	if err != nil {
		return err
	}

	var body transientPayloadBody
	if err := e.dx.Decode(r, &body, compiler); err != nil {
		return err
	}

	strategy, err := e.r.GetActiveVerificationStrategy(r.Context())
	if err != nil {
		return err
	}

	for k := range i.VerifiableAddresses {
		address := &i.VerifiableAddresses[k]
		if address.Status != identity.VerifiableAddressStatusPending {
			continue
		}
		verificationFlow, err := verification.NewPostHookFlow(e.r.Config(),
			e.r.Config().SelfServiceFlowVerificationRequestLifespan(r.Context()),
			e.r.GenerateCSRFToken(r), r, strategy, f)
		if err != nil {
			return err
		}

		verificationFlow.State = verification.StateSent

		if err := e.r.VerificationFlowPersister().CreateVerificationFlow(r.Context(), verificationFlow); err != nil {
			return err
		}

		switch address.Via {
		case identity.AddressTypeEmail:
			if err := strategy.SendVerificationEmail(r.Context(), verificationFlow, i, address); err != nil {
				return err
			}
		case identity.AddressTypePhone:
			if err := e.r.CodeAuthenticationService().SendCode(r.Context(), verificationFlow, address.Value, body.TransientPayload); err != nil {
				return err
			}
			address.Status = identity.VerifiableAddressStatusSent
			if err := e.r.PrivilegedIdentityPool().UpdateVerifiableAddress(r.Context(), address); err != nil {
				return err
			}
		default:
			return errors.New("Unexpected via type")
		}

	}
	return nil
}
