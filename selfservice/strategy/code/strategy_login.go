// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/sqlxx"
)

func (s *Strategy) handleLoginError(w http.ResponseWriter, r *http.Request, f *login.Flow,
	payload *submitSelfServiceLoginFlowWithCodeMethod, err error) error {
	if f != nil {
		f.UI.Nodes.ResetNodes("code")
		f.UI.Nodes.SetValueAttribute("identifier", payload.Identifier)
		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(s.deps.GenerateCSRFToken(r))
		}
	}

	return err
}

func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, ss *session.Session) (*identity.Identity, error) {
	if err := flow.MethodEnabledAndAllowedFromRequest(r, s.ID().String(), s.deps); err != nil {
		return nil, err
	}

	var p submitSelfServiceLoginFlowWithCodeMethod
	if err := s.dx.Decode(r, &p,
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.MustHTTPRawJSONSchemaCompiler(loginSchema),
		decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
		return nil, s.handleLoginError(w, r, f, &p, err)
	}

	if len(p.Code) == 0 {
		if len(p.Identifier) == 0 {
			return nil, s.handleLoginError(w, r, f, &p, schema.NewRequiredError("#/identifier", "identifier"))
		}

		i, err := s.findByCredentialsIdentifier(r.Context(), p.Identifier)
		if err != nil {
			return nil, s.handleLoginError(w, r, f, &p, err)
		}
		if i != nil {
			err := s.deps.CodeAuthenticationService().SendCode(r.Context(), f, p.Identifier, p.TransientPayload)
			if err != nil {
				return nil, s.handleLoginError(w, r, f, &p, err)
			}
		}
		f.UI.Nodes.Upsert(node.NewInputField("code", "", node.CodeGroup, node.InputAttributeTypeText))
		f.UI.Nodes.Remove("identifier")
		return nil, s.handleLoginError(w, r, f, &p, NewCodeSentError())
	} else {
		code, err := s.deps.CodeAuthenticationService().VerifyCode(r.Context(), f, p.Code)
		if err != nil {
			return nil, s.handleLoginError(w, r, f, &p, err)
		}
		i, err := s.findByCredentialsIdentifier(r.Context(), code.Identifier)
		if err != nil {
			return nil, s.handleLoginError(w, r, f, &p, err)
		}
		if i == nil {
			return nil, s.handleLoginError(w, r, f, &p, NewInvalidCodeError())
		}

		if err := s.updateVerifiableAddress(r.Context(), code.Identifier, i); err != nil {
			return nil, s.handleLoginError(w, r, f, &p, err)
		}

		return i, nil
	}
}

func (s *Strategy) updateVerifiableAddress(context context.Context, identifier string, i *identity.Identity) error {
	var address *identity.VerifiableAddress = nil
	for index, a := range i.VerifiableAddresses {
		if a.Value == identifier && a.Via == identity.VerifiableAddressTypePhone {
			address = &i.VerifiableAddresses[index]
			break
		}
	}

	if address == nil {
		return errors.New("verifiable address not found for identity")
	}

	address.Verified = true
	verifiedAt := sqlxx.NullTime(time.Now().UTC())
	address.VerifiedAt = &verifiedAt
	address.Status = identity.VerifiableAddressStatusCompleted
	if err := s.deps.PrivilegedIdentityPool().UpdateVerifiableAddress(context, address); err != nil {
		return err
	}

	return nil
}

func (s *Strategy) findByCredentialsIdentifier(context context.Context, identifier string) (*identity.Identity, error) {
	i, _, err := s.deps.PrivilegedIdentityPool().FindByCredentialsIdentifier(context, s.ID(), identifier)
	if errors.Is(errors.Cause(err), sqlcon.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return i, nil
}

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, l *login.Flow) error {
	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	// This block adds the identifier (i.e. phone) to the method when the request is forced - as a hint for the user.
	var identifier string
	if !l.IsForced() {
		// do nothing
	} else if sess, err := s.deps.SessionManager().FetchFromRequest(r.Context(), r); err != nil {
		// do nothing
	} else if id, err := s.deps.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), sess.IdentityID); err != nil {
		// do nothing
	} else if creds, ok := id.GetCredentials(s.ID()); !ok {
		// do nothing
	} else if len(creds.Identifiers) == 0 {
		// do nothing
	} else {
		identifier = creds.Identifiers[0]
	}

	l.UI.SetNode(node.NewInputField("identifier", identifier, node.DefaultGroup,
		node.InputAttributeTypeText, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeLabelID()))

	if l.Type != flow.TypeBrowser {
		return nil
	}

	return s.populateMethod(r, l.UI, text.NewInfoLogin())
}
