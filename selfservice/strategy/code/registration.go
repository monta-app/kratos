package code

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/sjson"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlxx"
)

// SubmitSelfServiceRegistrationFlowWithCodeMethodBody is used to decode the registration form payload
// when using the code method.
//
// swagger:model submitSelfServiceRegistrationFlowWithCodeMethodBody
type SubmitSelfServiceRegistrationFlowWithCodeMethodBody struct {
	// Code from the code
	//
	// required: false
	Code string `json:"code"`

	// The identity's traits
	//
	// required: true
	Traits json.RawMessage `json:"traits"`

	// The CSRF Token
	CSRFToken string `json:"csrf_token"`

	// Method to use
	//
	// This field must be set to `code` when using the code method.
	//
	// required: true
	Method string `json:"method"`
}

func (s *Strategy) RegisterRegistrationRoutes(_ *x.RouterPublic) {
}

func (s *Strategy) handleRegistrationError(_ http.ResponseWriter, r *http.Request, f *registration.Flow,
	p *SubmitSelfServiceRegistrationFlowWithCodeMethodBody, err error) error {
	if f != nil {
		if p != nil {
			for _, n := range container.NewFromJSON("", node.CodeGroup, p.Traits, "traits").Nodes {
				// we only set the value and not the whole field because we want to keep types from the initial form generation
				f.UI.Nodes.SetValueAttribute(n.ID(), n.Attributes.GetValue())
			}
		}

		if f.Type == flow.TypeBrowser {
			f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		}
	}

	return err
}

func (s *Strategy) decode(p *SubmitSelfServiceRegistrationFlowWithCodeMethodBody, r *http.Request) error {
	ds, err := s.d.Config(r.Context()).DefaultIdentityTraitsSchemaURL()
	if err != nil {
		return err
	}
	raw, err := sjson.SetBytes(registrationSchema, "properties.traits.$ref", ds.String()+"#/properties/traits")
	if err != nil {
		return errors.WithStack(err)
	}

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(raw)
	if err != nil {
		return errors.WithStack(err)
	}

	return s.hd.Decode(r, p, compiler, decoderx.HTTPDecoderSetValidatePayloads(true), decoderx.HTTPDecoderJSONFollowsFormFormat())
}

func (s *Strategy) Register(w http.ResponseWriter, r *http.Request, f *registration.Flow, i *identity.Identity) error {
	if err := flow.MethodEnabledAndAllowedFromRequest(r, s.ID().String(), s.d); err != nil {
		return err
	}

	var p SubmitSelfServiceRegistrationFlowWithCodeMethodBody
	if err := s.decode(&p, r); err != nil {
		return s.handleRegistrationError(w, r, f, &p, err)
	}

	if err := flow.EnsureCSRF(s.d, r, f.Type, s.d.Config(r.Context()).DisableAPIFlowEnforcement(), s.d.GenerateCSRFToken, p.CSRFToken); err != nil {
		return s.handleRegistrationError(w, r, f, &p, err)
	}

	if len(p.Traits) == 0 {
		p.Traits = json.RawMessage("{}")
	}

	i.Traits = identity.Traits(p.Traits)

	if p.Code == "" {
		if err := s.d.IdentityValidator().Validate(r.Context(), i); err != nil {
			return err
		}
		credentials, found := i.GetCredentials(identity.CredentialsTypeCode)
		if !found {
			return s.handleRegistrationError(w, r, f, &p, fmt.Errorf("credentials not found"))
		}
		if len(credentials.Identifiers) != 1 {
			return s.handleRegistrationError(w, r, f, &p,
				fmt.Errorf("credentials identifiers missing or more than one: %v", credentials.Identifiers))
		}
		err := s.d.CodeAuthenticationService().SendCode(r.Context(), f, credentials.Identifiers[0])
		if err != nil {
			return s.handleRegistrationError(w, r, f, &p, err)
		}
		f.UI.Nodes.Upsert(node.NewInputField("code", "", node.CodeGroup, node.InputAttributeTypeText))
		return s.handleRegistrationError(w, r, f, &p, NewCodeSentError())
	} else {
		code, err := s.d.CodeAuthenticationService().VerifyCode(r.Context(), f, p.Code)
		if err != nil {
			return s.handleRegistrationError(w, r, f, &p, err)
		}
		verifiedAt := sqlxx.NullTime(time.Now().UTC())
		i.VerifiableAddresses = append(i.VerifiableAddresses, identity.VerifiableAddress{
			Value:      code.Identifier,
			Verified:   true,
			VerifiedAt: &verifiedAt,
			Status:     identity.VerifiableAddressStatusCompleted,
			Via:        identity.VerifiableAddressTypePhone,
			IdentityID: i.ID,
		})

		if err := s.d.IdentityValidator().ValidateWithRunner(r.Context(), i,
			NewSchemaExtensionVerificationCode(code.Identifier)); err != nil {
			return err
		}

	}

	return nil
}

func (s *Strategy) PopulateRegistrationMethod(r *http.Request, f *registration.Flow) error {
	if f.Type != flow.TypeBrowser {
		return nil
	}

	return s.populateMethod(r, f.UI, text.NewInfoRegistration())
}
