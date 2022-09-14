package code

import (
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlxx"
)

func (s *Strategy) VerificationStrategyID() string {
	return verification.StrategyVerificationCodeName
}

func (s *Strategy) VerificationNodeGroup() node.UiNodeGroup {
	return node.CodeGroup
}

func (s *Strategy) PopulateVerificationMethod(r *http.Request, f *verification.Flow) error {
	f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	f.UI.GetNodes().Upsert(
		node.NewInputField("phone", nil, node.CodeGroup, node.InputAttributeTypePhone, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeInputPhone()),
	)
	f.UI.GetNodes().Append(node.NewInputField("method", s.VerificationStrategyID(), node.CodeGroup, node.InputAttributeTypeSubmit).WithMetaLabel(text.NewInfoNodeLabelSubmit()))
	return nil
}

func (s *Strategy) Verify(w http.ResponseWriter, r *http.Request, f *verification.Flow) (err error) {
	body, err := s.decodeVerification(r)
	if err != nil {
		return s.handleVerificationError(w, r, nil, body, err)
	}

	if len(body.Code) > 0 {
		if err := flow.MethodEnabledAndAllowed(r.Context(), s.VerificationStrategyID(), s.VerificationStrategyID(), s.d); err != nil {
			return s.handleVerificationError(w, r, nil, body, err)
		}

		return s.verificationUseCode(w, r, f, body)
	}

	if err := flow.MethodEnabledAndAllowed(r.Context(), s.VerificationStrategyID(), body.Method, s.d); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	if err := f.Valid(); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	switch f.State {
	case verification.StateChooseMethod:
		fallthrough
	case verification.StateSent:
		// Do nothing (continue with execution after this switch statement)
		return s.verificationHandleFormSubmission(w, r, f)
	case verification.StatePassedChallenge:
		return s.retryWithError(w, r, f.Type, errors.New("verification flow is not active"))
	default:
		return s.retryWithError(w, r, f.Type, errors.New("unexpected flow state"))
	}
}

type verificationSubmitPayload struct {
	Method    string `json:"method" form:"method"`
	Code      string `json:"code" form:"code"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
	Flow      string `json:"flow" form:"flow"`
	Phone     string `json:"phone" form:"phone"`
}

func (s *Strategy) decodeVerification(r *http.Request) (*verificationSubmitPayload, error) {
	var body verificationSubmitPayload

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(verificationSchema)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := s.hd.Decode(r, &body, compiler,
		decoderx.HTTPDecoderUseQueryAndBody(),
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderAllowedMethods("POST"),
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.HTTPDecoderJSONFollowsFormFormat(),
	); err != nil {
		return nil, errors.WithStack(err)
	}

	return &body, nil
}

// handleVerificationError is a convenience function for handling all types of errors that may occur (e.g. validation error).
func (s *Strategy) handleVerificationError(w http.ResponseWriter, r *http.Request, f *verification.Flow, body *verificationSubmitPayload, err error) error {
	if f != nil {
		f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		f.UI.GetNodes().Upsert(
			node.NewInputField("email", body.Phone, node.CodeGroup, node.InputAttributeTypePhone, node.WithRequiredInputAttribute),
		)
	}

	return err
}

func (s *Strategy) verificationUseCode(w http.ResponseWriter, r *http.Request, f *verification.Flow,
	body *verificationSubmitPayload) error {

	code, err := s.d.CodeAuthenticationService().VerifyCode(r.Context(), f, body.Code)
	if err != nil {
		return s.retryWithError(w, r, f.Type, err)
	}

	f.UI.Messages.Clear()
	f.State = verification.StatePassedChallenge
	f.UI.Messages.Set(text.NewInfoSelfServicePhoneVerificationSuccessful())
	if err := s.d.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
		return s.retryWithError(w, r, f.Type, err)
	}

	i, err := s.findByCredentialsIdentifier(r.Context(), code.Identifier)
	if err != nil {
		return s.retryWithError(w, r, f.Type, err)
	}

	if err := s.d.VerificationExecutor().PostVerificationHook(w, r, f, i); err != nil {
		return s.retryWithError(w, r, f.Type, err)
	}

	var address *identity.VerifiableAddress = nil
	for _, a := range i.VerifiableAddresses {
		if code.Identifier == a.Value {
			address = &a
			break
		}
	}
	if address == nil {
		return s.retryWithError(w, r, f.Type, errors.New("address ot found"))
	}
	address.Verified = true
	verifiedAt := sqlxx.NullTime(time.Now().UTC())
	address.VerifiedAt = &verifiedAt
	address.Status = identity.VerifiableAddressStatusCompleted
	if err := s.d.PrivilegedIdentityPool().UpdateVerifiableAddress(r.Context(), address); err != nil {
		return s.retryWithError(w, r, f.Type, err)
	}

	return nil
}

func (s *Strategy) verificationHandleFormSubmission(w http.ResponseWriter, r *http.Request, f *verification.Flow) error {
	var body = new(verificationSubmitPayload)
	body, err := s.decodeVerification(r)
	if err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	if len(body.Phone) == 0 {
		return s.handleVerificationError(w, r, f, body, schema.NewRequiredError("#/identifier", "identifier"))
	}

	if err := flow.EnsureCSRF(s.d, r, f.Type, s.d.Config().DisableAPIFlowEnforcement(r.Context()), s.d.GenerateCSRFToken, body.CSRFToken); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	if err := s.d.CodeAuthenticationService().SendCode(r.Context(), f, body.Phone); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	f.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	f.UI.GetNodes().Upsert(
		node.NewInputField("phone", body.Phone, node.CodeGroup, node.InputAttributeTypePhone, node.WithRequiredInputAttribute),
	)

	f.Active = sqlxx.NullString(s.VerificationNodeGroup())
	f.State = verification.StateSent
	f.UI.Messages.Set(text.NewVerificationPhoneSent())
	if err := s.d.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	return nil
}

func (s *Strategy) retryWithError(w http.ResponseWriter, r *http.Request, ft flow.Type, verErr error) error {
	return verErr
}
