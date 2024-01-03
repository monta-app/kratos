// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"context"
	"encoding/json"
	"github.com/ory/jsonschema/v3"
	"github.com/ory/x/randx"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlxx"
	"github.com/ory/x/urlx"
)

func (s *Strategy) VerificationStrategyID() string {
	return verification.StrategyVerificationCodeName
}

func (s *Strategy) RegisterPublicVerificationRoutes(public *x.RouterPublic) {
}

func (s *Strategy) RegisterAdminVerificationRoutes(admin *x.RouterAdmin) {
}

func (s *Strategy) PopulateVerificationMethod(r *http.Request, f *verification.Flow) error {
	f.UI.SetCSRF(s.deps.GenerateCSRFToken(r))
	f.UI.GetNodes().Upsert(
		node.NewInputField("email", nil, node.CodeGroup, node.InputAttributeTypeEmail, node.WithRequiredInputAttribute).
			WithMetaLabel(text.NewInfoNodeInputEmail()),
	)
	f.UI.GetNodes().Upsert(
		node.NewInputField("phone", nil, node.CodeGroup, node.InputAttributeTypeTel, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeInputPhone()),
	)
	f.UI.GetNodes().Append(
		node.NewInputField("method", s.VerificationStrategyID(), node.CodeGroup, node.InputAttributeTypeSubmit).
			WithMetaLabel(text.NewInfoNodeLabelSubmit()),
	)
	return nil
}

func (s *Strategy) decodeVerification(r *http.Request) (*updateVerificationFlowWithCodeMethodBody, error) {
	var body updateVerificationFlowWithCodeMethodBody

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(verificationMethodSchema)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := s.dx.Decode(r, &body, compiler,
		decoderx.HTTPDecoderUseQueryAndBody(),
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderAllowedMethods("POST", "GET"),
		decoderx.HTTPDecoderSetValidatePayloads(true),
		decoderx.HTTPDecoderJSONFollowsFormFormat(),
	); err != nil {
		return nil, errors.WithStack(err)
	}

	return &body, nil
}

// handleVerificationError is a convenience function for handling all types of errors that may occur (e.g. validation error).
func (s *Strategy) handleVerificationError(w http.ResponseWriter, r *http.Request, f *verification.Flow, body *updateVerificationFlowWithCodeMethodBody, err error) error {
	if f != nil {
		f.UI.SetCSRF(s.deps.GenerateCSRFToken(r))

		f.UI.GetNodes().Upsert(
			node.NewInputField("email", body.Email, node.CodeGroup, node.InputAttributeTypeEmail, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeInputEmail()),
		)
		f.UI.GetNodes().Upsert(
			node.NewInputField("phone", body.Phone, node.CodeGroup, node.InputAttributeTypeTel, node.WithRequiredInputAttribute).WithMetaLabel(text.NewInfoNodeInputPhone()),
		)
	}

	return err
}

// swagger:model updateVerificationFlowWithCodeMethodBody
type updateVerificationFlowWithCodeMethodBody struct {
	// Email to Verify
	//
	// Needs to be set when initiating the flow. If the email is a registered
	// verification email, a verification link will be sent. If the email is not known,
	// a email with details on what happened will be sent instead.
	//
	// format: email
	Email string `form:"email" json:"email"`

	// Phone to Verify
	// format: tel
	Phone string `form:"phone" json:"phone"`

	// Sending the anti-csrf token is only required for browser login flows.
	CSRFToken string `form:"csrf_token" json:"csrf_token"`

	// Method is the verification method
	//
	// enum:
	// - link
	// - code
	Method string `json:"method"`

	// The id of the flow
	Flow string `json:"flow" form:"flow"`

	// The verification code
	Code string `json:"code" form:"code"`

	TransientPayload json.RawMessage `json:"transient_payload" form:"transient_payload"`

	// A branding to be applied to the email body
	Branding string `json:"branding" form:"branding"`
}

// getMethod returns the method of this submission or "" if no method could be found
func (body *updateVerificationFlowWithCodeMethodBody) getMethod() string {
	if body.Method != "" {
		return body.Method
	}
	if body.Code != "" {
		return verification.StrategyVerificationCodeName
	}

	return ""
}

func (s *Strategy) Verify(w http.ResponseWriter, r *http.Request, f *verification.Flow) (err error) {
	body, err := s.decodeVerification(r)
	if err != nil {
		if e := new(jsonschema.ValidationError); errors.As(err, &e) {
			if e.InstancePtr == "#/method" {
				return errors.WithStack(flow.ErrStrategyNotResponsible)
			}
		}
		return s.handleVerificationError(w, r, nil, body, err)
	}

	if len(body.Method) > 0 && body.Method != s.VerificationStrategyID() {
		return errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if err := flow.MethodEnabledAndAllowed(r.Context(), s.VerificationStrategyID(), body.getMethod(), s.deps); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	if err := f.Valid(); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	switch f.State {
	case verification.StateChooseMethod:
		fallthrough
	case verification.StateSent:
		return s.verificationHandleFormSubmission(w, r, f, body)
	case verification.StatePassedChallenge:
		return s.retryVerificationFlowWithMessage(w, r, f.Type, text.NewErrorValidationVerificationRetrySuccess())
	default:
		return s.retryVerificationFlowWithMessage(w, r, f.Type, text.NewErrorValidationVerificationStateFailure())
	}
}

func (s *Strategy) createVerificationCodeForm(action string, code *string, address *string, via *identity.VerifiableAddressType) *container.Container {
	// re-initialize the UI with a "clean" new state
	c := &container.Container{
		Method: "POST",
		Action: action,
	}

	c.Nodes.Append(
		node.
			NewInputField("code", code, node.CodeGroup, node.InputAttributeTypeText, node.WithRequiredInputAttribute).
			WithMetaLabel(text.NewInfoNodeLabelVerifyOTP()),
	)
	c.Nodes.Append(
		node.NewInputField("method", s.VerificationNodeGroup(), node.CodeGroup, node.InputAttributeTypeHidden),
	)

	c.Nodes.Append(
		node.NewInputField("method", s.VerificationStrategyID(), node.CodeGroup, node.InputAttributeTypeSubmit).
			WithMetaLabel(text.NewInfoNodeLabelSubmit()),
	)

	if address != nil && via != nil {
		c.Nodes.Append(
			node.NewInputField(string(*via), address, node.CodeGroup, node.InputAttributeTypeSubmit).
				WithMetaLabel(text.NewInfoNodeResendOTP()),
		)
	}

	return c
}

func (s *Strategy) handleLinkClick(w http.ResponseWriter, r *http.Request, f *verification.Flow, code string) error {
	f.UI = s.createVerificationCodeForm(flow.AppendFlowTo(urlx.AppendPaths(s.deps.Config().SelfPublicURL(r.Context()), verification.RouteSubmitFlow), f.ID).String(), &code, nil, nil)

	// In the verification flow, we can't enforce CSRF if the flow is opened from an email, so we initialize the CSRF
	// token here, so all subsequent interactions are protected
	csrfToken := s.deps.CSRFHandler().RegenerateToken(w, r)
	f.UI.SetCSRF(csrfToken)
	f.CSRFToken = csrfToken

	if err := s.deps.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
		return err
	}

	// we always redirect to the browser UI here to allow API flows to complete aswell
	// TODO: In the future, we might want to redirect to a custom URI scheme here, to allow to open an app on the device of
	// the user to handle the flow directly.
	http.Redirect(w, r, f.AppendTo(s.deps.Config().SelfServiceFlowVerificationUI(r.Context())).String(), http.StatusSeeOther)

	return errors.WithStack(flow.ErrCompletedByStrategy)
}

func (s *Strategy) verificationHandleFormSubmission(w http.ResponseWriter, r *http.Request, f *verification.Flow, body *updateVerificationFlowWithCodeMethodBody) error {
	if len(body.Code) > 0 {
		if r.Method == http.MethodGet {
			// Special case: in the code strategy we send out links as well, that contain the code
			return s.handleLinkClick(w, r, f, body.Code)
		}

		// If not GET: try to use the submitted code
		return s.verificationUseCode(w, r, body, f)
	} else if len(body.Email) == 0 && len(body.Phone) == 0 {
		// If no code and no email or phone was provided, fail with a validation error
		return s.handleVerificationError(w, r, f, body, schema.NewRequiredError("#/email", "email"))
	}

	if err := flow.EnsureCSRF(s.deps, r, f.Type, s.deps.Config().DisableAPIFlowEnforcement(r.Context()), s.deps.GenerateCSRFToken, body.CSRFToken); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	via := identity.VerifiableAddressTypeEmail
	to := body.Email
	if len(body.Phone) != 0 {
		via = identity.VerifiableAddressTypePhone
		to = body.Phone
	}

	if err := s.deps.VerificationCodePersister().DeleteVerificationCodesOfFlow(r.Context(), f.ID); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	if err := s.deps.CodeSender().SendVerificationCode(r.Context(), f, via, to, body.TransientPayload, body.Branding); err != nil {
		if !errors.Is(err, ErrUnknownAddress) {
			return s.handleVerificationError(w, r, f, body, err)
		}
		// Continue execution
	}

	f.UI = s.createVerificationCodeForm(flow.AppendFlowTo(urlx.AppendPaths(s.deps.Config().SelfPublicURL(r.Context()), verification.RouteSubmitFlow), f.ID).String(), nil, &to, &via)
	if via == identity.VerifiableAddressTypeEmail {
		f.UI.Messages.Set(text.NewVerificationEmailWithCodeSent())
	} else {
		f.UI.Messages.Set(text.NewVerificationPhoneSent())
	}

	f.State = verification.StateSent
	f.UI.SetCSRF(s.deps.GenerateCSRFToken(r))

	if err := s.deps.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
		return s.handleVerificationError(w, r, f, body, err)
	}

	return nil
}

func (s *Strategy) verificationUseCode(w http.ResponseWriter, r *http.Request, body *updateVerificationFlowWithCodeMethodBody, f *verification.Flow) error {
	code, err := s.deps.VerificationCodePersister().UseVerificationCode(r.Context(), f.ID, body.Code)
	if errors.Is(err, ErrCodeNotFound) {
		f.UI.Messages.Clear()
		f.UI.Messages.Add(text.NewErrorValidationVerificationCodeInvalidOrAlreadyUsed())
		if err := s.deps.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
			return s.retryVerificationFlowWithError(w, r, f.Type, err)
		}

		// No error
		return nil
	} else if err != nil {
		return s.retryVerificationFlowWithError(w, r, f.Type, err)
	}

	if err := code.Validate(); err != nil {
		return s.retryVerificationFlowWithError(w, r, f.Type, err)
	}

	i, err := s.deps.IdentityPool().GetIdentity(r.Context(), code.VerifiableAddress.IdentityID)
	if err != nil {
		return s.retryVerificationFlowWithError(w, r, f.Type, err)
	}

	if err := s.deps.VerificationExecutor().PostVerificationHook(w, r, f, i); err != nil {
		return s.retryVerificationFlowWithError(w, r, f.Type, err)
	}

	address := code.VerifiableAddress
	address.Verified = true
	verifiedAt := sqlxx.NullTime(time.Now().UTC())
	address.VerifiedAt = &verifiedAt
	address.Status = identity.VerifiableAddressStatusCompleted
	if err := s.deps.PrivilegedIdentityPool().UpdateVerifiableAddress(r.Context(), address); err != nil {
		return s.retryVerificationFlowWithError(w, r, f.Type, err)
	}

	returnTo := s.getRedirectURL(r.Context(), f)

	f.UI = &container.Container{
		Method: "GET",
		Action: returnTo.String(),
	}

	f.State = verification.StatePassedChallenge
	// See https://github.com/ory/kratos/issues/1547
	f.SetCSRFToken(flow.GetCSRFToken(s.deps, w, r, f.Type))
	if code.VerifiableAddress.Via == identity.VerifiableAddressTypeEmail {
		f.UI.Messages.Set(text.NewInfoSelfServiceVerificationSuccessful())
	} else {
		f.UI.Messages.Set(text.NewInfoSelfServicePhoneVerificationSuccessful())
	}
	f.UI.
		Nodes.
		Append(node.NewAnchorField("continue", returnTo.String(), node.CodeGroup, text.NewInfoNodeLabelContinue()).
			WithMetaLabel(text.NewInfoNodeLabelContinue()))

	if err := s.deps.VerificationFlowPersister().UpdateVerificationFlow(r.Context(), f); err != nil {
		return s.retryVerificationFlowWithError(w, r, flow.TypeBrowser, err)
	}
	return nil
}

func (s *Strategy) getRedirectURL(ctx context.Context, f *verification.Flow) *url.URL {
	defaultRedirectURL := s.deps.Config().SelfServiceBrowserDefaultReturnTo(ctx)

	verificationRequestURL, err := urlx.Parse(f.GetRequestURL())
	if err != nil {
		// Initial flow request url is not a valid URL, use the default
		return defaultRedirectURL
	}

	verificationRequest := http.Request{URL: verificationRequestURL}

	returnTo, err := x.SecureRedirectTo(&verificationRequest, defaultRedirectURL,
		x.SecureRedirectAllowSelfServiceURLs(s.deps.Config().SelfPublicURL(ctx)),
		x.SecureRedirectAllowURLs(s.deps.Config().SelfServiceBrowserAllowedReturnToDomains(ctx)),
	)
	if err != nil {
		// Initial flow request url is not allowd, use the default
		return defaultRedirectURL
	}
	return returnTo
}

func (s *Strategy) retryVerificationFlowWithMessage(w http.ResponseWriter, r *http.Request, ft flow.Type, message *text.Message) error {
	s.deps.
		Logger().
		WithRequest(r).
		WithField("message", message).
		Debug("A verification flow is being retried because a validation error occurred.")

	f, err := verification.NewFlow(s.deps.Config(),
		s.deps.Config().SelfServiceFlowVerificationRequestLifespan(r.Context()), s.deps.CSRFHandler().RegenerateToken(w, r), r, s, ft)
	if err != nil {
		return s.handleVerificationError(w, r, f, nil, err)
	}

	f.UI.Messages.Add(message)

	if err := s.deps.VerificationFlowPersister().CreateVerificationFlow(r.Context(), f); err != nil {
		return s.handleVerificationError(w, r, f, nil, err)
	}

	if x.IsJSONRequest(r) {
		s.deps.Writer().WriteError(w, r, flow.NewFlowReplacedError(text.NewErrorSystemGeneric("An error occured, please use the new flow.")).WithFlow(f))
	} else {
		http.Redirect(w, r, f.AppendTo(s.deps.Config().SelfServiceFlowVerificationUI(r.Context())).String(), http.StatusSeeOther)
	}

	return errors.WithStack(flow.ErrCompletedByStrategy)
}

func (s *Strategy) retryVerificationFlowWithError(w http.ResponseWriter, r *http.Request, ft flow.Type, verErr error) error {
	s.deps.
		Logger().
		WithRequest(r).
		WithError(verErr).
		Debug("A verification flow is being retried because an error occurred.")

	f, err := verification.NewFlow(s.deps.Config(),
		s.deps.Config().SelfServiceFlowVerificationRequestLifespan(r.Context()), s.deps.CSRFHandler().RegenerateToken(w, r), r, s, ft)
	if err != nil {
		return s.handleVerificationError(w, r, f, nil, err)
	}

	var toReturn error

	if expired := new(flow.ExpiredError); errors.As(verErr, &expired) {
		f.UI.Messages.Add(text.NewErrorValidationVerificationFlowExpired(expired.ExpiredAt))
		toReturn = expired.WithFlow(f)
	} else if err := f.UI.ParseError(node.LinkGroup, verErr); err != nil {
		return err
	}

	if err := s.deps.VerificationFlowPersister().CreateVerificationFlow(r.Context(), f); err != nil {
		return s.handleVerificationError(w, r, f, nil, err)
	}

	if x.IsJSONRequest(r) {
		if toReturn == nil {
			toReturn = flow.NewFlowReplacedError(text.NewErrorSystemGeneric("An error occured, please retry the flow.")).
				WithFlow(f)
		}
		s.deps.Writer().WriteError(w, r, toReturn)
	} else {
		http.Redirect(w, r, f.AppendTo(s.deps.Config().SelfServiceFlowVerificationUI(r.Context())).String(), http.StatusSeeOther)
	}

	return errors.WithStack(flow.ErrCompletedByStrategy)
}

func (s *Strategy) SendVerification(ctx context.Context, f *verification.Flow, i *identity.Identity, a *identity.VerifiableAddress,
	transientPayload json.RawMessage, branding string) (err error) {

	rawCode := GenerateCode()
	//TODO delete after PS-187
	if a.Via == identity.VerifiableAddressTypePhone {
		rawCode = randx.MustString(4, randx.Numeric)
	}

	code, err := s.deps.VerificationCodePersister().CreateVerificationCode(ctx, &CreateVerificationCodeParams{
		RawCode:           rawCode,
		ExpiresIn:         s.deps.Config().SelfServiceCodeMethodLifespan(ctx),
		VerifiableAddress: a,
		FlowID:            f.ID,
	})

	if err != nil {
		return err
	}

	return s.deps.CodeSender().SendVerificationCodeTo(ctx, f, i, rawCode, code, transientPayload, branding)
}
