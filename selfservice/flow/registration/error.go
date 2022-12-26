// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package registration

import (
	"net/http"
	"path"
	"strconv"

	"github.com/ory/kratos/ui/node"

	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/text"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/x"
)

var (
	ErrHookAbortFlow        = errors.New("aborted registration hook execution")
	ErrAlreadyLoggedIn      = herodot.ErrBadRequest.WithID(text.ErrIDAlreadyLoggedIn).WithError("you are already logged in").WithReason("A valid session was detected and thus registration is not possible.")
	ErrRegistrationDisabled = herodot.ErrBadRequest.WithID(text.ErrIDSelfServiceFlowDisabled).WithError("registration flow disabled").WithReason("Registration is not allowed because it was disabled.")
)

type (
	errorHandlerDependencies interface {
		errorx.ManagementProvider
		x.WriterProvider
		x.LoggingProvider
		config.Provider

		FlowPersistenceProvider
		HandlerProvider
	}

	ErrorHandlerProvider interface{ RegistrationFlowErrorHandler() *ErrorHandler }

	ErrorHandler struct {
		d errorHandlerDependencies
	}
)

func NewErrorHandler(d errorHandlerDependencies) *ErrorHandler {
	return &ErrorHandler{d: d}
}

func (s *ErrorHandler) PrepareReplacementForExpiredFlow(w http.ResponseWriter, r *http.Request, f *Flow, err error) (*flow.ExpiredError, error) {
	e := new(flow.ExpiredError)
	if !errors.As(err, &e) {
		return nil, nil
	}
	// create new flow because the old one is not valid
	a, err := s.d.RegistrationHandler().FromOldFlow(w, r, *f)
	if err != nil {
		return nil, err
	}

	a.UI.Messages.Add(text.NewErrorValidationRegistrationFlowExpired(e.ExpiredAt))
	if err := s.d.RegistrationFlowPersister().UpdateRegistrationFlow(r.Context(), a); err != nil {
		return nil, err
	}

	return e.WithFlow(a), nil
}
func (s *ErrorHandler) WriteFlowError(
	w http.ResponseWriter,
	r *http.Request,
	f *Flow,
	group node.UiNodeGroup,
	err error,
) {
	s.d.Audit().
		WithError(err).
		WithRequest(r).
		WithField("registration_flow", f).
		Info("Encountered self-service flow error.")

	if f == nil {
		s.forward(w, r, nil, err)
		return
	}

	if expired, innerErr := s.PrepareReplacementForExpiredFlow(w, r, f, err); innerErr != nil {
		s.forward(w, r, f, innerErr)
		return
	} else if expired != nil {
		if f.Type == flow.TypeAPI || x.IsJSONRequest(r) {
			s.d.Writer().WriteError(w, r, expired)
		} else {
			http.Redirect(w, r, expired.GetFlow().AppendTo(s.d.Config().SelfServiceFlowRegistrationUI(r.Context())).String(), http.StatusSeeOther)
		}
		return
	}

	f.UI.ResetMessages()
	if innerErr := f.UI.ParseError(group, err); innerErr != nil {
		s.forward(w, r, f, innerErr)
		return
	}

	ds, innerErr := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
	if innerErr != nil {
		s.forward(w, r, f, innerErr)
		return
	}

	if innerErr := SortNodes(r.Context(), f.UI.Nodes, ds.String()); innerErr != nil {
		s.forward(w, r, f, innerErr)
		return
	}

	if innerErr := s.d.RegistrationFlowPersister().UpdateRegistrationFlow(r.Context(), f); innerErr != nil {
		s.forward(w, r, f, innerErr)
		return
	}

	if f.Type == flow.TypeBrowser && !x.IsJSONRequest(r) {
		isWebView, innerErr := flow.IsWebViewFlow(r.Context(), s.d.Config(), f)
		if innerErr != nil {
			s.forward(w, r, f, innerErr)
			return
		}

		var redirectLocation = ""
		if isWebView {
			c := s.d.Config()
			returnTo, innerErr := x.SecureRedirectTo(r, c.SelfServiceBrowserDefaultReturnTo(r.Context()),
				x.SecureRedirectUseSourceURL(f.RequestURL),
				x.SecureRedirectAllowURLs(c.SelfServiceBrowserAllowedReturnToDomains(r.Context())),
				x.SecureRedirectAllowSelfServiceURLs(c.SelfPublicURL(r.Context())),
				x.SecureRedirectOverrideDefaultReturnTo(s.d.Config().SelfServiceFlowLoginReturnTo(r.Context(), f.Active.String())),
			)
			if innerErr != nil {
				s.forward(w, r, f, innerErr)
				return
			}

			query := returnTo.Query()

			if len(f.UI.Messages) > 0 {
				query.Set("code", strconv.Itoa(int(f.UI.Messages[0].ID)))
				query.Set("message", f.UI.Messages[0].Text)
				returnTo.RawQuery = query.Encode()
			}
			returnTo.Path = path.Join(returnTo.Path, "error")
			redirectLocation = returnTo.String()

		} else {
			redirectLocation = f.AppendTo(s.d.Config().SelfServiceFlowRegistrationUI(r.Context())).String()
		}
		http.Redirect(w, r, redirectLocation, http.StatusFound)
		return
	}

	updatedFlow, innerErr := s.d.RegistrationFlowPersister().GetRegistrationFlow(r.Context(), f.ID)
	if innerErr != nil {
		s.forward(w, r, updatedFlow, innerErr)
	}

	s.d.Writer().WriteCode(w, r, x.RecoverStatusCode(err, http.StatusBadRequest), updatedFlow)
}

func (s *ErrorHandler) forward(w http.ResponseWriter, r *http.Request, rr *Flow, err error) {
	if rr == nil {
		if x.IsJSONRequest(r) {
			s.d.Writer().WriteError(w, r, err)
			return
		}
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		return
	}

	if rr.Type == flow.TypeAPI {
		s.d.Writer().WriteErrorCode(w, r, x.RecoverStatusCode(err, http.StatusBadRequest), err)
	} else {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
	}
}
