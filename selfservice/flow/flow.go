// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/text"
	"github.com/ory/x/sqlxx"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/ory/kratos/driver/config"

	"github.com/pkg/errors"

	"github.com/ory/kratos/ui/container"

	"github.com/ory/herodot"
	"github.com/ory/kratos/x"

	"github.com/gofrs/uuid"

	"github.com/ory/x/urlx"
)

const InternalContextDuplicateCredentialsPath = "registration_duplicate_credentials"
const InternalContextLinkCredentialsPath = "link_credentials"

type RegistrationDuplicateCredentials struct {
	CredentialsType   identity.CredentialsType
	CredentialsConfig sqlxx.JSONRawMessage
}

func AppendFlowTo(src *url.URL, id uuid.UUID) *url.URL {
	return urlx.CopyWithQuery(src, url.Values{"flow": {id.String()}})
}

func GetFlowID(r *http.Request) (uuid.UUID, error) {
	rid := x.ParseUUID(r.URL.Query().Get("flow"))
	if rid == uuid.Nil {
		return rid, errors.WithStack(herodot.ErrBadRequest.WithReasonf("The flow query parameter is missing or malformed."))
	}
	return rid, nil
}

type Flow interface {
	GetID() uuid.UUID
	GetType() Type
	GetRequestURL() string
	AppendTo(*url.URL) *url.URL
	GetUI() *container.Container
}

func IsWebViewFlow(ctx context.Context, conf *config.Config, f Flow) (bool, error) {
	if f.GetType() != TypeBrowser {
		return false, nil
	}
	requestURL, err := url.Parse(f.GetRequestURL())
	if err != nil {
		return false, err
	}
	redirectURL := conf.SelfServiceWebViewRedirectURL(ctx)
	if redirectURL == nil {
		return false, nil
	}
	return requestURL.Query().Get("return_to") == redirectURL.String(), nil
}

func GetWebViewRedirectLocation(r *http.Request, f Flow, conf *config.Config, strategy string) (string, error) {
	returnTo, innerErr := x.SecureRedirectTo(r, conf.SelfServiceBrowserDefaultReturnTo(r.Context()),
		x.SecureRedirectUseSourceURL(f.GetRequestURL()),
		x.SecureRedirectAllowURLs(conf.SelfServiceBrowserAllowedReturnToDomains(r.Context())),
		x.SecureRedirectAllowSelfServiceURLs(conf.SelfPublicURL(r.Context())),
		x.SecureRedirectOverrideDefaultReturnTo(conf.SelfServiceFlowLoginReturnTo(r.Context(), strategy)),
	)
	if innerErr != nil {
		return "", innerErr
	}

	query := returnTo.Query()

	var msg *text.Message = nil
	ui := f.GetUI()
	if len(ui.Messages) > 0 {
		msg = &ui.Messages[0]
	} else {
		for _, node := range ui.Nodes {
			if len(node.Messages) > 0 {
				msg = &node.Messages[0]
				break
			}
		}
	}
	if msg != nil {
		query.Set("code", strconv.Itoa(int(msg.ID)))
		query.Set("message", msg.Text)
		query.Set("flow", f.GetID().String()) // webview flow needs this
		returnTo.RawQuery = query.Encode()
	}
	returnTo.Path = path.Join(returnTo.Path, "kerr")
	return returnTo.String(), nil
}
