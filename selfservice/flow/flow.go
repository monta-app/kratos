package flow

import (
	"context"
	"github.com/ory/kratos/driver/config"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/ory/kratos/ui/container"

	"github.com/ory/herodot"
	"github.com/ory/kratos/x"

	"github.com/gofrs/uuid"

	"github.com/ory/x/urlx"
)

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
