// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/ory/kratos/request"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/ory/herodot"

	"github.com/ory/x/urlx"
)

type Configuration struct {
	// ID is the provider's ID
	ID string `json:"id"`

	// Provider is either "generic" for a generic OAuth 2.0 / OpenID Connect Provider or one of:
	// - generic
	// - google
	// - github
	// - github-app
	// - gitlab
	// - microsoft
	// - discord
	// - slack
	// - facebook
	// - vk
	// - yandex
	// - apple
	// - dingtalk
	Provider string `json:"provider"`

	// Label represents an optional label which can be used in the UI generation.
	Label string `json:"label"`

	// ClientID is the application's Client ID.
	ClientID string `json:"client_id"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"client_secret"`

	// IssuerURL is the OpenID Connect Server URL. You can leave this empty if `provider` is not set to `generic`.
	// If set, neither `auth_url` nor `token_url` are required.
	IssuerURL string `json:"issuer_url"`

	// AuthURL is the authorize url, typically something like: https://example.org/oauth2/auth
	// Should only be used when the OAuth2 / OpenID Connect server is not supporting OpenID Connect Discovery and when
	// `provider` is set to `generic`.
	AuthURL string `json:"auth_url"`

	// TokenURL is the token url, typically something like: https://example.org/oauth2/token
	// Should only be used when the OAuth2 / OpenID Connect server is not supporting OpenID Connect Discovery and when
	// `provider` is set to `generic`.
	TokenURL string `json:"token_url"`

	// Tenant is the Azure AD Tenant to use for authentication, and must be set when `provider` is set to `microsoft`.
	// Can be either `common`, `organizations`, `consumers` for a multitenant application or a specific tenant like
	// `8eaef023-2b34-4da1-9baa-8bc8c9d6a490` or `contoso.onmicrosoft.com`.
	Tenant string `json:"microsoft_tenant"`

	// SubjectSource is a flag which controls from which endpoint the subject identifier is taken by microsoft provider.
	// Can be either `userinfo` or `me`.
	// If the value is `uerinfo` then the subject identifier is taken from sub field of uderifo standard endpoint response.
	// If the value is `me` then the `id` field of https://graph.microsoft.com/v1.0/me response is taken as subject.
	// The default is `userinfo`.
	SubjectSource string `json:"subject_source"`

	// TeamId is the Apple Developer Team ID that's needed for the `apple` `provider` to work.
	// It can be found Apple Developer website and combined with `apple_private_key` and `apple_private_key_id`
	// is used to generate `client_secret`
	TeamId string `json:"apple_team_id"`

	// PrivateKeyId is the private Apple key identifier. Keys can be generated via developer.apple.com.
	// This key should be generated with the `Sign In with Apple` option checked.
	// This is needed when `provider` is set to `apple`
	PrivateKeyId string `json:"apple_private_key_id"`

	// PrivateKeyId is the Apple private key identifier that can be downloaded during key generation.
	// This is needed when `provider` is set to `apple`
	PrivateKey string `json:"apple_private_key"`

	// Scope specifies optional requested permissions.
	Scope []string `json:"scope"`

	// Mapper specifies the JSONNet code snippet which uses the OpenID Connect Provider's data (e.g. GitHub or Google
	// profile information) to hydrate the identity's data.
	//
	// It can be either a URL (file://, http(s)://, base64://) or an inline JSONNet code snippet.
	Mapper string `json:"mapper_url"`

	// RequestedClaims string encoded json object that specifies claims and optionally their properties which should be
	// included in the id_token or returned from the UserInfo Endpoint.
	//
	// More information: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
	RequestedClaims json.RawMessage `json:"requested_claims"`

	// List of values to check audience field of ID Token.
	// The audience field of ID Token should be equal to one of the items in this list.
	AllowedAudiences []string `json:"allowed_audiences"`
}

func (p Configuration) Redir(public *url.URL) string {
	return urlx.AppendPaths(public,
		strings.Replace(RouteCallback, ":provider", p.ID, 1),
	).String()
}

type ConfigurationCollection struct {
	BaseRedirectURI        string          `json:"base_redirect_uri"`
	ProvidersRequestConfig json.RawMessage `json:"providers_request,omitempty"`
	Providers              []Configuration `json:"providers"`
}

func (c ConfigurationCollection) Provider(ctx context.Context, id string, reg dependencies) (Provider, error) {
	var providerNames []string
	var addProviderName = func(pn string) string {
		providerNames = append(providerNames, pn)
		return pn
	}
	for k := range c.Providers {
		p := c.Providers[k]
		if p.ID == id {
			return addProvider(p, addProviderName, reg, providerNames)
		}
	}
	if len(c.ProvidersRequestConfig) > 0 {
		pc, err := c.getProviderConfiguration(ctx, id, reg)
		if err != nil {
			return nil, err
		}
		return addProvider(*pc, addProviderName, reg, providerNames)
	}
	return nil, errors.WithStack(herodot.ErrNotFound.WithReasonf(`OpenID Connect Provider "%s" is unknown or has not been configured`, id))
}

// !!! WARNING !!!
//
// If you add a provider here, please also add a test to
// provider_private_net_test.go
func addProvider(p Configuration, addProviderName func(pn string) string, reg dependencies, providerNames []string) (Provider, error) {
	switch p.Provider {
	case addProviderName("generic"):
		return NewProviderGenericOIDC(&p, reg), nil
	case addProviderName("google"):
		return NewProviderGoogle(&p, reg), nil
	case addProviderName("github"):
		return NewProviderGitHub(&p, reg), nil
	case addProviderName("github-app"):
		return NewProviderGitHubApp(&p, reg), nil
	case addProviderName("gitlab"):
		return NewProviderGitLab(&p, reg), nil
	case addProviderName("microsoft"):
		return NewProviderMicrosoft(&p, reg), nil
	case addProviderName("discord"):
		return NewProviderDiscord(&p, reg), nil
	case addProviderName("slack"):
		return NewProviderSlack(&p, reg), nil
	case addProviderName("facebook"):
		return NewProviderFacebook(&p, reg), nil
	case addProviderName("auth0"):
		return NewProviderAuth0(&p, reg), nil
	case addProviderName("vk"):
		return NewProviderVK(&p, reg), nil
	case addProviderName("yandex"):
		return NewProviderYandex(&p, reg), nil
	case addProviderName("apple"):
		return NewProviderApple(&p, reg), nil
	case addProviderName("spotify"):
		return NewProviderSpotify(&p, reg), nil
	case addProviderName("netid"):
		return NewProviderNetID(&p, reg), nil
	case addProviderName("dingtalk"):
		return NewProviderDingTalk(&p, reg), nil
	}
	return nil, errors.Errorf("provider type %s is not supported, supported are: %v", p.Provider, providerNames)
}

func (c ConfigurationCollection) getProviderConfiguration(ctx context.Context, id string, reg dependencies) (*Configuration, error) {
	req, err := c.buildRequest(ctx, id, reg)
	if err != nil {
		return nil, err
	}

	resp, err := reg.HTTPClient(ctx).Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.WithStack(herodot.ErrNotFound.WithReasonf(`OpenID Connect Provider "%s" configuration wasn't found`, id))
	default:
		return nil, errors.New(http.StatusText(resp.StatusCode))
	}

	config := &Configuration{}
	err = json.NewDecoder(resp.Body).Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c ConfigurationCollection) listProviderConfigurations(ctx context.Context, reg dependencies) (*ConfigurationCollection, error) {
	req, err := c.buildRequest(ctx, "", reg)
	if err != nil {
		return nil, err
	}

	resp, err := reg.HTTPClient(ctx).Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.WithStack(herodot.ErrNotFound.WithReasonf(`OpenID Connect Provider configurations were not found`))
	default:
		return nil, errors.New(http.StatusText(resp.StatusCode))
	}

	config := &ConfigurationCollection{}
	err = json.NewDecoder(resp.Body).Decode(&config.Providers)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c ConfigurationCollection) buildRequest(ctx context.Context, id string, reg dependencies) (*retryablehttp.Request, error) {
	builder, err := request.NewBuilder(c.ProvidersRequestConfig, reg)
	if err != nil {
		return nil, err
	}

	req, err := builder.BuildRequest(ctx, nil)
	if err != nil {
		return nil, err
	}

	if id != "" {
		req.URL.Path = fmt.Sprintf("%s/%s", req.URL.Path, id)
	}

	return req, nil
}

type WithSecretHidden Configuration

func (c WithSecretHidden) MarshalJSON() ([]byte, error) {
	type localConfiguration Configuration
	c.ClientSecret = ""
	c.PrivateKeyId = ""
	c.PrivateKey = ""
	return json.Marshal(localConfiguration(c))
}
