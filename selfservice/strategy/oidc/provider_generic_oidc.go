// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/x/stringslice"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

var _ Provider = new(ProviderGenericOIDC)

type ProviderGenericOIDC struct {
	p      *gooidc.Provider
	config *Configuration
	reg    dependencies
}

func NewProviderGenericOIDC(
	config *Configuration,
	reg dependencies,
) *ProviderGenericOIDC {
	return &ProviderGenericOIDC{
		config: config,
		reg:    reg,
	}
}

func (g *ProviderGenericOIDC) Config() *Configuration {
	return g.config
}

func (g *ProviderGenericOIDC) provider(ctx context.Context) (*gooidc.Provider, error) {
	if g.p == nil {
		p, err := gooidc.NewProvider(context.WithValue(ctx, oauth2.HTTPClient, g.reg.HTTPClient(ctx).HTTPClient), g.config.IssuerURL)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to initialize OpenID Connect Provider: %s", err))
		}
		g.p = p
	}
	return g.p, nil
}

func (g *ProviderGenericOIDC) oauth2ConfigFromEndpoint(ctx context.Context, endpoint oauth2.Endpoint) *oauth2.Config {
	scope := g.config.Scope
	if !stringslice.Has(scope, gooidc.ScopeOpenID) {
		scope = append(scope, gooidc.ScopeOpenID)
	}

	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scope,
		RedirectURL:  g.config.Redir(g.reg.Config().OIDCRedirectURIBase(ctx)),
	}
}

func (g *ProviderGenericOIDC) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := p.Endpoint()
	return g.oauth2ConfigFromEndpoint(ctx, endpoint), nil
}

func (g *ProviderGenericOIDC) AuthCodeURLOptions(r ider) ([]oauth2.AuthCodeOption, error) {
	var options []oauth2.AuthCodeOption

	if isForced(r) {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if len(g.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(g.config.RequestedClaims)))
	}

	if len(g.config.UpstreamParameters) != 0 {
		var params map[string]string
		if err := json.Unmarshal(g.config.UpstreamParameters, &params); err != nil {
			return nil, err
		}
		for key, value := range params {
			options = append(options, oauth2.SetAuthURLParam(key, value))
		}
	}

	return options, nil
}

func (g *ProviderGenericOIDC) verifyAndDecodeClaimsWithProvider(ctx context.Context, provider *gooidc.Provider, rawIDToken string) (*Claims, error) {
	skipClientIDCheck := g.config.AllowedAudiences != nil && len(g.config.AllowedAudiences) > 0
	token, err := provider.
		Verifier(&gooidc.Config{
			ClientID:          g.config.ClientID,
			SkipClientIDCheck: skipClientIDCheck,
		}).
		Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	if skipClientIDCheck {
		if err := verifyAudience(token.Audience, g.config.AllowedAudiences); err != nil {
			return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
		}
	}

	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	var rawClaims map[string]interface{}
	if err := token.Claims(&rawClaims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	claims.RawClaims = rawClaims

	return &claims, nil
}

func verifyAudience(received []string, expected []string) error {
	for _, r := range received {
		for _, e := range expected {
			if r == e {
				return nil
			}
		}
	}
	return errors.Errorf("oidc: audience not valid: %v", received)
}

func (g *ProviderGenericOIDC) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, errors.WithStack(ErrIDTokenMissing)
	}

	return g.ClaimsFromIDToken(ctx, raw)
}

func (g *ProviderGenericOIDC) ClaimsFromIDToken(ctx context.Context, rawIDToken string) (*Claims, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	return g.verifyAndDecodeClaimsWithProvider(ctx, p, rawIDToken)
}

func (g *ProviderGenericOIDC) ClaimsFromAccessToken(ctx context.Context, accessToken string) (*Claims, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	token := tokenAccessor{token: oauth2.Token{AccessToken: accessToken}}

	userinfo, err := p.UserInfo(ctx, &token)
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := userinfo.Claims(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	return &claims, nil
}

type tokenAccessor struct {
	token oauth2.Token
}

func (a *tokenAccessor) Token() (*oauth2.Token, error) {
	return &a.token, nil
}
