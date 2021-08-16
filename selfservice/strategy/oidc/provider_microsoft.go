package oidc

import (
	"context"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
)

type ProviderMicrosoft struct {
	*ProviderGenericOIDC
}

func NewProviderMicrosoft(
	config *Configuration,
	reg dependencies,
) *ProviderMicrosoft {
	config.IssuerURL = microsoftRootUrl + config.Tenant + "/v2.0"

	return &ProviderMicrosoft{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

const microsoftRootUrl = "https://login.microsoftonline.com/"

func (m *ProviderMicrosoft) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	if len(strings.TrimSpace(m.config.Tenant)) == 0 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("No Tenant specified for the `microsoft` oidc provider %s", m.config.ID))
	}

	endpointPrefix := microsoftRootUrl + m.config.Tenant
	endpoint := oauth2.Endpoint{
		AuthURL:  endpointPrefix + "/oauth2/v2.0/authorize",
		TokenURL: endpointPrefix + "/oauth2/v2.0/token",
	}

	return m.oauth2ConfigFromEndpoint(ctx, endpoint), nil
}

func (m *ProviderMicrosoft) Claims(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, errors.WithStack(ErrIDTokenMissing)
	}

	return m.ClaimsFromIdToken(ctx, raw)
}

func (m *ProviderMicrosoft) ClaimsFromIdToken(ctx context.Context, rawIdToken string) (*Claims, error) {
	parser := new(jwt.Parser)
	unverifiedClaims := microsoftUnverifiedClaims{}
	if _, _, err := parser.ParseUnverified(rawIdToken, &unverifiedClaims); err != nil {
		return nil, err
	}

	if _, err := uuid.FromString(unverifiedClaims.TenantID); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("TenantID claim is not a valid UUID: %s", err))
	}

	issuer := microsoftRootUrl + unverifiedClaims.TenantID + "/v2.0"
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to initialize OpenID Connect Provider: %s", err))
	}

	return m.verifyAndDecodeClaimsWithProvider(ctx, p, rawIdToken)
}

func (d *ProviderMicrosoft) ClaimsFromAccessToken(ctx context.Context, accessToken string) (*Claims, error) {
	return d.ProviderGenericOIDC.ClaimsFromAccessToken(gooidc.InsecureIssuerURLContext(ctx, d.config.IssuerURL), accessToken)
}

type microsoftUnverifiedClaims struct {
	TenantID string `json:"tid,omitempty"`
}

func (c *microsoftUnverifiedClaims) Valid() error {
	return nil
}
