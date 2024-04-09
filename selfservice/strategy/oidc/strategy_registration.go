// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/go-jsonnet"
	"net/http"
	"strings"
	"time"

	"github.com/ory/x/sqlxx"

	"github.com/ory/herodot"

	"github.com/ory/x/fetcher"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ory/x/decoderx"

	"golang.org/x/oauth2"

	"github.com/ory/kratos/selfservice/flow/login"

	"github.com/ory/kratos/text"

	"github.com/pkg/errors"

	"github.com/ory/kratos/continuity"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/x"
)

var _ registration.Strategy = new(Strategy)

type MetadataType string

type VerifiedAddress struct {
	Value string                         `json:"value"`
	Via   identity.VerifiableAddressType `json:"via"`
}

const (
	VerifiedAddressesKey = "identity.verified_addresses"

	PublicMetadata MetadataType = "identity.metadata_public"
	AdminMetadata  MetadataType = "identity.metadata_admin"
)

func (s *Strategy) RegisterRegistrationRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
}

func (s *Strategy) PopulateRegistrationMethod(r *http.Request, f *registration.Flow) error {
	if f.Type != flow.TypeBrowser {
		return nil
	}

	return s.populateMethod(r, f.UI, text.NewInfoRegistrationWith)
}

// Update Registration Flow with OpenID Connect Method
//
// swagger:model updateRegistrationFlowWithOidcMethod
type UpdateRegistrationFlowWithOidcMethod struct {
	// The provider to register with
	//
	// required: true
	Provider string `json:"provider"`

	// The CSRF Token
	CSRFToken string `json:"csrf_token"`

	// The identity traits
	Traits json.RawMessage `json:"traits"`

	// Method to use
	//
	// This field must be set to `oidc` when using the oidc method.
	//
	// required: true
	Method string `json:"method"`

	// Transient data to pass along to any webhooks
	//
	// required: false
	TransientPayload json.RawMessage `json:"transient_payload,omitempty"`

	// Only used in API-type flows, when an id token has been received by mobile app directly from oidc provider.
	//
	// required: false
	IDToken string `json:"id_token"`
	// Only used in API-type flows, when an access token has been received by mobile app directly from oidc provider.
	//
	// required: false
	AccessToken string `json:"access_token"`
}

func (s *Strategy) newLinkDecoder(p interface{}, r *http.Request) error {
	ds, err := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
	if err != nil {
		return err
	}

	raw, err := sjson.SetBytes(linkSchema, "properties.traits.$ref", ds.String()+"#/properties/traits")
	if err != nil {
		return errors.WithStack(err)
	}

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(raw)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := s.dec.Decode(r, &p, compiler,
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderSetValidatePayloads(false),
		decoderx.HTTPDecoderUseQueryAndBody(),
		decoderx.HTTPDecoderAllowedMethods("POST", "GET"),
		decoderx.HTTPDecoderJSONFollowsFormFormat(),
	); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (s *Strategy) Register(w http.ResponseWriter, r *http.Request, f *registration.Flow, i *identity.Identity) (err error) {
	var pid = ""
	var idToken = ""
	var accessToken = ""

	var p UpdateRegistrationFlowWithOidcMethod
	if f.Type == flow.TypeBrowser {
		if err := s.newLinkDecoder(&p, r); err != nil {
			return s.handleError(w, r, f, "", nil, err)
		}

		pid = p.Provider // this can come from both url query and post body
	} else {
		if err := flow.MethodEnabledAndAllowedFromRequest(r, s.ID().String(), s.d); err != nil {
			return err
		}

		if err := s.dec.Decode(r, &p,
			decoderx.HTTPDecoderSetValidatePayloads(true),
			decoderx.MustHTTPRawJSONSchemaCompiler(loginSchema),
			decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
			return s.handleError(w, r, f, "", nil, err)
		}

		idToken = p.IDToken
		accessToken = p.AccessToken
		pid = p.Provider
	}

	f.TransientPayload = p.TransientPayload
	if pid == "" {
		return errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if err := flow.MethodEnabledAndAllowed(r.Context(), s.SettingsStrategyID(), s.SettingsStrategyID(), s.d); err != nil {
		return s.handleError(w, r, f, pid, nil, err)
	}

	provider, err := s.provider(r.Context(), pid)
	if err != nil {
		return s.handleError(w, r, f, pid, nil, err)
	}

	c, err := provider.OAuth2(r.Context())
	if err != nil {
		return s.handleError(w, r, f, pid, nil, err)
	}

	req, err := s.validateFlow(r.Context(), r, f.ID)
	if err != nil {
		return s.handleError(w, r, f, pid, nil, err)
	}

	if s.alreadyAuthenticated(w, r, req) {
		return errors.WithStack(registration.ErrAlreadyLoggedIn)
	}

	state := generateState(f.ID.String())
	if f.Type == flow.TypeBrowser {
		if err := s.d.ContinuityManager().Pause(r.Context(), w, r, sessionName,
			continuity.WithPayload(&authCodeContainer{
				State:            state,
				FlowID:           f.ID.String(),
				Traits:           p.Traits,
				TransientPayload: f.TransientPayload,
			}),
			continuity.WithLifespan(time.Minute*30)); err != nil {
			return s.handleError(w, r, f, pid, nil, err)
		}

		options, err := provider.AuthCodeURLOptions(req)
		if err != nil {
			return s.handleError(w, r, f, pid, nil, err)
		}
		codeURL := c.AuthCodeURL(state, options...)
		if x.IsJSONRequest(r) {
			s.d.Writer().WriteError(w, r, flow.NewBrowserLocationChangeRequiredError(codeURL))
		} else {
			http.Redirect(w, r, codeURL, http.StatusSeeOther)
		}

		return errors.WithStack(flow.ErrCompletedByStrategy)
	} else if f.Type == flow.TypeAPI {
		var claims *Claims
		if apiFlowProvider, ok := provider.(APIFlowProvider); ok {
			if len(idToken) > 0 {
				claims, err = apiFlowProvider.ClaimsFromIDToken(r.Context(), idToken)
				if err != nil {
					return errors.WithStack(err)
				}
			} else if len(accessToken) > 0 {
				claims, err = apiFlowProvider.ClaimsFromAccessToken(r.Context(), accessToken)
				if err != nil {
					return errors.WithStack(err)
				}
			} else {
				return s.handleError(w, r, f, p.Provider, nil, ErrIDTokenMissing)
			}
		} else {
			return s.handleError(w, r, f, p.Provider, nil, ErrProviderNoAPISupport)
		}

		fetch := fetcher.NewFetcher(fetcher.WithClient(s.d.HTTPClient(r.Context())))
		jn, err := fetch.Fetch(provider.Config().Mapper)
		if err != nil {
			return s.handleError(w, r, f, provider.Config().ID, nil, err)
		}

		var jsonClaims bytes.Buffer
		if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
			return s.handleError(w, r, f, provider.Config().ID, nil, err)
		}

		vm := jsonnet.MakeVM()
		vm.ExtCode("claims", jsonClaims.String())
		evaluated, err := vm.EvaluateAnonymousSnippet(provider.Config().Mapper, jn.String())
		if err != nil {
			return s.handleError(w, r, f, provider.Config().ID, nil, err)
		} else if traits := gjson.Get(evaluated, "identity.traits"); !traits.IsObject() {
			i.Traits = []byte{'{', '}'}
			s.d.Logger().
				WithRequest(r).
				WithField("oidc_provider", provider.Config().ID).
				WithSensitiveField("oidc_claims", claims).
				WithField("mapper_jsonnet_output", evaluated).
				WithField("mapper_jsonnet_url", provider.Config().Mapper).
				Error("OpenID Connect Jsonnet mapper did not return an object for key identity.traits. Please check your Jsonnet code!")
		} else {
			i.Traits = []byte(traits.Raw)
		}

		s.d.Logger().
			WithRequest(r).
			WithField("oidc_provider", provider.Config().ID).
			WithSensitiveField("oidc_claims", claims).
			WithField("mapper_jsonnet_output", evaluated).
			WithField("mapper_jsonnet_url", provider.Config().Mapper).
			Debug("OpenID Connect Jsonnet mapper completed.")

		// Validate the identity itself
		if err := s.d.IdentityValidator().Validate(r.Context(), i); err != nil {
			return s.handleError(w, r, f, provider.Config().ID, i.Traits, err)
		}

		creds, err := identity.NewCredentialsOIDC(
			idToken,
			"",
			"",
			provider.Config().ID,
			claims.Subject)
		if err != nil {
			return s.handleError(w, r, f, provider.Config().ID, i.Traits, err)
		}

		i.SetCredentials(s.ID(), *creds)

		return nil

	} else {
		return errors.WithStack(errors.New(fmt.Sprintf("Not supported flow type: %s", f.Type)))
	}
}

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, token *oauth2.Token, claims *Claims, provider Provider, container *authCodeContainer) (*login.Flow, error) {
	if _, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeOIDC, identity.OIDCUniqueID(provider.Config().ID, claims.Subject)); err == nil {
		// If the identity already exists, we should perform the login flow instead.

		// That will execute the "pre registration" hook which allows to e.g. disallow this flow. The registration
		// ui however will NOT be shown, instead the user is directly redirected to the auth path. That should then
		// do a silent re-request. While this might be a bit excessive from a network perspective it should usually
		// happen without any downsides to user experience as the request has already been authorized and should
		// not need additional consent/login.

		// This is kinda hacky but the only way to ensure seamless login/registration flows when using OIDC.
		s.d.Logger().WithRequest(r).WithField("provider", provider.Config().ID).
			WithField("subject", claims.Subject).
			Debug("Received successful OpenID Connect callback but user is already registered. Re-initializing login flow now.")

		// If return_to was set before, we need to preserve it.
		var opts []login.FlowOption
		if len(a.ReturnTo) > 0 {
			opts = append(opts, login.WithFlowReturnTo(a.ReturnTo))
		}

		// This endpoint only handles browser flow at the moment.
		ar, _, err := s.d.LoginHandler().NewLoginFlow(w, r, flow.TypeBrowser, opts...)
		if err != nil {
			return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
		}

		ar.RequestURL, err = x.TakeOverReturnToParameter(a.RequestURL, ar.RequestURL)
		if err != nil {
			return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
		}

		if _, err := s.processLogin(w, r, ar, token, claims, provider, container); err != nil {
			return ar, err
		}
		return nil, nil
	}

	fetch := fetcher.NewFetcher(fetcher.WithClient(s.d.HTTPClient(r.Context())))
	jn, err := fetch.Fetch(provider.Config().Mapper)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	i, va, err := s.createIdentity(w, r, a, claims, provider, container, jn)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	// Validate the identity itself
	if err := s.d.IdentityValidator().Validate(r.Context(), i); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	for n := range i.VerifiableAddresses {
		verifiable := &i.VerifiableAddresses[n]
		for _, verified := range va {
			if verifiable.Via == verified.Via && verifiable.Value == verified.Value {
				verifiable.Status = identity.VerifiableAddressStatusCompleted
				verifiable.Verified = true
				t := sqlxx.NullTime(time.Now().UTC().Round(time.Second))
				verifiable.VerifiedAt = &t
			}
		}
	}

	var it string
	if idToken, ok := token.Extra("id_token").(string); ok {
		if it, err = s.d.Cipher(r.Context()).Encrypt(r.Context(), []byte(idToken)); err != nil {
			return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
		}
	}

	cat, err := s.d.Cipher(r.Context()).Encrypt(r.Context(), []byte(token.AccessToken))
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	crt, err := s.d.Cipher(r.Context()).Encrypt(r.Context(), []byte(token.RefreshToken))
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	creds, err := identity.NewCredentialsOIDC(it, cat, crt, provider.Config().ID, claims.Subject)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	i.SetCredentials(s.ID(), *creds)
	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeOIDC, provider.Config().ID, a, i); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	return nil, nil
}

func (s *Strategy) createIdentity(w http.ResponseWriter, r *http.Request, a *registration.Flow, claims *Claims, provider Provider, container *authCodeContainer, jn *bytes.Buffer) (*identity.Identity, []VerifiedAddress, error) {
	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	vm, err := s.d.JsonnetVM(r.Context())
	if err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	vm.ExtCode("claims", jsonClaims.String())
	vm.ExtVar("provider", provider.Config().ID)
	evaluated, err := vm.EvaluateAnonymousSnippet(provider.Config().Mapper, jn.String())
	if err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	i := identity.NewIdentity(s.d.Config().DefaultIdentityTraitsSchemaID(r.Context()))
	if err := s.setTraits(provider, container, evaluated, i); err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	if err := s.setMetadata(evaluated, i, PublicMetadata); err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	if err := s.setMetadata(evaluated, i, AdminMetadata); err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	va, err := s.extractVerifiedAddresses(evaluated)
	if err != nil {
		return nil, nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	s.d.Logger().
		WithRequest(r).
		WithField("oidc_provider", provider.Config().ID).
		WithSensitiveField("oidc_claims", claims).
		WithSensitiveField("mapper_jsonnet_output", evaluated).
		WithField("mapper_jsonnet_url", provider.Config().Mapper).
		Debug("OpenID Connect Jsonnet mapper completed.")
	return i, va, nil
}

func (s *Strategy) setTraits(provider Provider, container *authCodeContainer, evaluated string, i *identity.Identity) error {
	jsonTraits := gjson.Get(evaluated, "identity.traits")
	if !jsonTraits.IsObject() {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("OpenID Connect Jsonnet mapper did not return an object for key identity.traits. Please check your Jsonnet code!"))
	}

	traits, err := merge(container.Traits, json.RawMessage(jsonTraits.Raw))
	if err != nil {
		return err
	}

	i.Traits = traits
	s.d.Logger().
		WithField("oidc_provider", provider.Config().ID).
		WithSensitiveField("identity_traits", i.Traits).
		WithSensitiveField("mapper_jsonnet_output", evaluated).
		WithField("mapper_jsonnet_url", provider.Config().Mapper).
		Debug("Merged form values and OpenID Connect Jsonnet output.")
	return nil
}

func (s *Strategy) setMetadata(evaluated string, i *identity.Identity, m MetadataType) error {
	if m != PublicMetadata && m != AdminMetadata {
		return errors.Errorf("undefined metadata type: %s", m)
	}

	metadata := gjson.Get(evaluated, string(m))
	if metadata.Exists() && !metadata.IsObject() {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("OpenID Connect Jsonnet mapper did not return an object for key %s. Please check your Jsonnet code!", m))
	}

	switch m {
	case PublicMetadata:
		i.MetadataPublic = []byte(metadata.Raw)
	case AdminMetadata:
		i.MetadataAdmin = []byte(metadata.Raw)
	}

	return nil
}

func (s *Strategy) extractVerifiedAddresses(evaluated string) ([]VerifiedAddress, error) {
	if verifiedAddresses := gjson.Get(evaluated, VerifiedAddressesKey); verifiedAddresses.Exists() {
		if !verifiedAddresses.IsArray() {
			return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("OpenID Connect Jsonnet mapper did not return an array for key %s. Please check your Jsonnet code!", VerifiedAddressesKey))
		}

		var va []VerifiedAddress
		if err := json.Unmarshal([]byte(verifiedAddresses.Raw), &va); err != nil {
			return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("Failed to unmarshal value for key %s. Please check your Jsonnet code!", VerifiedAddressesKey).WithDebugf("%s", err))
		}

		for _, va := range va {
			if va.Via == identity.VerifiableAddressTypeEmail {
				va.Value = strings.ToLower(strings.TrimSpace(va.Value))
			}
		}

		return va, nil
	}

	return nil, nil
}
