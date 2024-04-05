// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	oryClient "github.com/ory/kratos/internal/httpclient"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/x/ioutilx"
	"github.com/ory/x/sqlxx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ory/kratos/internal/testhelpers"
)

func TestLoginCodeStrategySMSExternal(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/default.schema.json")
	conf.MustSet(ctx, fmt.Sprintf("%s.%s.enabled", config.ViperKeySelfServiceStrategyConfig, identity.CredentialsTypeCode.String()), true)
	conf.MustSet(ctx, fmt.Sprintf("%s.%s.passwordless_enabled", config.ViperKeySelfServiceStrategyConfig, identity.CredentialsTypeCode.String()), true)

	_ = testhelpers.NewLoginUIFlowEchoServer(t, reg)
	_ = testhelpers.NewErrorTestServer(t, reg)
	_ = newReturnTs(t, reg)

	public, _ := testhelpers.NewKratosServer(t, reg)

	var externalVerifyResult string
	var externalVerifyRequestBody string
	initExternalSMSVerifier(t, ctx, conf, "file://./stub/request.config.external_login.jsonnet",
		&externalVerifyRequestBody, &externalVerifyResult)

	createIdentity := func(ctx context.Context, t *testing.T) *identity.Identity {
		t.Helper()
		i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		email := testhelpers.RandomEmail()
		phone := testhelpers.RandomPhone()

		i.Traits = identity.Traits(fmt.Sprintf(`{"tos": true, "email": "%s", "phone": "%s"}`, email, phone))

		i.Credentials[identity.CredentialsTypeCode] = identity.Credentials{Type: identity.CredentialsTypeCode, Identifiers: []string{phone}, Config: sqlxx.JSONRawMessage("{\"address_type\": \"phone\", \"used_at\": \"2023-07-26T16:59:06+02:00\"}")}

		var va []identity.VerifiableAddress
		va = append(va, identity.VerifiableAddress{
			Value:    phone,
			Via:      identity.AddressTypePhone,
			Verified: true,
			Status:   identity.VerifiableAddressStatusCompleted,
		})

		i.VerifiableAddresses = va

		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
		return i
	}

	type state struct {
		flow          *oryClient.LoginFlow
		identity      *identity.Identity
		client        *http.Client
		loginCode     string
		identityPhone string
		testServer    *httptest.Server
		body          string
	}

	type ApiType string

	const (
		ApiTypeBrowser ApiType = "browser"
		ApiTypeSPA     ApiType = "spa"
		ApiTypeNative  ApiType = "api"
	)

	createLoginFlow := func(ctx context.Context, t *testing.T, public *httptest.Server, apiType ApiType) *state {
		t.Helper()

		identity := createIdentity(ctx, t)

		var client *http.Client
		if apiType == ApiTypeNative {
			client = &http.Client{}
		} else {
			client = testhelpers.NewClientWithCookies(t)
		}

		client.Transport = testhelpers.NewTransportWithLogger(http.DefaultTransport, t).RoundTripper

		var clientInit *oryClient.LoginFlow
		if apiType == ApiTypeNative {
			clientInit = testhelpers.InitializeLoginFlowViaAPI(t, client, public, false)
		} else {
			clientInit = testhelpers.InitializeLoginFlowViaBrowser(t, client, public, false, apiType == ApiTypeSPA, false, false)
		}

		body, err := json.Marshal(clientInit)
		require.NoError(t, err)

		csrfToken := gjson.GetBytes(body, "ui.nodes.#(attributes.name==csrf_token).attributes.value").String()
		if apiType == ApiTypeNative {
			require.Emptyf(t, csrfToken, "csrf_token should be empty in native flows, but was found in: %s", body)
		} else {
			require.NotEmptyf(t, csrfToken, "could not find csrf_token in: %s", body)
		}

		loginPhone := gjson.Get(identity.Traits.String(), "phone").String()
		require.NotEmptyf(t, loginPhone, "could not find the phone trait inside the identity: %s", identity.Traits.String())

		return &state{
			flow:          clientInit,
			identity:      identity,
			identityPhone: loginPhone,
			client:        client,
			testServer:    public,
		}
	}

	type onSubmitAssertion func(t *testing.T, s *state, body string, res *http.Response)

	submitLogin := func(ctx context.Context, t *testing.T, s *state, apiType ApiType, vals func(v *url.Values), mustHaveSession bool) *state {
		t.Helper()

		values := url.Values{}
		// we need to remove resend here
		// since it is not required for the first request
		// subsequent requests might need it later
		values.Del("resend")
		values.Set("method", "code")
		vals(&values)

		browserReturnURL := conf.SelfServiceFlowLoginUI(ctx).String()
		if apiType == ApiTypeBrowser && values.Has("code") {
			browserReturnURL = conf.SelfServiceBrowserDefaultReturnTo(ctx).String()
		}
		body := testhelpers.SubmitLoginFormWithFlow(t, apiType == ApiTypeNative, s.client, func(v url.Values) {
			for k, value := range values {
				v.Set(k, value[0])
			}
		},
			apiType == ApiTypeSPA, http.StatusOK,
			testhelpers.ExpectURL(apiType == ApiTypeNative || apiType == ApiTypeSPA, public.URL+login.RouteSubmitFlow, browserReturnURL),
			s.flow)

		s.body = body

		if mustHaveSession {
			req, err := http.NewRequest("GET", s.testServer.URL+session.RouteWhoami, nil)
			require.NoError(t, err)

			if apiType == ApiTypeNative {
				req.Header.Set("Authorization", "Bearer "+gjson.Get(body, "session_token").String())
			}

			resp, err := s.client.Do(req)
			require.NoError(t, err)
			require.EqualValues(t, http.StatusOK, resp.StatusCode, "%s", string(ioutilx.MustReadAll(resp.Body)))
			body = string(ioutilx.MustReadAll(resp.Body))
		}

		return s
	}

	for _, tc := range []struct {
		d       string
		apiType ApiType
	}{
		{
			d:       "SPA client",
			apiType: ApiTypeSPA,
		},
		{
			d:       "Browser client",
			apiType: ApiTypeBrowser,
		},
		{
			d:       "Native client",
			apiType: ApiTypeNative,
		},
	} {

		t.Run("test="+tc.d, func(t *testing.T) {
			t.Run("case=should be able to log in with code", func(t *testing.T) {
				// create login flow
				s := createLoginFlow(ctx, t, public, tc.apiType)

				// submit phone
				s = submitLogin(ctx, t, s, tc.apiType, func(v *url.Values) {
					v.Set("identifier", s.identityPhone)
				}, false)

				assert.Contains(t, externalVerifyResult, "code has been sent")

				// 3. Submit OTP
				submitLogin(ctx, t, s, tc.apiType, func(v *url.Values) {
					v.Set("code", "0000")
				}, true)

				assert.Contains(t, externalVerifyResult, "code valid")
			})
		})
	}
}
