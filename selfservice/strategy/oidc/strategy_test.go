// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jarcoal/httpmock"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/ui/node"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/x/sqlxx"

	"github.com/ory/x/snapshotx"

	"github.com/ory/kratos/text"

	"github.com/ory/x/ioutilx"

	"github.com/ory/x/assertx"

	"github.com/ory/kratos/ui/container"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/x/urlx"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"

	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
)

func TestStrategy(t *testing.T) {
	ctx := context.Background()
	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
		subject   string
		claims    idTokenClaims
		scope     []string
	)
	remoteAdmin, remotePublic, hydraIntegrationTSURL := newHydra(t, &subject, &claims, &scope)
	returnTS := newReturnTs(t, reg)
	conf.MustSet(ctx, config.ViperKeyURLsAllowedReturnToDomains, []string{returnTS.URL})
	conf.MustSet(ctx, config.ViperKeySelfServiceVerificationEnabled, true)
	uiTS := newUI(t, reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)
	invalid := newOIDCProvider(t, ts, remotePublic, remoteAdmin, "invalid-issuer", "", nil)
	testCallbackUrl := newTestCallback(t, reg)
	webviewRedirectURI := ts.URL + "/self-service/oidc/webview"
	validProviderConfig := newOIDCProvider(t, ts, remotePublic, remoteAdmin, "valid", testCallbackUrl, nil)
	viperSetProviderConfig(
		t,
		conf,
		validProviderConfig,
		newOIDCProvider(t, ts, remotePublic, remoteAdmin, "secondProvider", testCallbackUrl, nil),
		oidc.Configuration{
			Provider:     "generic",
			ID:           "invalid-issuer",
			ClientID:     invalid.ClientID,
			ClientSecret: invalid.ClientSecret,
			// We replace this URL to cause an issuer validation mismatch.
			IssuerURL: strings.Replace(remotePublic, "localhost", "127.0.0.1", 1) + "/",
			Mapper:    "file://./stub/oidc.hydra.jsonnet",
		},
		newOIDCProvider(t, ts, remotePublic, remoteAdmin, "check_audience", testCallbackUrl, []string{"test.audience"}),
	)

	conf.MustSet(ctx, config.ViperKeySelfServiceRegistrationEnabled, true)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration.schema.json")
	conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeOIDC.String()), []config.SelfServiceHook{{Name: "session"}})
	conf.MustSet(ctx, config.ViperKeySelfServiceWebViewRedirectURL, webviewRedirectURI)

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)
	t.Logf("Hydra Public URL: %s", remotePublic)
	t.Logf("Hydra Admin URL: %s", remoteAdmin)
	t.Logf("Hydra Integration URL: %s", hydraIntegrationTSURL)
	t.Logf("Return URL: %s", returnTS.URL)

	subject = "foo@bar.com"
	scope = []string{}

	// assert form values
	var afv = func(t *testing.T, flowID uuid.UUID, provider string) (action string) {
		var config *container.Container
		if req, err := reg.RegistrationFlowPersister().GetRegistrationFlow(context.Background(), flowID); err == nil {
			require.EqualValues(t, req.ID, flowID)
			config = req.UI
			require.NotNil(t, config)
		} else if req, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), flowID); err == nil {
			require.EqualValues(t, req.ID, flowID)
			config = req.UI
			require.NotNil(t, config)
		} else {
			require.NoError(t, err)
			return
		}

		assert.Equal(t, "POST", config.Method)

		var found bool
		for _, field := range config.Nodes {
			if strings.Contains(field.ID(), "provider") && field.GetValue() == provider {
				found = true
				break
			}
		}
		require.True(t, found, "%+v", assertx.PrettifyJSONPayload(t, config))

		return config.Action
	}

	var registerAction = func(flowID uuid.UUID) string {
		return ts.URL + registration.RouteSubmitFlow + "?flow=" + flowID.String()
	}

	var loginAction = func(flowID uuid.UUID) string {
		return ts.URL + login.RouteSubmitFlow + "?flow=" + flowID.String()
	}

	var makeRequestWithCookieJar = func(t *testing.T, provider string, action string, fv url.Values, jar *cookiejar.Jar) (*http.Response, []byte) {
		fv.Set("provider", provider)
		fv.Set("method", "oidc")
		res, err := testhelpers.NewClientWithCookieJar(t, jar, false).PostForm(action, fv)
		require.NoError(t, err, action)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, 200, res.StatusCode, "%s: %s\n\t%s", action, res.Request.URL.String(), body)

		return res, body
	}

	var makeRequest = func(t *testing.T, provider string, action string, fv url.Values) (*http.Response, []byte) {
		return makeRequestWithCookieJar(t, provider, action, fv, nil)
	}

	var assertSystemError = func(t *testing.T, res *http.Response, body []byte, code int, reason string) {
		require.Contains(t, res.Request.URL.String(), errTS.URL, "%s", body)

		assert.Equal(t, int64(code), gjson.GetBytes(body, "code").Int(), "%s", body)
		assert.Contains(t, gjson.GetBytes(body, "reason").String(), reason, "%s", body)
	}

	// assert system error (redirect to error endpoint)
	var asem = func(t *testing.T, res *http.Response, body []byte, code int, reason string) {
		require.Contains(t, res.Request.URL.String(), errTS.URL, "%s", body)

		assert.Equal(t, int64(code), gjson.GetBytes(body, "code").Int(), "%s", body)
		assert.Contains(t, gjson.GetBytes(body, "message").String(), reason, "%s", body)
	}

	// assert ui error (redirect to login/registration ui endpoint)
	var aue = func(t *testing.T, res *http.Response, body []byte, reason string) {
		require.Contains(t, res.Request.URL.String(), uiTS.URL, "status: %d, body: %s", res.StatusCode, body)
		assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(), reason, "%s", body)
	}

	// assert identity (success)
	var ai = func(t *testing.T, res *http.Response, body []byte) {
		assert.Contains(t, res.Request.URL.String(), returnTS.URL, "%s", body)
		assert.Equal(t, subject, gjson.GetBytes(body, "identity.traits.subject").String(), "%s", body)
		assert.Equal(t, claims.traits.website, gjson.GetBytes(body, "identity.traits.website").String(), "%s", body)
		assert.Equal(t, claims.metadataPublic.picture, gjson.GetBytes(body, "identity.metadata_public.picture").String(), "%s", body)
	}

	var newLoginFlow = func(t *testing.T, redirectTo string, exp time.Duration, flowType flow.Type) (req *login.Flow) {
		// Use NewLoginFlow to instantiate the request but change the things we need to control a copy of it.
		req, _, err := reg.LoginHandler().NewLoginFlow(httptest.NewRecorder(),
			&http.Request{URL: urlx.ParseOrPanic(redirectTo)}, flowType)
		require.NoError(t, err)
		req.RequestURL = redirectTo
		req.ExpiresAt = time.Now().Add(exp)
		require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(context.Background(), req))

		// sanity check
		got, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), req.ID)
		require.NoError(t, err)

		require.Len(t, got.UI.Nodes, len(req.UI.Nodes), "%+v", got)

		return
	}

	var newLoginFlowBrowser = func(t *testing.T, redirectTo string, exp time.Duration) (req *login.Flow) {
		return newLoginFlow(t, redirectTo, exp, flow.TypeBrowser)
	}

	var newRegistrationFlow = func(t *testing.T, redirectTo string, exp time.Duration, flowType flow.Type) *registration.Flow {
		// Use NewLoginFlow to instantiate the request but change the things we need to control a copy of it.
		req, err := reg.RegistrationHandler().NewRegistrationFlow(httptest.NewRecorder(),
			&http.Request{URL: urlx.ParseOrPanic(redirectTo)}, flowType)
		require.NoError(t, err)
		req.RequestURL = redirectTo
		req.ExpiresAt = time.Now().Add(exp)
		require.NoError(t, reg.RegistrationFlowPersister().UpdateRegistrationFlow(context.Background(), req))

		// sanity check
		got, err := reg.RegistrationFlowPersister().GetRegistrationFlow(context.Background(), req.ID)
		require.NoError(t, err)
		require.Len(t, got.UI.Nodes, len(req.UI.Nodes), "%+v", req)

		return req
	}

	var newRegistrationFlowBrowser = func(t *testing.T, redirectTo string, exp time.Duration) *registration.Flow {
		return newRegistrationFlow(t, redirectTo, exp, flow.TypeBrowser)
	}

	t.Run("case=should fail because provider does not exist", func(t *testing.T) {
		for k, v := range []string{
			loginAction(newLoginFlowBrowser(t, returnTS.URL, time.Minute).ID),
			registerAction(newRegistrationFlowBrowser(t, returnTS.URL, time.Minute).ID),
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				res, body := makeRequest(t, "provider-does-not-exist", v, url.Values{})
				assertSystemError(t, res, body, http.StatusNotFound, "is unknown or has not been configured")
			})
		}
	})

	var expectValidationError = func(t *testing.T, isAPI, forced, isSPA bool, values func(url.Values)) string {
		return testhelpers.SubmitLoginForm(t, isAPI, nil, ts, values,
			isSPA, forced,
			testhelpers.ExpectStatusCode(isAPI || isSPA, http.StatusBadRequest, http.StatusOK),
			testhelpers.ExpectURL(isAPI || isSPA, ts.URL+login.RouteSubmitFlow, conf.SelfServiceFlowLoginUI(ctx).String()))
	}

	t.Run("case=api should fail because id_token was not provided", func(t *testing.T) {
		var check = func(t *testing.T, body string) {
			assert.NotEmpty(t, gjson.Get(body, "id").String(), "%s", body)
			assert.Contains(t, gjson.Get(body, "ui.action").String(), ts.URL+login.RouteSubmitFlow, "%s", body)

			assert.Contains(t,
				gjson.Get(body, "ui.messages.0.text").String(),
				"no id_token",
				"%s", body)
			//assert.Len(t, gjson.Get(body, "ui.nodes").Array(), 4) //TODO Get rid of password fields
		}

		var values = func(v url.Values) {
			v.Set("method", "oidc")
			v.Set("provider", "valid")
		}

		check(t, expectValidationError(t, true, false, false, values))
	})

	t.Run("case=api should fail because id_token is invalid", func(t *testing.T) {
		var check = func(t *testing.T, body string) {
			assert.NotEmpty(t, gjson.Get(body, "id").String(), "%s", body)
			assert.Contains(t, gjson.Get(body, "ui.action").String(), ts.URL+login.RouteSubmitFlow, "%s", body)

			assert.Contains(t,
				gjson.Get(body, "ui.messages.0.text").String(),
				"malformed jwt",
				"%s", body)
			//assert.Len(t, gjson.Get(body, "ui.nodes").Array(), 4) //TODO Get rid of password fields
		}

		var values = func(v url.Values) {
			v.Set("method", "oidc")
			v.Set("provider", "valid")
			v.Set("id_token", "invalid-token")
		}

		check(t, expectValidationError(t, true, false, false, values))
	})

	t.Run("case=should fail because the issuer is mismatching", func(t *testing.T) {
		scope = []string{"openid"}
		for k, v := range []string{
			loginAction(newLoginFlowBrowser(t, returnTS.URL, time.Minute).ID),
			registerAction(newRegistrationFlowBrowser(t, returnTS.URL, time.Minute).ID),
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				res, body := makeRequest(t, "invalid-issuer", v, url.Values{})
				assertSystemError(t, res, body, http.StatusInternalServerError, "issuer did not match the issuer returned by provider")
			})
		}
	})

	t.Run("case=should fail because flow does not exist", func(t *testing.T) {
		for k, v := range []string{loginAction(x.NewUUID()), registerAction(x.NewUUID())} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				res, body := makeRequest(t, "valid", v, url.Values{})
				asem(t, res, body, http.StatusNotFound, "Unable to locate the resource")
			})
		}
	})

	t.Run("case=should fail because the flow is expired", func(t *testing.T) {
		for k, v := range []uuid.UUID{
			newLoginFlowBrowser(t, returnTS.URL, -time.Minute).ID,
			newRegistrationFlowBrowser(t, returnTS.URL, -time.Minute).ID} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				action := afv(t, v, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})

				assert.NotEqual(t, v, gjson.GetBytes(body, "id"))
				require.Contains(t, res.Request.URL.String(), uiTS.URL, "%s", body)
				assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(), "flow expired", "%s", body)
			})
		}
	})

	t.Run("case=should fail registration because scope was not provided", func(t *testing.T) {
		subject = "foo@bar.com"
		scope = []string{}

		for k, v := range []uuid.UUID{
			newLoginFlowBrowser(t, returnTS.URL, time.Minute).ID,
			newRegistrationFlowBrowser(t, returnTS.URL, time.Minute).ID} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				action := afv(t, v, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				aue(t, res, body, "no id_token was returned")
			})
		}
	})

	t.Run("case=should fail because password can not handle AAL2", func(t *testing.T) {
		testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration-aal.schema.json")
		t.Cleanup(func() {
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration.schema.json")
		})
		bc := testhelpers.NewDebugClient(t)
		f := testhelpers.InitializeLoginFlowViaAPI(t, bc, ts, false)

		update, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), uuid.FromStringOrNil(f.Id))
		require.NoError(t, err)
		update.RequestedAAL = identity.AuthenticatorAssuranceLevel2
		require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(context.Background(), update))

		req, err := http.NewRequest("POST", f.Ui.Action, bytes.NewBufferString(`{"method":"oidc"}`))
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		actual, res := testhelpers.MockMakeAuthenticatedRequest(t, reg, conf, routerP.Router, req)
		assert.Contains(t, res.Request.URL.String(), ts.URL+login.RouteSubmitFlow)
		assert.Equal(t, text.NewErrorValidationLoginNoStrategyFound().Text, gjson.GetBytes(actual, "ui.messages.0.text").String())
	})

	t.Run("case=should fail login because scope was not provided", func(t *testing.T) {
		r := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
		action := afv(t, r.ID, "valid")
		res, body := makeRequest(t, "valid", action, url.Values{})
		aue(t, res, body, "no id_token was returned")
	})

	t.Run("case=should fail registration flow because subject is not an email", func(t *testing.T) {
		subject = "not-an-email"
		scope = []string{"openid"}

		r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
		action := afv(t, r.ID, "valid")
		res, body := makeRequest(t, "valid", action, url.Values{})

		require.Contains(t, res.Request.URL.String(), uiTS.URL, "%s", body)
		assert.Contains(t, gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.subject).messages.0.text").String(), "is not valid", "%s\n%s", gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.subject)").Raw, body)
	})

	t.Run("case=should fail because the audience is mismatching", func(t *testing.T) {
		subject = "foo@bar.com"
		scope = []string{"openid"}

		r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
		action := afv(t, r.ID, "check_audience")
		_, body := makeRequest(t, "check_audience", action, url.Values{})
		assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(), "audience not valid", "%s", body)
	})

	t.Run("case=cannot register multiple accounts with the same OIDC account", func(t *testing.T) {
		subject = "oidc-register-then-login@ory.sh"
		scope = []string{"openid", "offline"}

		expectTokens := func(t *testing.T, provider string, body []byte) {
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), uuid.FromStringOrNil(gjson.GetBytes(body, "identity.id").String()))
			require.NoError(t, err)
			c := i.Credentials[identity.CredentialsTypeOIDC].Config
			assert.NotEmpty(t, gjson.GetBytes(c, "providers.0.initial_access_token").String())
			assertx.EqualAsJSONExcept(
				t,
				json.RawMessage(fmt.Sprintf(`{"providers": [{"subject":"%s","provider":"%s"}]}`, subject, provider)),
				json.RawMessage(c),
				[]string{"providers.0.initial_id_token", "providers.0.initial_access_token", "providers.0.initial_refresh_token"},
			)
		}

		t.Run("case=should pass registration", func(t *testing.T) {
			r := newRegistrationFlow(t, returnTS.URL, time.Minute, flow.TypeBrowser)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			ai(t, res, body)
			expectTokens(t, "valid", body)
		})

		t.Run("case=try another registration", func(t *testing.T) {
			returnTo := fmt.Sprintf("%s/home?query=true", returnTS.URL)
			r := newRegistrationFlow(t, fmt.Sprintf("%s?return_to=%s", returnTS.URL, url.QueryEscape(returnTo)), time.Minute, flow.TypeBrowser)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			assert.Equal(t, returnTo, res.Request.URL.String())
			ai(t, res, body)
			expectTokens(t, "valid", body)
		})
	})

	expectTokens := func(t *testing.T, provider string, body []byte) uuid.UUID {
		id := uuid.FromStringOrNil(gjson.GetBytes(body, "identity.id").String())
		i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), id)
		require.NoError(t, err)
		c := i.Credentials[identity.CredentialsTypeOIDC].Config
		assert.NotEmpty(t, gjson.GetBytes(c, "providers.0.initial_access_token").String())
		assertx.EqualAsJSONExcept(
			t,
			json.RawMessage(fmt.Sprintf(`{"providers": [{"subject":"%s","provider":"%s"}]}`, subject, provider)),
			json.RawMessage(c),
			[]string{"providers.0.initial_id_token", "providers.0.initial_access_token", "providers.0.initial_refresh_token"},
		)
		return id
	}

	t.Run("case=register and then login", func(t *testing.T) {
		scope = []string{"openid", "offline"}
		claims.traits.groups = []string{"group1", "group2"}
		claims.metadataPublic.picture = "picture.png"

		t.Run("case=api", func(t *testing.T) {
			subject = "register-then-login-api@ory.sh"

			err, tokens := getOauthTokens(t, remotePublic,
				validProviderConfig.ClientID,
				validProviderConfig.ClientSecret,
				testCallbackUrl)
			require.NoError(t, err)

			var values = func(v url.Values) {
				v.Set("method", "oidc")
				v.Set("provider", "valid")
				v.Set("id_token", tokens.IDToken)
			}

			t.Run("case=should pass registration", func(t *testing.T) {
				body := testhelpers.SubmitRegistrationForm(t, true, nil, ts, values,
					false, http.StatusOK, ts.URL+registration.RouteSubmitFlow)
				assert.Equal(t, subject, gjson.Get(body, "identity.traits.subject").String(), "%s", body)
			})

			t.Run("case=should pass login", func(t *testing.T) {
				body := testhelpers.SubmitLoginForm(t, true, nil, ts, values,
					false, false, http.StatusOK, ts.URL+login.RouteSubmitFlow)

				assert.NotEmpty(t, gjson.Get(body, "session"), "%s", body)
			})
		})

		t.Run("case=webview", func(t *testing.T) {
			subject = "register-then-login-webview@ory.sh"

			cj, err := cookiejar.New(&cookiejar.Options{})
			require.NoError(t, err)
			var successToken string
			c := &http.Client{
				Jar: cj,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if strings.HasSuffix(req.URL.Path, "/success") {
						assert.True(t, req.URL.Query().Has("session_token"))
						successToken = req.URL.Query().Get("session_token")
						cookies := cj.Cookies(req.URL)
						for _, cookie := range cookies {
							assert.NotEqual(t, "ory_kratos_session", cookie.Name)
						}
						return http.ErrUseLastResponse
					}
					return nil
				},
			}

			var values = func(v url.Values) {
				v.Set("method", "oidc")
				v.Set("provider", "valid")
			}

			t.Run("case=should pass registration", func(t *testing.T) {
				body := testhelpers.SubmitRegistrationForm(t, false, c, ts, values,
					false, http.StatusSeeOther, ts.URL+"/self-service/methods/oidc/callback/valid",
					testhelpers.InitFlowWithReturnTo(webviewRedirectURI))

				assert.NotEmpty(t, gjson.Get(body, "session_token"), "%s", body)
				assert.NotEmpty(t, gjson.Get(body, "session"), "%s", body)
			})

			t.Run("case=should pass login", func(t *testing.T) {
				body := testhelpers.SubmitLoginForm(t, false, c, ts, values,
					false, false, http.StatusSeeOther, ts.URL+"/self-service/methods/oidc/callback/valid",
					testhelpers.InitFlowWithReturnTo(webviewRedirectURI))

				assert.NotEmpty(t, gjson.Get(body, "session_token"), "%s", body)
				assert.Equal(t, successToken, gjson.Get(body, "session_token").String())
				assert.NotEmpty(t, gjson.Get(body, "session"), "%s", body)

				clientWithToken := http.Client{
					Transport: x.NewTransportWithHeader(http.Header{
						"Authorization": {"Bearer " + successToken},
					}),
				}

				var res *http.Response
				res, err = clientWithToken.Do(testhelpers.NewHTTPGetJSONRequest(t, ts.URL+session.RouteWhoami))
				assert.NoError(t, err)
				var b []byte
				b, err = io.ReadAll(res.Body)
				require.NoError(t, res.Body.Close())
				require.NoError(t, err)
				assert.Equal(t, true, gjson.GetBytes(b, "active").Bool(), "%s", b)

			})
		})

		t.Run("case=browser", func(t *testing.T) {
			subject = "register-then-login-browser@ory.sh"

			t.Run("case=should pass registration", func(t *testing.T) {
				r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
				action := afv(t, r.ID, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				ai(t, res, body)
				expectTokens(t, "valid", body)
				assert.Equal(t, "valid", gjson.GetBytes(body, "authentication_methods.0.provider").String(), "%s", body)
				assert.Equal(t, "", gjson.GetBytes(body, "identity.metadata_public.sso_groups.valid").String(), "%s", body)
			})

			t.Run("case=should pass login", func(t *testing.T) {
				r := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
				action := afv(t, r.ID, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				ai(t, res, body)
				expectTokens(t, "valid", body)
				assert.Equal(t, "valid", gjson.GetBytes(body, "authentication_methods.0.provider").String(), "%s", body)
				assert.Equal(t, `["group1","group2"]`, gjson.GetBytes(body, "identity.metadata_public.sso_groups.valid").String(), "%s", body)
			})
		})
	})

	t.Run("case=login without registered account", func(t *testing.T) {
		subject = "login-without-register@ory.sh"
		scope = []string{"openid"}

		t.Run("case=api should fail as user is not registered", func(t *testing.T) {
			err, tokens := getOauthTokens(t, remotePublic,
				validProviderConfig.ClientID,
				validProviderConfig.ClientSecret,
				testCallbackUrl)
			require.NoError(t, err)

			var values = func(v url.Values) {
				v.Set("method", "oidc")
				v.Set("provider", "valid")
				v.Set("id_token", tokens.IDToken)
			}

			body := testhelpers.SubmitLoginForm(t, true, nil, ts, values,
				false, false, http.StatusBadRequest, ts.URL+login.RouteSubmitFlow)

			assert.Equal(t, int(text.ErrorValidationOIDCUserNotFound), int(gjson.Get(body, "ui.messages.0.id").Int()), "%s", body)
		})

		t.Run("case=should pass login", func(t *testing.T) {
			t.Run("case=browser", func(t *testing.T) {
				flowId := newLoginFlowBrowser(t, returnTS.URL, time.Minute).ID
				action := afv(t, flowId, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				ai(t, res, body)
				assert.Equal(t, "valid", gjson.GetBytes(body, "authentication_methods.0.provider").String(), "%s", body)
			})
		})
	})

	t.Run("case=login without registered account with return_to", func(t *testing.T) {
		subject = "login-without-register-return-to@ory.sh"
		scope = []string{"openid"}
		returnTo := "/foo"

		t.Run("case=should pass login", func(t *testing.T) {
			r := newLoginFlow(t, fmt.Sprintf("%s?return_to=%s", returnTS.URL, returnTo), time.Minute, flow.TypeBrowser)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			assert.True(t, strings.HasSuffix(res.Request.URL.String(), returnTo))
			ai(t, res, body)
		})
	})

	t.Run("case=register and register again but login", func(t *testing.T) {
		subject = "register-twice@ory.sh"
		scope = []string{"openid"}

		t.Run("case=should pass registration", func(t *testing.T) {
			r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			ai(t, res, body)
		})

		t.Run("case=should pass second time registration", func(t *testing.T) {
			r := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			ai(t, res, body)
		})

		t.Run("case=should pass third time registration with return to", func(t *testing.T) {
			returnTo := "/foo"
			r := newLoginFlow(t, fmt.Sprintf("%s?return_to=%s", returnTS.URL, returnTo), time.Minute, flow.TypeBrowser)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			assert.True(t, strings.HasSuffix(res.Request.URL.String(), returnTo))
			ai(t, res, body)
		})
	})

	t.Run("case=register, merge, and complete data", func(t *testing.T) {
		subject = "incomplete-data@ory.sh"
		scope = []string{"openid"}
		claims = idTokenClaims{}
		claims.traits.website = "https://www.ory.sh/kratos"
		claims.traits.groups = []string{"group1", "group2"}
		claims.metadataPublic.picture = "picture.png"
		claims.metadataAdmin.phoneNumber = "911"

		t.Run("case=should fail registration on first attempt", func(t *testing.T) {
			r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{"traits.name": {"i"}})
			require.Contains(t, res.Request.URL.String(), uiTS.URL, "%s", body)

			assert.Equal(t, "length must be >= 2, but got 1", gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.name).messages.0.text").String(), "%s", body) // make sure the field is being echoed
			assert.Equal(t, "traits.name", gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.name).attributes.name").String(), "%s", body)                    // make sure the field is being echoed
			assert.Equal(t, "i", gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.name).attributes.value").String(), "%s", body)                             // make sure the field is being echoed
			assert.Equal(t, "https://www.ory.sh/kratos", gjson.GetBytes(body, "ui.nodes.#(attributes.name==traits.website).attributes.value").String(), "%s", body)  // make sure the field is being echoed
		})

		t.Run("case=should pass registration with valid data", func(t *testing.T) {
			r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{"traits.name": {"valid-name"}})
			ai(t, res, body)
			assert.Equal(t, "https://www.ory.sh/kratos", gjson.GetBytes(body, "identity.traits.website").String(), "%s", body)
			assert.Equal(t, "valid-name", gjson.GetBytes(body, "identity.traits.name").String(), "%s", body)
			assert.Equal(t, "[\"group1\",\"group2\"]", gjson.GetBytes(body, "identity.traits.groups").String(), "%s", body)
		})
	})

	t.Run("case=should fail to register if email is already being used by password credentials", func(t *testing.T) {
		subject = "email-exist-with-password-strategy@ory.sh"
		scope = []string{"openid"}

		cj, err := cookiejar.New(&cookiejar.Options{})
		require.NoError(t, err)
		webViewHTTPClient := &http.Client{
			Jar: cj,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if strings.HasSuffix(req.URL.Path, "/kerr") {
					assert.Equal(t, strconv.Itoa(int(text.ErrorValidationDuplicateCredentials)),
						req.URL.Query().Get("code"), "%s", req.URL.String())
					assert.Contains(t, req.URL.Query().Get("message"),
						"account with the same", "%s", req.URL.String())
					return http.ErrUseLastResponse
				}
				return nil
			},
		}

		var values = func(v url.Values) {
			v.Set("method", "oidc")
			v.Set("provider", "valid")
		}

		i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		i.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{
			Identifiers: []string{subject},
		})
		i.Traits = identity.Traits(`{"subject":"` + subject + `"}`)

		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), i))

		t.Run("case=should fail registration", func(t *testing.T) {
			t.Run("case=browser", func(t *testing.T) {
				r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
				action := afv(t, r.ID, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				aue(t, res, body, "An account with the same identifier (email, phone, username, ...) exists already.")
			})

			t.Run("case=webview", func(t *testing.T) {
				body := testhelpers.SubmitRegistrationForm(t, false, webViewHTTPClient, ts, values,
					false, http.StatusFound, ts.URL+"/self-service/methods/oidc/callback/valid",
					testhelpers.InitFlowWithReturnTo(webviewRedirectURI))

				assert.Empty(t, gjson.Get(body, "session_token"), "%s", body)
				assert.Empty(t, gjson.Get(body, "session"), "%s", body)
			})
		})

		t.Run("case=should fail login", func(t *testing.T) {
			t.Run("case=browser", func(t *testing.T) {
				r := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
				action := afv(t, r.ID, "valid")
				res, body := makeRequest(t, "valid", action, url.Values{})
				aue(t, res, body, "An account with the same identifier (email, phone, username, ...) exists already.")
			})

			t.Run("case=webview", func(t *testing.T) {
				body := testhelpers.SubmitLoginForm(t, false, webViewHTTPClient, ts, values,
					false, false, http.StatusFound, ts.URL+"/self-service/methods/oidc/callback/valid",
					testhelpers.InitFlowWithReturnTo(webviewRedirectURI))

				assert.Empty(t, gjson.Get(body, "session_token"), "%s", body)
				assert.Empty(t, gjson.Get(body, "session"), "%s", body)
			})
		})
	})

	t.Run("case=should redirect to default return ts when sending authenticated login flow without forced flag", func(t *testing.T) {
		subject = "no-reauth-login@ory.sh"
		scope = []string{"openid"}

		fv := url.Values{"traits.name": {"valid-name"}}
		jar, _ := cookiejar.New(nil)
		r1 := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
		res1, body1 := makeRequestWithCookieJar(t, "valid", afv(t, r1.ID, "valid"), fv, jar)
		ai(t, res1, body1)
		r2 := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
		res2, body2 := makeRequestWithCookieJar(t, "valid", afv(t, r2.ID, "valid"), fv, jar)
		ai(t, res2, body2)
		assert.Equal(t, body1, body2)
	})

	t.Run("case=should reauthenticate when sending authenticated login flow with forced flag", func(t *testing.T) {
		subject = "reauth-login@ory.sh"
		scope = []string{"openid"}

		fv := url.Values{"traits.name": {"valid-name"}}
		jar, _ := cookiejar.New(nil)
		r1 := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
		res1, body1 := makeRequestWithCookieJar(t, "valid", afv(t, r1.ID, "valid"), fv, jar)
		ai(t, res1, body1)
		r2 := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
		require.NoError(t, reg.LoginFlowPersister().ForceLoginFlow(context.Background(), r2.ID))
		res2, body2 := makeRequestWithCookieJar(t, "valid", afv(t, r2.ID, "valid"), fv, jar)
		ai(t, res2, body2)
		assert.NotEqual(t, gjson.GetBytes(body1, "id"), gjson.GetBytes(body2, "id"))
		authAt1, err := time.Parse(time.RFC3339, gjson.GetBytes(body1, "authenticated_at").String())
		require.NoError(t, err)
		authAt2, err := time.Parse(time.RFC3339, gjson.GetBytes(body2, "authenticated_at").String())
		require.NoError(t, err)
		// authenticated at is newer in the second body
		assert.Greater(t, authAt2.Sub(authAt1).Milliseconds(), int64(0), "%s - %s : %s - %s", authAt2, authAt1, body2, body1)
	})

	t.Run("case=registration should start new login flow if duplicate credentials detected", func(t *testing.T) {
		claims.traits.groups = []string{"group1", "group2"}

		loginWithOIDC := func(t *testing.T, c *http.Client, flowID uuid.UUID, provider string) (*http.Response, []byte) {
			action := afv(t, flowID, provider)
			res, err := c.PostForm(action, url.Values{"provider": {provider}})
			require.NoError(t, err, action)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, res.Body.Close())
			require.NoError(t, err)
			return res, body
		}

		stratNewLoginFlowForLinking := func(t *testing.T, c *http.Client, flowID uuid.UUID) *login.Flow {
			action := afv(t, flowID, "valid")
			res, err := c.PostForm(action, url.Values{"method": {node.LoginAndLinkCredentials}})
			require.NoError(t, err, action)
			body, err := io.ReadAll(res.Body)
			require.NoError(t, res.Body.Close())
			require.NoError(t, err)
			aue(t, res, body, "New credentials will be linked to existing account after login.")
			loginFlow, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), uuid.FromStringOrNil(gjson.GetBytes(body, "id").String()))
			assert.NotNil(t, loginFlow, "%s", body)
			return loginFlow
		}

		checkCredentialsLinked := func(res *http.Response, body []byte, identityID uuid.UUID, provider string) {
			assert.Contains(t, res.Request.URL.String(), returnTS.URL, "%s", body)
			assert.Equal(t, subject, gjson.GetBytes(body, "identity.traits.subject").String(), "%s", body)
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, identityID)
			require.NoError(t, err)
			assert.NotEmpty(t, i.Credentials["oidc"], "%+v", i.Credentials)
			assert.Equal(t, provider, gjson.GetBytes(i.Credentials["oidc"].Config, "providers.0.provider").String(),
				"%s", string(i.Credentials["oidc"].Config[:]))
			assert.NotEmpty(t, gjson.GetBytes(body, "authentication_methods.#(method==oidc).method"), "%s", body)
			assert.Equal(t, provider, gjson.GetBytes(body, "authentication_methods.#(method==oidc).provider").String(), "%s", body)
			assert.NotEmpty(t, gjson.GetBytes(i.MetadataPublic, "sso_groups."+provider+".#(==group1)"), "%s", i.MetadataPublic)
			assert.NotEmpty(t, gjson.GetBytes(i.MetadataPublic, "sso_groups."+provider+".#(==group2)"), "%s", i.MetadataPublic)
		}

		t.Run("case=second login is password", func(t *testing.T) {
			subject = "new-login-if-email-exist-with-password-strategy@ory.sh"
			subject2 := "new-login-subject2@ory.sh"
			scope = []string{"openid"}
			password := "lwkj52sdkjf"

			var i *identity.Identity
			t.Run("case=create password identity", func(t *testing.T) {
				i = identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
				p, err := reg.Hasher(ctx).Generate(ctx, []byte(password))
				require.NoError(t, err)
				i.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{
					Identifiers: []string{subject},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password":"` + string(p) + `"}`),
				})
				i.Traits = identity.Traits(`{"subject":"` + subject + `"}`)
				require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), i))

				i2 := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
				i2.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{
					Identifiers: []string{subject2},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password":"` + string(p) + `"}`),
				})
				i2.Traits = identity.Traits(`{"subject":"` + subject2 + `"}`)
				require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), i2))
			})

			c := testhelpers.NewClientWithCookieJar(t, nil, false)
			r := newLoginFlowBrowser(t, returnTS.URL, time.Minute)
			t.Run("case=should fail login", func(t *testing.T) {
				res, body := loginWithOIDC(t, c, r.ID, "valid")
				aue(t, res, body, "An account with the same identifier (email, phone, username, ...) exists already.")
				assert.Equal(t, node.LoginAndLinkCredentials, gjson.GetBytes(body, "ui.nodes.#(attributes.name==\"method\").attributes.value").String(), "%s", body)
			})

			var loginFlow *login.Flow
			t.Run("case=should start new login flow", func(t *testing.T) {
				loginFlow = stratNewLoginFlowForLinking(t, c, r.ID)
			})

			t.Run("case=should fail login if existing identity identifier doesn't match", func(t *testing.T) {
				res, err := c.PostForm(loginFlow.UI.Action, url.Values{
					"csrf_token": {loginFlow.CSRFToken},
					"method":     {"password"},
					"identifier": {subject2},
					"password":   {password}})
				require.NoError(t, err, loginFlow.UI.Action)
				body, err := io.ReadAll(res.Body)
				require.NoError(t, res.Body.Close())
				require.NoError(t, err)
				assert.Equal(t, strconv.Itoa(int(text.ErrorValidationLoginLinkedCredentialsDoNotMatch)), gjson.GetBytes(body, "ui.messages.0.id").String(), "%s", body)
			})

			t.Run("case=should link oidc credentials to existing identity", func(t *testing.T) {
				res, err := c.PostForm(loginFlow.UI.Action, url.Values{
					"csrf_token": {loginFlow.CSRFToken},
					"method":     {"password"},
					"identifier": {subject},
					"password":   {password}})
				require.NoError(t, err, loginFlow.UI.Action)
				body, err := io.ReadAll(res.Body)
				require.NoError(t, res.Body.Close())
				require.NoError(t, err)
				checkCredentialsLinked(res, body, i.ID, "valid")
			})
		})

		t.Run("case=second login is OIDC", func(t *testing.T) {
			email1 := "existing-oidc-identity-1@ory.sh"
			email2 := "existing-oidc-identity-2@ory.sh"
			scope = []string{"openid", "offline"}

			var identityID uuid.UUID
			t.Run("case=create OIDC identity", func(t *testing.T) {
				subject = email1
				r := newRegistrationFlow(t, returnTS.URL, time.Minute, flow.TypeBrowser)
				action := afv(t, r.ID, "secondProvider")
				res, body := makeRequest(t, "secondProvider", action, url.Values{})
				ai(t, res, body)
				identityID = expectTokens(t, "secondProvider", body)

				subject = email2
				r = newRegistrationFlow(t, returnTS.URL, time.Minute, flow.TypeBrowser)
				action = afv(t, r.ID, "valid")
				res, body = makeRequest(t, "valid", action, url.Values{})
				ai(t, res, body)
				expectTokens(t, "valid", body)
			})

			subject = email1
			c := testhelpers.NewClientWithCookieJar(t, nil, false)
			r := newLoginFlow(t, returnTS.URL, time.Minute, flow.TypeBrowser)
			t.Run("case=should fail login", func(t *testing.T) {
				res, body := loginWithOIDC(t, c, r.ID, "valid")
				aue(t, res, body, "An account with the same identifier (email, phone, username, ...) exists already.")
				assert.Equal(t, node.LoginAndLinkCredentials, gjson.GetBytes(body, "ui.nodes.#(attributes.name==\"method\").attributes.value").String(), "%s", body)
			})

			var loginFlow *login.Flow
			t.Run("case=should start new login flow", func(t *testing.T) {
				loginFlow = stratNewLoginFlowForLinking(t, c, r.ID)
			})

			subject = email2
			t.Run("case=should fail login if existing identity identifier doesn't match", func(t *testing.T) {
				res, body := loginWithOIDC(t, c, loginFlow.ID, "valid")
				aue(t, res, body, "Linked credentials do not match.")
			})

			subject = email1
			t.Run("case=should link oidc credentials to existing identity", func(t *testing.T) {
				res, body := loginWithOIDC(t, c, loginFlow.ID, "secondProvider")
				checkCredentialsLinked(res, body, identityID, "secondProvider")
			})
		})
	})

	t.Run("case=verified addresses should be respected", func(t *testing.T) {
		scope = []string{"openid"}

		testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration-verifiable-email.schema.json")

		var assertVerifiedEmail = func(t *testing.T, body []byte, verified bool) {
			assert.Len(t, gjson.GetBytes(body, "identity.verifiable_addresses").Array(), 1, "%s", body)
			assert.Equal(t, "email", gjson.GetBytes(body, "identity.verifiable_addresses.0.via").String(), "%s", body)
			assert.Equal(t, subject, gjson.GetBytes(body, "identity.verifiable_addresses.0.value").String(), "%s", body)
			assert.Equal(t, verified, gjson.GetBytes(body, "identity.verifiable_addresses.0.verified").Bool(), "%s", body)
		}

		t.Run("case=should have verified address when subject matches", func(t *testing.T) {
			subject = "verified-email@ory.sh"
			r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{})
			ai(t, res, body)
			assertVerifiedEmail(t, body, true)
		})

		t.Run("case=should have unverified address when subject does not match", func(t *testing.T) {
			subject = "changed-verified-email@ory.sh"
			r := newRegistrationFlowBrowser(t, returnTS.URL, time.Minute)
			action := afv(t, r.ID, "valid")
			res, body := makeRequest(t, "valid", action, url.Values{"traits.subject": {"unverified-email@ory.sh"}})
			subject = "unverified-email@ory.sh"
			ai(t, res, body)
			assertVerifiedEmail(t, body, false)
		})
	})

	t.Run("method=TestPopulateSignUpMethod", func(t *testing.T) {
		conf.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://foo/")

		sr, err := registration.NewFlow(conf, time.Minute, "nosurf", &http.Request{URL: urlx.ParseOrPanic("/")}, flow.TypeBrowser)
		require.NoError(t, err)
		require.NoError(t, reg.RegistrationStrategies(context.Background()).MustStrategy(identity.CredentialsTypeOIDC).(*oidc.Strategy).PopulateRegistrationMethod(&http.Request{}, sr))

		snapshotx.SnapshotTExcept(t, sr.UI, []string{"action", "nodes.0.attributes.value"})
	})

	t.Run("method=TestPopulateLoginMethod", func(t *testing.T) {
		conf.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://foo/")
		for k, flowType := range map[string]flow.Type{
			"api":     flow.TypeAPI,
			"browser": flow.TypeBrowser,
		} {
			t.Run(fmt.Sprintf("case=%s", k), func(t *testing.T) {

				sr, err := login.NewFlow(conf, time.Minute, "nosurf", &http.Request{URL: urlx.ParseOrPanic("/")}, flowType)
				require.NoError(t, err)
				require.NoError(t, reg.LoginStrategies(context.Background()).MustStrategy(identity.CredentialsTypeOIDC).(*oidc.Strategy).PopulateLoginMethod(&http.Request{}, identity.AuthenticatorAssuranceLevel1, sr))

				snapshotx.SnapshotTExcept(t, sr.UI, []string{"action", "nodes.0.attributes.value"})
			})
		}
	})
}

func TestCountActiveFirstFactorCredentials(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	strategy := oidc.NewStrategy(reg)

	toJson := func(c identity.CredentialsOIDC) []byte {
		out, err := json.Marshal(&c)
		require.NoError(t, err)
		return out
	}

	for k, tc := range []struct {
		in       identity.CredentialsCollection
		expected int
	}{
		{
			in: identity.CredentialsCollection{{
				Type:   strategy.ID(),
				Config: sqlxx.JSONRawMessage{},
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type: strategy.ID(),
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{""},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:"},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{":foo"},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"not-bar:foo"},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:not-foo"},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:foo"},
				Config: toJson(identity.CredentialsOIDC{Providers: []identity.CredentialsOIDCProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
			expected: 1,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			in := make(map[identity.CredentialsType]identity.Credentials)
			for _, v := range tc.in {
				in[v.Type] = v
			}
			actual, err := strategy.CountActiveFirstFactorCredentials(in)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDisabledEndpoint(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.StrategyEnable(t, conf, identity.CredentialsTypeOIDC.String(), false)

	publicTS, _ := testhelpers.NewKratosServer(t, reg)

	t.Run("case=should not callback when oidc method is disabled", func(t *testing.T) {
		c := testhelpers.NewClientWithCookies(t)
		res, err := c.Get(publicTS.URL + oidc.RouteCallback)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)

		b := ioutilx.MustReadAll(res.Body)
		assert.Contains(t, string(b), "This endpoint was disabled by system administrator")
	})

	t.Run("case=should not auth when oidc method is disabled", func(t *testing.T) {
		c := testhelpers.NewClientWithCookies(t)

		t.Run("flow=settings", func(t *testing.T) {
			testhelpers.SetDefaultIdentitySchema(conf, "file://stub/stub.schema.json")
			c := testhelpers.NewHTTPClientWithArbitrarySessionCookie(t, reg)
			f := testhelpers.InitializeSettingsFlowViaAPI(t, c, publicTS)

			res, err := c.PostForm(f.Ui.Action, url.Values{"link": {"oidc"}})
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, res.StatusCode)

			b := ioutilx.MustReadAll(res.Body)
			assert.Contains(t, string(b), "This endpoint was disabled by system administrator")
		})

		t.Run("flow=login", func(t *testing.T) {
			f := testhelpers.InitializeLoginFlowViaAPI(t, c, publicTS, false)
			res, err := c.PostForm(f.Ui.Action, url.Values{
				"method":   {"oidc"},
				"provider": {"valid"},
				"id_token": {"fake_token"}})
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, res.StatusCode)

			b := ioutilx.MustReadAll(res.Body)
			assert.Contains(t, string(b), "This endpoint was disabled by system administrator")
		})

		t.Run("flow=registration", func(t *testing.T) {
			f := testhelpers.InitializeRegistrationFlowViaAPI(t, c, publicTS)
			res, err := c.PostForm(f.Ui.Action, url.Values{
				"method":   {"oidc"},
				"provider": {"oidc"},
				"id_token": {"fake_token"}})
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, res.StatusCode)

			b := ioutilx.MustReadAll(res.Body)
			assert.Contains(t, string(b), "This endpoint was disabled by system administrator")
		})
	})
}

func TestPostEndpointRedirect(t *testing.T) {
	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
		subject   string
		claims    idTokenClaims
		scope     []string
	)
	testhelpers.StrategyEnable(t, conf, identity.CredentialsTypeOIDC.String(), true)

	remoteAdmin, remotePublic, _ := newHydra(t, &subject, &claims, &scope)

	publicTS, adminTS := testhelpers.NewKratosServers(t)

	viperSetProviderConfig(
		t,
		conf,
		newOIDCProvider(t, publicTS, remotePublic, remoteAdmin, "apple", "", nil),
	)
	testhelpers.InitKratosServers(t, reg, publicTS, adminTS)

	t.Run("case=should redirect to GET and preserve parameters"+publicTS.URL, func(t *testing.T) {
		// create a client that does not follow redirects
		c := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		res, err := c.PostForm(publicTS.URL+"/self-service/methods/oidc/callback/apple", url.Values{"state": {"foo"}, "test": {"3"}})
		require.NoError(t, err)
		defer res.Body.Close()
		assert.Equal(t, http.StatusFound, res.StatusCode)

		location, err := res.Location()
		require.NoError(t, err)
		assert.Equal(t, publicTS.URL+"/self-service/methods/oidc/callback/apple?state=foo&test=3", location.String())
	})
}

func TestProvidersHandler(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.StrategyEnable(t, conf, identity.CredentialsTypeOIDC.String(), true)

	// Start kratos server
	publicTS, adminTS := testhelpers.NewKratosServerWithCSRF(t, reg)

	var get = func(t *testing.T, base *httptest.Server, href string, expectCode int) gjson.Result {
		t.Helper()
		res, err := base.Client().Get(base.URL + href)
		require.NoError(t, err)
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())

		require.EqualValues(t, expectCode, res.StatusCode, "%s", body)
		return gjson.ParseBytes(body)
	}

	t.Run("case=should return an empty list", func(t *testing.T) {
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				parsed := get(t, ts, "/providers/oidc", http.StatusOK)
				require.True(t, parsed.IsArray(), "%s", parsed.Raw)
				assert.Len(t, parsed.Array(), 0)
			})
		}
	})

	t.Run("case=should return list containing two providers", func(t *testing.T) {
		viperSetProviderConfig(
			t,
			conf,
			oidc.Configuration{
				Provider:     "generic",
				ID:           "provider1",
				ClientID:     "clientID1",
				ClientSecret: "secret1",
				IssuerURL:    "https//:url1",
				Mapper:       "mapper1",
				PrivateKeyId: "ke1",
				PrivateKey:   "ke1-value",
			},
			oidc.Configuration{
				Provider:     "generic",
				ID:           "provider2",
				ClientID:     "clientID2",
				ClientSecret: "secret2",
				IssuerURL:    "https//:url2",
				Mapper:       "mapper2",
				PrivateKeyId: "ke1",
				PrivateKey:   "ke1-value",
			},
		)
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				parsed := get(t, ts, "/providers/oidc", http.StatusOK)
				require.True(t, parsed.IsArray(), "%s", parsed.Raw)
				assert.Len(t, parsed.Array(), 2)
				assert.Equal(t, "provider1", parsed.Array()[0].Get("id").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("client_secret").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("apple_private_key").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("apple_private_key_id").String(), "%s", parsed.Array()[0].Raw)
			})
		}
	})

	t.Run("case=should fetch providers from external source", func(t *testing.T) {
		viperSetProvidersRequestConfig(
			t,
			conf,
			&oidc.ConfigurationCollection{
				ProvidersRequestConfig: json.RawMessage(
					`{
						"url": "https://example.com/identity/providers/oidc",
						"method": "GET",
						"auth": {
							"type": "api_key",
							"config": {
								"name": "Authorization",
								"value": "token",
								"in": "header"
							}
						}
					}`,
				),
			},
		)
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		httpmock.RegisterResponder("GET", "https://example.com/identity/providers/oidc",
			func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, json.RawMessage(
					`[{"id": "provider1", "provider": "generic", "client_secret": "secret1"}, {"id": "provider2", "provider": "generic", "client_secret": "secret1"}]`))
			},
		)
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				parsed := get(t, ts, "/providers/oidc", http.StatusOK)
				require.True(t, parsed.IsArray(), "%s", parsed.Raw)
				assert.Len(t, parsed.Array(), 2)
				assert.Equal(t, "provider1", parsed.Array()[0].Get("id").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("client_secret").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("apple_private_key").String(), "%s", parsed.Array()[0].Raw)
				assert.Equal(t, "", parsed.Array()[0].Get("apple_private_key_id").String(), "%s", parsed.Array()[0].Raw)
			})
		}
	})
}
