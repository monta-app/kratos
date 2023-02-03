package saml_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/assertx"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/urlx"
	"github.com/tidwall/gjson"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/x/sqlxx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gotest "gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestStrategy(t *testing.T) {
	ctx := context.Background()
	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
		email     string
	)

	returnTS := newReturnTs(t, reg)
	conf.MustSet(ctx, config.ViperKeyURLsAllowedReturnToDomains, []string{returnTS.URL})

	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	errTS := testhelpers.NewErrorTestServer(t, reg)
	conf.MustSet(ctx, config.ViperKeySelfServiceErrorUI, errTS.URL+"/error-ts")
	uiTS := newUI(t, reg)

	providerId := "TestStrategyProvider"
	urlAcs := ts.URL + saml.RouteBaseAcs + "/" + providerId
	remoteIDP := newIDP(t, ts.URL+saml.RouteBaseMetadata+"/"+providerId, urlAcs)

	webviewRedirectURI := ts.URL + "/self-service/oidc/webview"

	ViperSetProviderConfig(t, conf,
		saml.Configuration{
			ID:             providerId,
			Provider:       "generic",
			Label:          "SAML IdP 1",
			PublicCertPath: "file://./testdata/cert.pem",
			PrivateKeyPath: "file://./testdata/key.pem",
			AttributesMap:  map[string]string{"id": "uid", "email": "email"},
			IDPInformation: map[string]string{"idp_metadata_url": remoteIDP + "/simplesaml/saml2/idp/metadata.php"},
			Mapper:         "file://./testdata/saml.jsonnet",
		})

	conf.MustSet(ctx, config.ViperKeySelfServiceRegistrationEnabled, true)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/registration.schema.json")
	conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})
	conf.MustSet(ctx, config.ViperKeySelfServiceWebViewRedirectURL, webviewRedirectURI)

	// assert identity (success)
	var ai = func(t *testing.T, res *http.Response, body []byte) {
		assert.Contains(t, res.Request.URL.String(), returnTS.URL)
		assert.Equal(t, email, gjson.GetBytes(body, "identity.traits.email").String(), "%s", body)
	}

	// assert ui error
	var aue = func(t *testing.T, res *http.Response, body []byte, reason string) {
		require.Contains(t, res.Request.URL.String(), uiTS.URL, "status: %d, body: %s", res.StatusCode, body)
		assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(), reason, "%s", body)
		assert.Contains(t, gjson.GetBytes(body, "ui.action").String(), "self-service/login", "%s", body)
	}

	var newLoginFlow = func(t *testing.T, requestURL string, returnToURL string, exp time.Duration) (f *login.Flow) {
		// Use NewLoginFlow to instantiate the request but change the things we need to control a copy of it.
		rURL := urlx.ParseOrPanic(requestURL)
		q := rURL.Query()
		q.Set("return_to", returnToURL)
		rURL.RawQuery = q.Encode()
		f, _, err := reg.LoginHandler().NewLoginFlow(httptest.NewRecorder(),
			&http.Request{URL: rURL}, flow.TypeBrowser)
		require.NoError(t, err)
		f.RequestURL = rURL.String()
		f.ReturnTo = returnToURL
		f.ExpiresAt = time.Now().Add(exp)
		require.NoError(t, reg.LoginFlowPersister().UpdateLoginFlow(context.Background(), f))

		// sanity check
		got, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), f.ID)
		require.NoError(t, err)

		require.Len(t, got.UI.Nodes, len(f.UI.Nodes), "%+v", got)

		return
	}

	// assert form values
	var afv = func(t *testing.T, flowID uuid.UUID, provider string) (action string) {
		var conf *container.Container
		if req, err := reg.RegistrationFlowPersister().GetRegistrationFlow(context.Background(), flowID); err == nil {
			require.EqualValues(t, req.ID, flowID)
			conf = req.UI
			require.NotNil(t, conf)
		} else if req, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), flowID); err == nil {
			require.EqualValues(t, req.ID, flowID)
			conf = req.UI
			require.NotNil(t, conf)
		} else {
			require.NoError(t, err)
			return
		}

		assert.Equal(t, "POST", conf.Method)

		var found bool
		for _, field := range conf.Nodes {
			if strings.Contains(field.ID(), "samlProvider") && field.GetValue() == provider {
				found = true
				break
			}
		}
		require.True(t, found, "%+v", assertx.PrettifyJSONPayload(t, conf))

		return conf.Action
	}

	var makeRequestWithClient = func(t *testing.T, action string, fv url.Values, client *http.Client, statusCode int) (*http.Response, []byte) {
		if client == nil {
			client = NewTestClient(t, nil)
		}

		res, err := client.PostForm(action, fv)
		require.NoError(t, err, action)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, statusCode, res.StatusCode, "%s: %s\n\t%s", action, res.Request.URL.String(), body)

		return res, body
	}

	var getValueByName = func(body []byte, name string) string {
		doc, err := html.Parse(strings.NewReader(string(body)))
		require.NoError(t, err, body)

		node := traverse(doc, name)
		require.NotNil(t, node)
		result, ok := getAttribute(node, "value")
		require.True(t, ok)

		return result
	}

	t.Run("case=should fail because provider does not exist", func(t *testing.T) {
		t.Run("case=browser", func(t *testing.T) {
			f := newLoginFlow(t, returnTS.URL, "", time.Minute)
			action := afv(t, f.ID, providerId)

			client := NewTestClient(t, nil)

			//Post to kratos to initiate SAML flow
			resp, body := makeRequestWithClient(t, action, url.Values{
				"method":       []string{"saml"},
				"samlProvider": []string{"does-not-exist"},
			}, client, 200)
			assert.Contains(t, resp.Request.URL.String(), uiTS.URL, "%s", body)

			flowWithError, err := reg.LoginFlowPersister().GetLoginFlow(context.Background(), f.ID)
			assert.NoError(t, err)

			assert.Contains(t, flowWithError.UI.Nodes.Find("samlProvider").Messages[0].Text, "is unknown")
		})

		t.Run("case=webview", func(t *testing.T) {
			f := newLoginFlow(t, returnTS.URL, webviewRedirectURI, time.Minute)
			action := afv(t, f.ID, providerId)

			cj, err := cookiejar.New(&cookiejar.Options{})
			require.NoError(t, err)
			client := &http.Client{
				Jar: cj,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if strings.HasSuffix(req.URL.Path, "/kerr") {
						assert.Equal(t, strconv.Itoa(int(text.ErrorValidationSAMLProviderNotFound)), req.URL.Query().Get("code"), "%s", req.URL.String())
						return http.ErrUseLastResponse
					}
					return nil
				},
			}

			//Post to kratos to initiate SAML flow
			res, _ := makeRequestWithClient(t, action, url.Values{
				"method":       []string{"saml"},
				"samlProvider": []string{"does-not-exist"},
			}, client, 303)
			location, err := res.Location()
			assert.NoError(t, err)
			assert.True(t, strings.HasSuffix(location.Path, "/kerr"), "%v", res)
		})
	})

	t.Run("case=login without registered account and then login again", func(t *testing.T) {
		t.Run("case=browser", func(t *testing.T) {
			email = "user1@example.com"

			doLogin := func(t *testing.T) {
				f := newLoginFlow(t, returnTS.URL, "", time.Minute)
				action := afv(t, f.ID, providerId)

				client := NewTestClient(t, nil)

				//Post to kratos to initiate SAML flow
				res, body := makeRequestWithClient(t, action, url.Values{
					"method":       []string{"saml"},
					"samlProvider": []string{providerId},
				}, client, 200)

				//Post to identity provider UI
				res, body = makeRequestWithClient(t, res.Request.URL.String(), url.Values{
					"username": []string{"user1"},
					"password": []string{"user1pass"},
				}, client, 200)

				//Extract SAML response from body returned by identity provider
				SAMLResponse := getValueByName(body, "SAMLResponse")
				relayState := getValueByName(body, "RelayState")

				//Post SAML response to kratos
				res, body = makeRequestWithClient(t, urlAcs, url.Values{
					"SAMLResponse": []string{SAMLResponse},
					"RelayState":   []string{relayState},
				}, client, 200)

				ai(t, res, body)
				assert.Equal(t, providerId, gjson.GetBytes(body, "authentication_methods.0.provider").String(), "%s", body)
			}

			doLogin(t)
			doLogin(t)
		})

		t.Run("case=webview", func(t *testing.T) {
			email = "user2@example.com"

			doLogin := func(t *testing.T) {
				f := newLoginFlow(t, returnTS.URL, webviewRedirectURI, time.Minute)
				action := afv(t, f.ID, providerId)

				cj, err := cookiejar.New(&cookiejar.Options{})
				require.NoError(t, err)
				client := &http.Client{
					Jar: cj,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						if strings.HasSuffix(req.URL.Path, "/success") {
							assert.True(t, req.URL.Query().Has("session_token"))
							return http.ErrUseLastResponse
						}
						return nil
					},
				}

				//Post to kratos to initiate SAML flow
				res, body := makeRequestWithClient(t, action, url.Values{
					"method":       []string{"saml"},
					"samlProvider": []string{providerId},
				}, client, 200)

				//Post to identity provider UI
				res, body = makeRequestWithClient(t, res.Request.URL.String(), url.Values{
					"username": []string{"user2"},
					"password": []string{"user2pass"},
				}, client, 200)

				//Extract SAML response from body returned by identity provider
				SAMLResponse := getValueByName(body, "SAMLResponse")
				relayState := getValueByName(body, "RelayState")

				//Post SAML response to kratos
				res, body = makeRequestWithClient(t, urlAcs, url.Values{
					"SAMLResponse": []string{SAMLResponse},
					"RelayState":   []string{relayState},
				}, client, 303)

				location, err := res.Location()
				assert.NoError(t, err)
				assert.True(t, strings.HasSuffix(location.Path, "/success"), "%v", res)
				token := location.Query().Get("session_token")
				assert.Equal(t, gjson.GetBytes(body, "session_token").String(), token)
				assert.Equal(t, email, gjson.GetBytes(body, "session.identity.traits.email").String(), "%s", body)
				assert.Equal(t, providerId, gjson.GetBytes(body, "session.authentication_methods.0.provider").String(), "%s", body)

				clientWithToken := http.Client{
					Transport: x.NewTransportWithHeader(http.Header{
						"Authorization": {"Bearer " + token},
					}),
				}

				res, err = clientWithToken.Do(testhelpers.NewHTTPGetJSONRequest(t, ts.URL+session.RouteWhoami))
				assert.NoError(t, err)
				body, err = io.ReadAll(res.Body)
				require.NoError(t, res.Body.Close())
				require.NoError(t, err)
				assert.Equal(t, true, gjson.GetBytes(body, "active").Bool(), "%s", body)
			}

			doLogin(t)
			doLogin(t)
		})
	})

	t.Run("case=registration should start new login flow if duplicate credentials detected", func(t *testing.T) {
		email = "user1@example.com"
		password := "lwkj52sdkjf"
		var i *identity.Identity

		createPasswordIdentity := func(t *testing.T) {
			var err error
			i, _, err = reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(
				context.Background(),
				identity.CredentialsTypePassword,
				email,
			)
			if err != nil && !errors.Is(err, sqlcon.ErrNoRows) {
				assert.NoError(t, err)
			}
			if i != nil {
				err := reg.PrivilegedIdentityPool().DeleteIdentity(context.Background(), i.ID)
				assert.NoError(t, err)
			}
			i = identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
			p, err := reg.Hasher(ctx).Generate(ctx, []byte(password))
			i.SetCredentials(identity.CredentialsTypePassword, identity.Credentials{
				Identifiers: []string{email},
				Config:      sqlxx.JSONRawMessage(`{"hashed_password":"` + string(p) + `"}`),
			})
			i.Traits = identity.Traits(`{"email":"` + email + `"}`)

			require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), i))
		}

		startFlowAndTryToLogin := func(t *testing.T, c *http.Client, returnToURL string, statusCode int) (*http.Response, []byte, *login.Flow) {
			f := newLoginFlow(t, returnTS.URL, returnToURL, time.Minute)
			action := afv(t, f.ID, providerId)

			//Post to kratos to initiate SAML flow
			res, body := makeRequestWithClient(t, action, url.Values{
				"method":       []string{"saml"},
				"samlProvider": []string{providerId},
			}, c, 200)

			//Post to identity provider UI
			res, body = makeRequestWithClient(t, res.Request.URL.String(), url.Values{
				"username": []string{"user1"},
				"password": []string{"user1pass"},
			}, c, 200)

			//Extract SAML response from body returned by identity provider
			SAMLResponse := getValueByName(body, "SAMLResponse")
			relayState := getValueByName(body, "RelayState")

			//Post SAML response to kratos
			res, body = makeRequestWithClient(t, urlAcs, url.Values{
				"SAMLResponse": []string{SAMLResponse},
				"RelayState":   []string{relayState},
			}, c, statusCode)
			return res, body, f
		}

		checkCredentialsLinked := func(t *testing.T, isAPI bool, identityID uuid.UUID, body string) {
			identityConfidential, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, identityID)
			require.NoError(t, err)
			assert.NotEmpty(t, identityConfidential.Credentials["saml"], "%+v", identityConfidential.Credentials)
			assert.Equal(t, "TestStrategyProvider", gjson.GetBytes(identityConfidential.Credentials["saml"].Config,
				"providers.0.samlProvider").String(),
				"%s", string(identityConfidential.Credentials["saml"].Config[:]))
			path := ""
			if isAPI {
				path = "session.authentication_methods"
			} else {
				path = "authentication_methods"
			}
			assert.Contains(t, gjson.Get(body, path).String(), "saml", "%s", body)
		}

		t.Run("case=browser", func(t *testing.T) {
			createPasswordIdentity(t)
			c := NewTestClient(t, nil)
			var flowID uuid.UUID
			t.Run("case=should fail login", func(t *testing.T) {
				res, body, _ := startFlowAndTryToLogin(t, c, "", 200)

				aue(t, res, body, "An account with the same identifier (email, phone, username, ...) exists already.")
				assert.NotEmpty(t, gjson.GetBytes(body,
					fmt.Sprintf("ui.nodes.#(attributes.value==\"%s\")",
						node.LoginAndLinkCredentials)).String(),
					"%s", body)
				flowID, _ = uuid.FromString(gjson.GetBytes(body, "id").String())
			})

			var loginFlow *login.Flow

			t.Run("case=should start new browser login flow", func(t *testing.T) {
				action := afv(t, flowID, providerId)

				res, body := makeRequestWithClient(t, action, url.Values{
					"method": []string{node.LoginAndLinkCredentials},
				}, c, 200)
				require.Contains(t, res.Request.URL.String(), uiTS.URL, "status: %d, body: %s", res.StatusCode, body)
				assert.Contains(t, gjson.GetBytes(body, "ui.messages.0.text").String(),
					"New credentials will be linked to existing account after login.", "%s", body)
				loginFlow, _ = reg.LoginFlowPersister().GetLoginFlow(context.Background(), uuid.FromStringOrNil(gjson.GetBytes(body, "id").String()))
				assert.NotNil(t, loginFlow, "%s", body)
			})

			t.Run("case=should link saml credentials to existing identity", func(t *testing.T) {
				res, body := makeRequestWithClient(t, loginFlow.UI.Action, url.Values{
					"csrf_token": {loginFlow.CSRFToken},
					"method":     {"password"},
					"identifier": {email},
					"password":   {password},
				}, c, 200)
				assert.Contains(t, res.Request.URL.String(), returnTS.URL, "%s", body)
				assert.Equal(t, email, gjson.GetBytes(body, "identity.traits.email").String(), "%s", body)

				checkCredentialsLinked(t, false, i.ID, string(body))
			})
		})

		t.Run("case=webview", func(t *testing.T) {
			createPasswordIdentity(t)

			cj, err := cookiejar.New(&cookiejar.Options{})
			require.NoError(t, err)
			client := &http.Client{
				Jar: cj,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if strings.HasSuffix(req.URL.Path, "/kerr") {
						assert.Equal(t, strconv.Itoa(int(text.ErrorValidationDuplicateCredentials)), req.URL.Query().Get("code"), "%s", req.URL.String())
						return http.ErrUseLastResponse
					}
					return nil
				},
			}

			var linkCredentialsFlow *login.Flow
			t.Run("case=should fail login", func(t *testing.T) {
				res, _, f := startFlowAndTryToLogin(t, client, webviewRedirectURI, 303)
				location, err := res.Location()
				assert.NoError(t, err)
				assert.True(t, strings.HasSuffix(location.Path, "/kerr"), "%v", res)
				assert.Equal(t, f.ID.String(), location.Query().Get("flow"), "%s", location)
				linkCredentialsFlow = f
			})

			t.Run("case=should start new api login flow and link saml credentials to existing identity", func(t *testing.T) {
				var values = func(v url.Values) {
					v.Set("identifier", email)
					v.Set("password", password)
					v.Set("linkCredentialsFlow", linkCredentialsFlow.ID.String())
				}
				body := testhelpers.SubmitLoginForm(t, true, nil, ts, values,
					false, false, http.StatusOK, ts.URL+login.RouteSubmitFlow)
				assert.Equal(t, email, gjson.Get(body, "session.identity.traits.email").String(), "%s", body)
				st := gjson.Get(body, "session_token").String()
				assert.NotEmpty(t, st, "%s", body)

				checkCredentialsLinked(t, true, i.ID, body)
			})
		})
	})
}

func TestGetAndDecryptAssertion(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, middleware, _, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	assertion, err := GetAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)

	require.NoError(t, err)
	gotest.Check(t, assertion != nil)
}

func TestGetAttributesFromAssertion(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, middleware, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	assertion, _ := GetAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)

	mapAttributes, err := strategy.GetAttributesFromAssertion(assertion)

	require.NoError(t, err)
	gotest.Check(t, mapAttributes["urn:oid:0.9.2342.19200300.100.1.1"][0] == "myself")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"][0] == "Member")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"][1] == "Staff")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"][0] == "myself@testshib.org")
	gotest.Check(t, mapAttributes["urn:oid:2.5.4.4"][0] == "And I")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"][0] == "Member@testshib.org")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.9"][1] == "Staff@testshib.org")
	gotest.Check(t, mapAttributes["urn:oid:2.5.4.42"][0] == "Me Myself")
	gotest.Check(t, mapAttributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.7"][0] == "urn:mace:dir:entitlement:common-lib-terms")
	gotest.Check(t, mapAttributes["urn:oid:2.5.4.3"][0] == "Me Myself And I")
	gotest.Check(t, mapAttributes["urn:oid:2.5.4.20"][0] == "555-5555")

	t.Log(mapAttributes)
}

func TestCreateAuthRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, middleware, _, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	authReq, err := middleware.ServiceProvider.MakeAuthenticationRequest("https://samltest.id/idp/profile/SAML2/Redirect/SSO", "saml.HTTPPostBinding", "saml.HTTPPostBinding")
	require.NoError(t, err)

	matchACS, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/acs`, authReq.AssertionConsumerServiceURL)
	require.NoError(t, err)
	gotest.Check(t, matchACS)

	matchMetadata, err := regexp.MatchString(`http://127.0.0.1:\d{5}/self-service/methods/saml/metadata`, authReq.Issuer.Value)
	require.NoError(t, err)
	gotest.Check(t, matchMetadata)

	gotest.Check(t, is.Equal(authReq.Destination, "https://samltest.id/idp/profile/SAML2/Redirect/SSO"))
}

func TestProvider(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, _, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	provider, err := strategy.Provider(context.Background(), "samlProvider")
	require.NoError(t, err)
	gotest.Check(t, provider != nil)
	gotest.Check(t, provider.Config().ID == "samlProvider")
	gotest.Check(t, provider.Config().Label == "samlProviderLabel")
}

func TestConfig(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, _, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	cfg, err := strategy.Config(context.Background())
	require.NoError(t, err)
	gotest.Check(t, cfg != nil)
	gotest.Check(t, len(cfg.SAMLProviders) == 1)
	gotest.Check(t, cfg.SAMLProviders[0].ID == "samlProvider")
	gotest.Check(t, cfg.SAMLProviders[0].Label == "samlProviderLabel")
}

func TestID(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, _, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	id := strategy.ID()
	gotest.Check(t, id == "saml")
}

func TestCountActiveCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, _, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	mapCredentials := make(map[identity.CredentialsType]identity.Credentials)

	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(identity.CredentialsSAML{
		Providers: []identity.CredentialsSAMLProvider{
			{
				Subject:  "testUserID",
				Provider: "saml",
			}},
	})
	require.NoError(t, err)

	mapCredentials[identity.CredentialsTypeSAML] = identity.Credentials{
		Type:        identity.CredentialsTypeSAML,
		Identifiers: []string{"saml:testUserID"},
		Config:      b.Bytes(),
	}

	count, err := strategy.CountActiveCredentials(mapCredentials)
	require.NoError(t, err)
	gotest.Check(t, count == 1)
}

func TestGetRegistrationIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	_, middleware, strategy, _, _ := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	provider, _ := strategy.Provider(context.Background(), "samlProvider")
	assertion, _ := GetAndDecryptAssertion(t, "./testdata/SP_SamlResponse.xml", middleware.ServiceProvider.Key)
	attributes, _ := strategy.GetAttributesFromAssertion(assertion)
	claims, _ := provider.Claims(context.Background(), strategy.D().Config(), attributes, "samlProvider")

	i, err := strategy.GetRegistrationIdentity(nil, context.Background(), provider, claims, false)
	require.NoError(t, err)
	gotest.Check(t, i != nil)
}

func TestCountActiveFirstFactorCredentials(t *testing.T) {
	_, reg := internal.NewFastRegistryWithMocks(t)
	strategy := saml.NewStrategy(reg)

	toJson := func(c identity.CredentialsSAML) []byte {
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
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{""},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:"},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{":foo"},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"not-bar:foo"},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:not-foo"},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
					{Subject: "foo", Provider: "bar"},
				}}),
			}},
		},
		{
			in: identity.CredentialsCollection{{
				Type:        strategy.ID(),
				Identifiers: []string{"bar:foo"},
				Config: toJson(identity.CredentialsSAML{Providers: []identity.CredentialsSAMLProvider{
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

func TestModifyIdentityTraits(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

}

func TestProvidersHandler(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.StrategyEnable(t, conf, identity.CredentialsTypeSAML.String(), true)

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
				parsed := get(t, ts, "/providers/saml", http.StatusOK)
				require.True(t, parsed.IsArray(), "%s", parsed.Raw)
				assert.Len(t, parsed.Array(), 0)
			})
		}
	})

	t.Run("case=should return list containing two providers", func(t *testing.T) {
		viperSetProviderConfig(
			t,
			conf,
			saml.Configuration{
				Provider: "generic",
				ID:       "provider1",
				Mapper:   "mapper1",
			},
			saml.Configuration{
				Provider: "generic",
				ID:       "provider2",
				Mapper:   "mapper2",
			},
		)
		for name, ts := range map[string]*httptest.Server{"public": publicTS, "admin": adminTS} {
			t.Run("endpoint="+name, func(t *testing.T) {
				parsed := get(t, ts, "/providers/saml", http.StatusOK)
				require.True(t, parsed.IsArray(), "%s", parsed.Raw)
				assert.Len(t, parsed.Array(), 2)
				assert.Equal(t, "provider1", parsed.Array()[0].Get("id").String(), "%s", parsed.Array()[0].Raw)
			})
		}
	})

}