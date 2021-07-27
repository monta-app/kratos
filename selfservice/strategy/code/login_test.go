package code_test

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	kratos "github.com/ory/kratos-client-go"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/x"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlxx"
)

func newReturnTs(t *testing.T, reg interface {
	session.ManagementProvider
	x.WriterProvider
	config.Provider
}) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := reg.SessionManager().FetchFromRequest(r.Context(), r)
		require.NoError(t, err)
		reg.Writer().Write(w, r, sess)
	}))
	t.Cleanup(ts.Close)
	reg.Config(context.Background()).MustSet(config.ViperKeySelfServiceBrowserDefaultReturnTo, ts.URL+"/return-ts")
	return ts
}

func checkFormContent(t *testing.T, body []byte, requiredFields ...string) {
	fieldNameSet(t, body, requiredFields)
	formMethodIsPOST(t, body)
}

// fieldNameSet checks if the fields have the right "name" set.
func fieldNameSet(t *testing.T, body []byte, fields []string) {
	for _, f := range fields {
		assert.Equal(t, f, gjson.GetBytes(body, fmt.Sprintf("ui.nodes.#(attributes.name==%s).attributes.name", f)).String(), "%s", body)
	}
}

func formMethodIsPOST(t *testing.T, body []byte) {
	assert.Equal(t, "POST", gjson.GetBytes(body, "ui.method").String())
}

func TestStrategy_Login(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	reg.WithRandomCodeGenerator(&randomCodeGeneratorStub{code: "0000"})
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeCode)+".enabled", true)
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypePassword)+".enabled", false)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/default.schema.json")
	conf.MustSet(config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")
	conf.MustSet(config.CodeMaxAttempts, 5)
	conf.MustSet(config.CodeLifespan, "1h")

	publicTS, _ := testhelpers.NewKratosServer(t, reg)
	redirTS := newReturnTs(t, reg)

	uiTS := testhelpers.NewLoginUIFlowEchoServer(t, reg)

	conf.MustSet(config.ViperKeySelfServiceLoginUI, uiTS.URL+"/login-ts")

	var expectValidationError = func(t *testing.T, isAPI, forced, isSPA bool, values func(url.Values)) string {
		return testhelpers.SubmitLoginForm(t, isAPI, nil, publicTS, values,
			isSPA, forced,
			testhelpers.ExpectStatusCode(isAPI || isSPA, http.StatusBadRequest, http.StatusOK),
			testhelpers.ExpectURL(isAPI || isSPA, publicTS.URL+login.RouteSubmitFlow, conf.SelfServiceFlowLoginUI().String()),
		)
	}

	createIdentity := func(identifier string) (error, *identity.Identity) {
		stateChangedAt := sqlxx.NullTime(time.Now())

		i := &identity.Identity{
			SchemaID:       "default",
			Traits:         identity.Traits(fmt.Sprintf(`{"phone":"%s"}`, identifier)),
			State:          identity.StateActive,
			StateChangedAt: &stateChangedAt}
		if err := reg.IdentityManager().Create(context.Background(), i); err != nil {
			return err, nil
		}

		return nil, i
	}

	t.Run("should return an error because no phone is set", func(t *testing.T) {
		var check = func(t *testing.T, body string) {
			assert.NotEmpty(t, gjson.Get(body, "id").String(), "%s", body)
			assert.Contains(t, gjson.Get(body, "ui.action").String(), publicTS.URL+login.RouteSubmitFlow, "%s", body)

			assert.Equal(t, "Property identifier is missing.",
				gjson.Get(body, "ui.nodes.#(attributes.name==identifier).messages.0.text").String(), "%s", body)

			// The code value should not be returned!
			assert.Empty(t, gjson.Get(body, "ui.nodes.#(attributes.name==code).attributes.value").String())
		}

		t.Run("type=api", func(t *testing.T) {
			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Del("identifier")
			}

			check(t, expectValidationError(t, true, false, false, values))
		})
	})

	var loginWithPhone = func(t *testing.T, isAPI, refresh, isSPA bool,
		expectedStatusCode int, expectedURL string,
		values func(url.Values)) string {
		f := testhelpers.InitializeLoginFlow(t, isAPI, nil, publicTS, false, false)

		assert.Empty(t, getLoginNode(f, "code"))
		assert.NotEmpty(t, getLoginNode(f, "identifier"))

		body := testhelpers.SubmitLoginFormWithFlow(t, isAPI, nil, values,
			false, http.StatusOK,
			testhelpers.ExpectURL(isAPI || isSPA, publicTS.URL+login.RouteSubmitFlow, conf.SelfServiceFlowLoginUI().String()),
			f)

		assert.Equal(t,
			errorsx.Cause(code.NewCodeSentError()).(code.CodeSentError).ValidationError.Messages[0].Text,
			gjson.Get(body, "ui.messages.0.text").String(),
			"%s", body,
		)
		assert.NotEmpty(t, gjson.Get(body, "ui.nodes.#(attributes.name==code)"), "%s", body)
		assert.Empty(t, gjson.Get(body, "ui.nodes.#(attributes.name==code).attirbutes.value"), "%s", body)

		st := gjson.Get(body, "session_token").String()
		assert.Empty(t, st, "Response body: %s", body) //No session token as we have not presented the code yet

		values = func(v url.Values) {
			if isAPI {
				v.Set("method", "code")
			}
			v.Set("code", "0000")
		}

		body = testhelpers.SubmitLoginFormWithFlow(t, isAPI, nil, values, false, expectedStatusCode, expectedURL, f)

		return body
	}

	t.Run("should not send code as user was not registered", func(t *testing.T) {

		var check = func(t *testing.T, body string) {
			assert.NotEmpty(t, gjson.Get(body, "id").String(), "%s", body)
			assert.Contains(t, gjson.Get(body, "ui.action").String(), publicTS.URL+login.RouteSubmitFlow, "%s", body)
			assert.Equal(t, text.NewErrorValidationInvalidCode().Text, gjson.Get(body, "ui.messages.0.text").String(), body)
		}

		t.Run("type=api", func(t *testing.T) {
			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("identifier", "+99999999999")
			}

			check(t, loginWithPhone(t, true, false, false,
				http.StatusBadRequest,
				publicTS.URL+login.RouteSubmitFlow,
				values))
		})
		t.Run("type=browser", func(t *testing.T) {
			var values = func(v url.Values) {
				v.Set("identifier", "+99999999999")
			}

			check(t, loginWithPhone(t, false, false, false,
				http.StatusOK,
				conf.SelfServiceFlowLoginUI().String(),
				values))
		})
	})

	t.Run("should pass with registered user", func(t *testing.T) {
		identifier := fmt.Sprintf("+45%s", fmt.Sprint(rand.Int())[0:8])
		conf.MustSet(config.CodeTestNumbers, []string{identifier})
		err, createdIdentity := createIdentity(identifier)
		assert.NoError(t, err)

		var values = func(v url.Values) {
			v.Set("method", "code")
			v.Set("identifier", identifier)
		}

		t.Run("type=api", func(t *testing.T) {
			body := loginWithPhone(t, true, false, false, http.StatusOK, publicTS.URL+login.RouteSubmitFlow, values)
			assert.Equal(t, identifier, gjson.Get(body, "session.identity.traits.phone").String(), "%s", body)
			assert.NotEmpty(t, gjson.Get(body, "session_token").String(), "%s", body)
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), createdIdentity.ID)
			assert.NoError(t, err)
			assert.NotEmpty(t, i.VerifiableAddresses, "%s", body)
			assert.Equal(t, identifier, i.VerifiableAddresses[0].Value)
			assert.True(t, i.VerifiableAddresses[0].Verified)

			assert.Equal(t, identifier, gjson.Get(body, "session.identity.verifiable_addresses.0.value").String())
			assert.Equal(t, "true", gjson.Get(body, "session.identity.verifiable_addresses.0.verified").String())
		})
		t.Run("type=browser", func(t *testing.T) {
			body := loginWithPhone(t, false, false, false, http.StatusOK, redirTS.URL, values)
			assert.Equal(t, identifier, gjson.Get(body, "identity.traits.phone").String(), "%s", body)
			assert.True(t, gjson.Get(body, "active").Bool(), "%s", body)
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), createdIdentity.ID)
			assert.NoError(t, err)
			assert.NotEmpty(t, i.VerifiableAddresses, "%s", body)
			assert.Equal(t, identifier, i.VerifiableAddresses[0].Value)
			assert.True(t, i.VerifiableAddresses[0].Verified)

			assert.Equal(t, identifier, gjson.Get(body, "identity.verifiable_addresses.0.value").String())
			assert.Equal(t, "true", gjson.Get(body, "identity.verifiable_addresses.0.verified").String())
		})
	})
}

func getLoginNode(f *kratos.SelfServiceLoginFlow, nodeName string) *kratos.UiNode {
	for _, n := range f.Ui.Nodes {
		if n.Attributes.UiNodeInputAttributes.Name == nodeName {
			return &n
		}
	}
	return nil
}
