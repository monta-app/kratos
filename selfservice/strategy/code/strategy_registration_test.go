// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"

	client "github.com/ory/kratos/internal/httpclient"
	"github.com/ory/x/resilience"

	"github.com/gobuffalo/httptest"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/courier/template/sms"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/x"
	"github.com/ory/x/snapshotx"
	"github.com/ory/x/urlx"
)

func TestRegistration(t *testing.T) {
	ctx := context.Background()

	t.Run("case=registration", func(t *testing.T) {
		conf, reg := internal.NewFastRegistryWithMocks(t)

		router := x.NewRouterPublic()
		admin := x.NewRouterAdmin()
		conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeCode), map[string]interface{}{"enabled": true})

		publicTS, _ := testhelpers.NewKratosServerWithRouters(t, reg, router, admin)
		//errTS := testhelpers.NewErrorTestServer(t, reg)
		uiTS := testhelpers.NewRegistrationUIFlowEchoServer(t, reg)
		redirTS := testhelpers.NewRedirSessionEchoTS(t, reg)

		// Overwrite these two to ensure that they run
		conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, redirTS.URL+"/default-return-to")
		conf.MustSet(ctx, config.ViperKeySelfServiceRegistrationAfter+"."+config.DefaultBrowserReturnURL, redirTS.URL+"/registration-return-ts")
		testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/default.schema.json")
		conf.MustSet(ctx, config.CodeMaxAttempts, 5)

		t.Run("case=should fail if identifier changed when submitted with code", func(t *testing.T) {
			identifier := "+4550050000"

			cleanCourierQueue(reg)

			hc := new(http.Client)

			f := testhelpers.InitializeRegistrationFlow(t, true, hc, publicTS, false)

			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier)
			}
			testhelpers.SubmitRegistrationFormWithFlow(t, true, hc, values,
				false, http.StatusOK, publicTS.URL+registration.RouteSubmitFlow, f)

			messages, err := reg.CourierPersister().NextMessages(context.Background(), 10)
			assert.NoError(t, err, "Courier queue should not be empty.")
			assert.Equal(t, 1, len(messages))
			var smsModel sms.CodeMessageModel
			err = json.Unmarshal(messages[0].TemplateData, &smsModel)
			assert.NoError(t, err)

			values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier+"2")
				v.Set("code", smsModel.Code)
			}

			body := testhelpers.SubmitRegistrationFormWithFlow(t, true, hc, values,
				false, http.StatusBadRequest, publicTS.URL+registration.RouteSubmitFlow, f)
			assert.Contains(t, body, "not equal to verified phone")

		})

		t.Run("case=should fail if spam detected", func(t *testing.T) {
			identifier := "+4550050001"
			conf.MustSet(ctx, config.CodeSMSSpamProtectionEnabled, true)

			for i := 0; i <= 50; i++ {
				requestCode(t, publicTS, identifier, http.StatusOK)
			}

			requestCode(t, publicTS, identifier, http.StatusBadRequest)

			identifier = "+456005"

			for i := 0; i <= 100; i++ {
				requestCode(t, publicTS, identifier+fmt.Sprintf("%04d", i), http.StatusOK)
			}

			requestCode(t, publicTS, identifier+"0101", http.StatusBadRequest)
		})

		var expectSuccessfulLogin = func(
			t *testing.T, isAPI, isSPA bool, hc *http.Client,
			expectReturnTo string,
			identifier string,
		) string {
			if hc == nil {
				if isAPI {
					hc = new(http.Client)
				} else {
					hc = testhelpers.NewClientWithCookies(t)
				}
			}

			cleanCourierQueue(reg)

			f := testhelpers.InitializeRegistrationFlow(t, isAPI, hc, publicTS, isSPA)

			assert.Empty(t, getRegistrationNode(f, "code"))
			assert.NotEmpty(t, getRegistrationNode(f, "traits.phone"))

			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier)
			}
			body := testhelpers.SubmitRegistrationFormWithFlow(t, isAPI, hc, values,
				isSPA, http.StatusOK, expectReturnTo, f)

			assert.Equal(t, "code", gjson.Get(body, "active").String(), "Response body: %s", body)

			messages, err := reg.CourierPersister().NextMessages(context.Background(), 10)
			assert.NoError(t, err, "Courier queue should not be empty.")
			assert.Equal(t, 1, len(messages))
			var smsModel sms.CodeMessageModel
			err = json.Unmarshal(messages[0].TemplateData, &smsModel)
			assert.NoError(t, err)

			st := gjson.Get(body, "session_token").String()
			assert.Empty(t, st, "Response body: %s", body) //No session token as we have not presented the code yet

			values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier)
				v.Set("code", smsModel.Code)
			}

			body = testhelpers.SubmitRegistrationFormWithFlow(t, isAPI, hc, values,
				isSPA, http.StatusOK, expectReturnTo, f)

			assert.Equal(t, identifier, gjson.Get(body, "session.identity.traits.phone").String(),
				"%s", body)
			identityID, err := uuid.FromString(gjson.Get(body, "identity.id").String())
			assert.NoError(t, err)
			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), identityID)
			assert.NoError(t, err)
			assert.NotEmpty(t, i.Credentials, "%s", body)
			assert.Equal(t, identifier, i.Credentials["code"].Identifiers[0], "%s", body)
			assert.NotEmpty(t, gjson.Get(body, "session_token").String(), "%s", body)
			assert.Equal(t, identifier, gjson.Get(body, "identity.verifiable_addresses.0.value").String())
			assert.Equal(t, "true", gjson.Get(body, "identity.verifiable_addresses.0.verified").String())

			return body
		}

		t.Run("case=should pass and set up a session", func(t *testing.T) {
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/default.schema.json")
			conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypeCode.String()), []config.SelfServiceHook{{Name: "session"}})
			t.Cleanup(func() {
				conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypeCode.String()), nil)
			})

			identifier := "+4570050001"

			t.Run("type=api", func(t *testing.T) {
				expectSuccessfulLogin(t, true, false, nil,
					publicTS.URL+registration.RouteSubmitFlow, identifier)
			})

			//t.Run("type=spa", func(t *testing.T) {
			//	hc := testhelpers.NewClientWithCookies(t)
			//	body := expectSuccessfulLogin(t, false, true, hc, func(v url.Values) {
			//		v.Set("traits.username", "registration-identifier-8-spa")
			//		v.Set("password", x.NewUUID().String())
			//		v.Set("traits.foobar", "bar")
			//	})
			//	assert.Equal(t, `registration-identifier-8-spa`, gjson.Get(body, "identity.traits.username").String(), "%s", body)
			//	assert.Empty(t, gjson.Get(body, "session_token").String(), "%s", body)
			//	assert.NotEmpty(t, gjson.Get(body, "session.id").String(), "%s", body)
			//})
			//
			//t.Run("type=browser", func(t *testing.T) {
			//	body := expectSuccessfulLogin(t, false, false, nil, func(v url.Values) {
			//		v.Set("traits.username", "registration-identifier-8-browser")
			//		v.Set("password", x.NewUUID().String())
			//		v.Set("traits.foobar", "bar")
			//	})
			//	assert.Equal(t, `registration-identifier-8-browser`, gjson.Get(body, "identity.traits.username").String(), "%s", body)
			//})
		})

		t.Run("case=should create verifiable address", func(t *testing.T) {
			identifier := "+1234567890"
			conf.MustSet(ctx, config.CodeTestNumbers, []string{identifier})
			createdIdentity := &identity.Identity{
				SchemaID: "default",
				Traits:   identity.Traits(fmt.Sprintf(`{"phone":"%s"}`, identifier)),
				State:    identity.StateActive}
			err := reg.IdentityManager().Create(context.Background(), createdIdentity)
			assert.NoError(t, err)

			i, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), createdIdentity.ID)
			assert.NoError(t, err)
			assert.Equal(t, identifier, i.VerifiableAddresses[0].Value)
			assert.False(t, i.VerifiableAddresses[0].Verified)
			assert.Equal(t, identity.VerifiableAddressStatusPending, i.VerifiableAddresses[0].Status)
		})

		t.Run("method=TestPopulateSignUpMethod", func(t *testing.T) {
			conf.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://foo/")
			t.Cleanup(func() {
				conf.MustSet(ctx, config.ViperKeyPublicBaseURL, publicTS.URL)
			})

			sr, err := registration.NewFlow(conf, time.Minute, "nosurf", &http.Request{URL: urlx.ParseOrPanic("/")}, flow.TypeBrowser)
			require.NoError(t, err)
			require.NoError(t, reg.RegistrationStrategies(context.Background()).
				MustStrategy(identity.CredentialsTypeCode).(*code.Strategy).PopulateRegistrationMethod(&http.Request{}, sr))

			snapshotx.SnapshotTExcept(t, sr.UI, []string{"action", "nodes.0.attributes.value"})
		})

		t.Run("case=should use standby sender", func(t *testing.T) {
			senderMessagesCount := 0
			standbySenderMessagesCount := 0
			senderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				senderMessagesCount++
			}))
			standbySenderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				standbySenderMessagesCount++
			}))

			configTemplate := `{
				"url": "%s",
				"method": "POST",
				"body": "file://./stub/request.config.twilio.jsonnet"
			}`

			conf.MustSet(ctx, config.ViperKeyCourierSMSRequestConfig, fmt.Sprintf(configTemplate, senderSrv.URL))
			conf.MustSet(ctx, config.ViperKeyCourierSMSStandbyRequestConfig, fmt.Sprintf(configTemplate, standbySenderSrv.URL))
			conf.MustSet(ctx, config.ViperKeyCourierSMSFrom, "test sender")
			conf.MustSet(ctx, config.ViperKeyCourierSMSStandbyFrom, "test standby sender")
			conf.MustSet(ctx, config.ViperKeyCourierSMSEnabled, true)
			conf.MustSet(ctx, config.ViperKeyCourierSMTPURL, "http://foo.url")

			c, err := reg.Courier(ctx)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer t.Cleanup(cancel)

			identifier := "+4550050005"
			f := testhelpers.InitializeRegistrationFlow(t, true, nil, publicTS, false)
			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier)
			}
			testhelpers.SubmitRegistrationFormWithFlow(t, true, nil, values,
				false, http.StatusOK, publicTS.URL+registration.RouteSubmitFlow, f)
			testhelpers.SubmitRegistrationFormWithFlow(t, true, nil, values,
				false, http.StatusOK, publicTS.URL+registration.RouteSubmitFlow, f)

			go func() {
				require.NoError(t, c.Work(ctx))
			}()

			require.NoError(t, resilience.Retry(reg.Logger(), time.Millisecond*250, time.Second*10, func() error {
				if senderMessagesCount+standbySenderMessagesCount >= 2 {
					return nil
				}
				return errors.New("messages not sent yet")
			}))

			assert.Equal(t, 1, senderMessagesCount)
			assert.Equal(t, 1, standbySenderMessagesCount)

			senderSrv.Close()
			standbySenderSrv.Close()

		})

		t.Run("should save transient payload to SMS template data", func(t *testing.T) {
			identifier := fmt.Sprintf("+452%s", fmt.Sprint(rand.Int())[0:7])

			var values = func(v url.Values) {
				v.Set("method", "code")
				v.Set("traits.phone", identifier)
				v.Set("transient_payload", `{"branding": "brand-1"}`)
			}

			var doTest = func(t *testing.T, isAPI bool) {
				cleanCourierQueue(reg)
				hc := new(http.Client)
				f := testhelpers.InitializeRegistrationFlow(t, isAPI, hc, publicTS, false)
				expectedURL := uiTS.URL
				if isAPI {
					expectedURL = publicTS.URL + registration.RouteSubmitFlow
				}
				testhelpers.SubmitRegistrationFormWithFlow(t, isAPI, hc, values,
					false, http.StatusOK, expectedURL, f)

				message := testhelpers.CourierExpectMessage(t, reg, identifier, "")
				assert.Equal(t, "brand-1", gjson.GetBytes(message.TemplateData, "TransientPayload.branding").String(), "%s", message.TemplateData)
			}

			t.Run("type=browser", func(t *testing.T) {
				doTest(t, false)
			})

			t.Run("type=api", func(t *testing.T) {
				doTest(t, true)
			})
		})
	})
}

func cleanCourierQueue(reg *driver.RegistryDefault) {
	for {
		_, err := reg.CourierPersister().NextMessages(context.Background(), 10)
		if err != nil {
			return
		}
	}
}

func requestCode(t *testing.T, publicTS *httptest.Server, identifier string, statusCode int) {
	hc := new(http.Client)
	f := testhelpers.InitializeRegistrationFlow(t, true, hc, publicTS, false)
	var values = func(v url.Values) {
		v.Set("method", "code")
		v.Set("traits.phone", identifier)
	}
	testhelpers.SubmitRegistrationFormWithFlow(t, true, hc, values,
		false, statusCode, publicTS.URL+registration.RouteSubmitFlow, f)
}

func getRegistrationNode(f *client.RegistrationFlow, nodeName string) *client.UiNode {
	for _, n := range f.Ui.Nodes {
		if n.Attributes.UiNodeInputAttributes.Name == nodeName {
			return &n
		}
	}
	return nil
}
