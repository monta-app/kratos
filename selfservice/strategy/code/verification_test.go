package code_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	kratos "github.com/ory/kratos-client-go"
	"github.com/ory/kratos/courier/template/sms"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/assertx"
)

func TestVerification(t *testing.T) {
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/default.schema.json")
	conf.MustSet(config.ViperKeySelfServiceBrowserDefaultReturnTo, "https://www.ory.sh")
	conf.MustSet(config.ViperKeyURLsAllowedReturnToDomains, []string{"https://www.ory.sh"})
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+identity.CredentialsTypePassword.String()+".enabled", true)
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+recovery.StrategyRecoveryLinkName+".enabled", true)
	conf.MustSet(config.ViperKeySelfServiceStrategyConfig+"."+verification.StrategyVerificationCodeName+".enabled", true)
	conf.MustSet(config.ViperKeySelfServiceRecoveryEnabled, true)
	conf.MustSet(config.ViperKeySelfServiceVerificationEnabled, true)

	public, _ := testhelpers.NewKratosServerWithCSRF(t, reg)

	var identityToVerify = &identity.Identity{
		ID:       x.NewUUID(),
		Traits:   identity.Traits(`{"phone":"+4580010000"}`),
		SchemaID: config.DefaultIdentityTraitsSchemaID,
	}

	var verificationPhone = gjson.GetBytes(identityToVerify.Traits, "phone").String()

	require.NoError(t, reg.IdentityManager().Create(context.Background(), identityToVerify,
		identity.ManagerAllowWriteProtectedTraits))

	var expect = func(t *testing.T, hc *http.Client, isAPI, isSPA bool, values func(url.Values), c int,
		f *kratos.SelfServiceVerificationFlow) string {
		if hc == nil {
			hc = testhelpers.NewDebugClient(t)
			if !isAPI {
				hc = testhelpers.NewClientWithCookies(t)
				hc.Transport = testhelpers.NewTransportWithLogger(http.DefaultTransport, t).RoundTripper
			}
		}

		return testhelpers.SubmitVerificationForm(t, isAPI, isSPA, hc, public, values, c,
			testhelpers.ExpectURL(isAPI || isSPA,
				public.URL+verification.RouteSubmitFlow, conf.SelfServiceFlowVerificationUI().String()),
			f)
	}

	var expectSuccess = func(t *testing.T, hc *http.Client, isAPI, isSPA bool,
		f *kratos.SelfServiceVerificationFlow, values func(url.Values)) string {
		return expect(t, hc, isAPI, isSPA, values, http.StatusOK, f)
	}

	t.Run("description=should verify phone", func(t *testing.T) {

		//t.Run("type=browser", func(t *testing.T) {
		//	check(t, expectSuccess(t, nil, false, false, values))
		//})
		//
		//t.Run("type=spa", func(t *testing.T) {
		//	check(t, expectSuccess(t, nil, false, true, values))
		//})

		t.Run("type=api", func(t *testing.T) {
			f := testhelpers.InitializeVerificationFlowViaAPI(t, nil, public)
			body := expectSuccess(t, nil, true, false, f,
				func(v url.Values) {
					v.Set("phone", verificationPhone)
				})
			assert.EqualValues(t, string(node.CodeGroup), gjson.Get(body, "active").String(), "%s", body)
			assert.EqualValues(t, verificationPhone,
				gjson.Get(body, "ui.nodes.#(attributes.name==phone).attributes.value").String(), "%s", body)
			assertx.EqualAsJSON(t, text.NewVerificationPhoneSent(), json.RawMessage(gjson.Get(body, "ui.messages.0").Raw))

			message := testhelpers.CourierExpectMessage(t, reg, verificationPhone, "")

			var smsModel sms.CodeMessageModel
			err := json.Unmarshal(message.TemplateData, &smsModel)
			assert.NoError(t, err)

			body = expectSuccess(t, nil, true, false, f,
				func(v url.Values) {
					v.Set("phone", verificationPhone)
					v.Set("code", smsModel.Code)
				})
			assert.EqualValues(t, string(node.CodeGroup), gjson.Get(body, "active").String(), "%s", body)
			assert.EqualValues(t, verificationPhone,
				gjson.Get(body, "ui.nodes.#(attributes.name==phone).attributes.value").String(), "%s", body)

			assert.EqualValues(t, "passed_challenge", gjson.Get(body, "state").String())
			assert.EqualValues(t, text.NewInfoSelfServicePhoneVerificationSuccessful().Text,
				gjson.Get(body, "ui.messages.0.text").String())
			id, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), identityToVerify.ID)
			require.NoError(t, err)
			require.Len(t, id.VerifiableAddresses, 1)

			address := id.VerifiableAddresses[0]
			assert.EqualValues(t, verificationPhone, address.Value)
			assert.True(t, address.Verified)
			assert.EqualValues(t, identity.VerifiableAddressStatusCompleted, address.Status)
			assert.True(t, time.Time(*address.VerifiedAt).Add(time.Second*5).After(time.Now()))

		})
	})

}
