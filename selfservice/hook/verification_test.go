// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"bytes"
	"context"
	"github.com/tidwall/gjson"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ory/kratos/internal/testhelpers"

	"github.com/ory/kratos/courier"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/flow/verification"
	"github.com/ory/kratos/selfservice/hook"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/sqlxx"
)

func TestVerifier(t *testing.T) {
	ctx := context.Background()
	u, err := http.NewRequest(
		http.MethodPost,
		"https://www.ory.sh/",
		bytes.NewReader([]byte("transient_payload=%7B%22branding%22%3A+%22brand-1%22%7D&branding=brand-1")),
	)
	if err != nil {
		return
	}
	u.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, hf := range map[string]func(*hook.Verifier, *identity.Identity, flow.Flow) error{
		"settings": func(h *hook.Verifier, i *identity.Identity, f flow.Flow) error {
			return h.ExecuteSettingsPostPersistHook(
				httptest.NewRecorder(), u, f.(*settings.Flow), i)
		},
		"register": func(h *hook.Verifier, i *identity.Identity, f flow.Flow) error {
			return h.ExecutePostRegistrationPostPersistHook(
				httptest.NewRecorder(), u, f.(*registration.Flow), &session.Session{ID: x.NewUUID(), Identity: i})
		},
	} {
		t.Run("name="+k, func(t *testing.T) {
			conf, reg := internal.NewFastRegistryWithMocks(t)
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/verify.schema.json")
			conf.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://www.ory.sh/")
			conf.MustSet(ctx, config.ViperKeyCourierSMTPURL, "smtp://foo@bar@dev.null/")

			i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
			i.Traits = identity.Traits(`{"emails":["foo@ory.sh","bar@ory.sh","baz@ory.sh"]}`)
			require.NoError(t, reg.IdentityManager().Create(context.Background(), i))

			actual, err := reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.VerifiableAddressTypeEmail, "foo@ory.sh")
			require.NoError(t, err)
			assert.EqualValues(t, "foo@ory.sh", actual.Value)

			actual, err = reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.VerifiableAddressTypeEmail, "bar@ory.sh")
			require.NoError(t, err)
			assert.EqualValues(t, "bar@ory.sh", actual.Value)

			actual, err = reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.VerifiableAddressTypeEmail, "baz@ory.sh")
			require.NoError(t, err)
			assert.EqualValues(t, "baz@ory.sh", actual.Value)

			verifiedAt := sqlxx.NullTime(time.Now())
			actual.Status = identity.VerifiableAddressStatusCompleted
			actual.Verified = true
			actual.VerifiedAt = &verifiedAt
			require.NoError(t, reg.PrivilegedIdentityPool().UpdateVerifiableAddress(context.Background(), actual))

			i, err = reg.IdentityPool().GetIdentity(context.Background(), i.ID)
			require.NoError(t, err)

			var originalFlow flow.Flow
			switch k {
			case "settings":
				originalFlow = &settings.Flow{RequestURL: "http://foo.com/settings?after_verification_return_to=verification_callback"}
			case "register":
				originalFlow = &registration.Flow{RequestURL: "http://foo.com/registration?after_verification_return_to=verification_callback"}
			default:
				t.FailNow()
			}

			h := hook.NewVerifier(reg)
			require.NoError(t, hf(h, i, originalFlow))
			s, err := reg.GetActiveVerificationStrategy(ctx)
			require.NoError(t, err)
			expectedVerificationFlow, err := verification.NewPostHookFlow(conf, conf.SelfServiceFlowVerificationRequestLifespan(ctx), "", u, s, originalFlow)
			require.NoError(t, err)

			var verificationFlow verification.Flow
			require.NoError(t, reg.Persister().GetConnection(context.Background()).First(&verificationFlow))

			assert.Equal(t, expectedVerificationFlow.RequestURL, verificationFlow.RequestURL)

			messages, err := reg.CourierPersister().NextMessages(context.Background(), 12)
			require.NoError(t, err)
			require.Len(t, messages, 2)

			recipients := make([]string, len(messages))
			for k, m := range messages {
				recipients[k] = m.Recipient
				assert.Equal(t, "brand-1", gjson.GetBytes(m.TemplateData, "TransientPayload.branding").String(), "%v", string(m.TemplateData))
				assert.Equal(t, "brand-1", gjson.GetBytes(m.TemplateData, "Branding").String(), "%v", string(m.TemplateData))
			}

			assert.Contains(t, recipients, "foo@ory.sh")
			assert.Contains(t, recipients, "bar@ory.sh")
			assert.NotContains(t, recipients, "baz@ory.sh")
			// Email to baz@ory.sh is skipped because it is verified already.

			//these addresses will be marked as sent and won't be sent again by the settings hook
			address1, err := reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.VerifiableAddressTypeEmail, "foo@ory.sh")
			require.NoError(t, err)
			assert.EqualValues(t, identity.VerifiableAddressStatusSent, address1.Status)
			address2, err := reg.IdentityPool().FindVerifiableAddressByValue(context.Background(), identity.VerifiableAddressTypeEmail, "bar@ory.sh")
			require.NoError(t, err)
			assert.EqualValues(t, identity.VerifiableAddressStatusSent, address2.Status)

			require.NoError(t, hf(h, i, originalFlow))
			expectedVerificationFlow, err = verification.NewPostHookFlow(conf, conf.SelfServiceFlowVerificationRequestLifespan(ctx), "", u, s, originalFlow)
			var verificationFlow2 verification.Flow
			require.NoError(t, reg.Persister().GetConnection(context.Background()).First(&verificationFlow2))
			assert.Equal(t, expectedVerificationFlow.RequestURL, verificationFlow2.RequestURL)
			messages, err = reg.CourierPersister().NextMessages(context.Background(), 12)
			require.EqualError(t, err, courier.ErrQueueEmpty.Error())
			assert.Len(t, messages, 0)
		})
	}
}

func TestPhoneVerifier(t *testing.T) {
	u, err := http.NewRequest(
		http.MethodPost,
		"https://www.ory.sh/",
		bytes.NewReader([]byte("branding=brand-1")),
	)
	if err != nil {
		return
	}
	u.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	t.Run("verify phone number", func(t *testing.T) {
		ctx := context.Background()
		conf, reg := internal.NewFastRegistryWithMocks(t)
		testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/verify.phone.schema.json")
		conf.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://www.ory.sh/")

		i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		i.Traits = identity.Traits(`{"phone":"+18004444444"}`)
		require.NoError(t, reg.IdentityManager().Create(ctx, i))

		actual, err := reg.IdentityPool().FindVerifiableAddressByValue(ctx, identity.VerifiableAddressTypePhone, "+18004444444")
		require.NoError(t, err)
		assert.EqualValues(t, "+18004444444", actual.Value)

		var originalFlow flow.Flow
		originalFlow = &settings.Flow{RequestURL: "http://foo.com/settings?after_verification_return_to=verification_callback"}

		h := hook.NewVerifier(reg)
		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), u, originalFlow.(*settings.Flow), i))
		s, err := reg.GetActiveVerificationStrategy(ctx)
		require.NoError(t, err)
		expectedVerificationFlow, err := verification.NewPostHookFlow(conf, conf.SelfServiceFlowVerificationRequestLifespan(ctx), "", u, s, originalFlow)
		require.NoError(t, err)

		var verificationFlow verification.Flow
		require.NoError(t, reg.Persister().GetConnection(ctx).First(&verificationFlow))

		assert.Equal(t, expectedVerificationFlow.RequestURL, verificationFlow.RequestURL)

		messages, err := reg.CourierPersister().NextMessages(ctx, 12)
		require.NoError(t, err)
		require.Len(t, messages, 1)

		recipients := make([]string, len(messages))
		for k, m := range messages {
			recipients[k] = m.Recipient
		}

		assert.Equal(t, "+18004444444", messages[0].Recipient)

		//this address will be marked as sent and won't be sent again by the settings hook
		address1, err := reg.IdentityPool().FindVerifiableAddressByValue(ctx, identity.VerifiableAddressTypePhone, "+18004444444")
		require.NoError(t, err)
		assert.EqualValues(t, identity.VerifiableAddressStatusSent, address1.Status)

		require.NoError(t, h.ExecuteSettingsPostPersistHook(httptest.NewRecorder(), u, originalFlow.(*settings.Flow), i))
		expectedVerificationFlow, err = verification.NewPostHookFlow(conf, conf.SelfServiceFlowVerificationRequestLifespan(ctx), "", u, s, originalFlow)
		var verificationFlow2 verification.Flow
		require.NoError(t, reg.Persister().GetConnection(ctx).First(&verificationFlow2))
		assert.Equal(t, expectedVerificationFlow.RequestURL, verificationFlow2.RequestURL)
		messages, err = reg.CourierPersister().NextMessages(ctx, 12)
		require.EqualError(t, err, courier.ErrQueueEmpty.Error())
		assert.Len(t, messages, 0)
	})
}
