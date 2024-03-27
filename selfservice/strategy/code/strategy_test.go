// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/x/stringslice"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/recovery"
	"github.com/ory/kratos/selfservice/strategy/code"
)

func initViper(t *testing.T, ctx context.Context, c *config.Config) {
	testhelpers.SetDefaultIdentitySchema(c, "file://./stub/default.schema.json")
	c.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, "https://www.ory.sh")
	c.MustSet(ctx, config.ViperKeyURLsAllowedReturnToDomains, []string{"https://www.ory.sh"})
	c.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+identity.CredentialsTypePassword.String()+".enabled", true)
	c.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(recovery.RecoveryStrategyCode)+".enabled", true)
	c.MustSet(ctx, config.ViperKeySelfServiceRecoveryEnabled, true)
	c.MustSet(ctx, config.ViperKeySelfServiceRecoveryUse, "code")
	c.MustSet(ctx, config.ViperKeySelfServiceVerificationEnabled, true)
	c.MustSet(ctx, config.ViperKeySelfServiceVerificationUse, "code")
}

func TestGenerateCode(t *testing.T) {
	codes := make([]string, 100)
	for k := range codes {
		codes[k] = code.GenerateCode()
	}

	assert.Len(t, stringslice.Unique(codes), len(codes))
}

func TestMaskAddress(t *testing.T) {
	for _, tc := range []struct {
		address  string
		expected string
	}{
		{
			address:  "a",
			expected: "a",
		},
		{
			address:  "ab@cd",
			expected: "ab****@cd",
		},
		{
			address:  "fixed@ory.sh",
			expected: "fi****@ory.sh",
		},
		{
			address:  "f@ory.sh",
			expected: "f@ory.sh",
		},
		{
			address:  "+12345678910",
			expected: "+12****10",
		},
		{
			address:  "+123456",
			expected: "+12****56",
		},
	} {
		t.Run("case="+tc.address, func(t *testing.T) {
			assert.Equal(t, tc.expected, code.MaskAddress(tc.address))
		})
	}
}

func initExternalSMSVerifier(t *testing.T, ctx context.Context, conf *config.Config, mapperFile string,
	externalVerifyRequestBody *string, externalVerifyResult *string) *httptest.Server {
	vs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		requestBody := string(rb)
		verifyResult := ""
		if strings.HasSuffix(r.URL.Path, "start") {
			verifyResult = "code has been sent"
		} else if strings.HasSuffix(r.URL.Path, "check") {
			if strings.Contains(requestBody, "0000") {
				verifyResult = "code valid"
			} else {
				verifyResult = "code invalid"
				w.WriteHeader(http.StatusBadRequest)
			}
		}
		*externalVerifyRequestBody = requestBody
		*externalVerifyResult = verifyResult
	}))

	t.Cleanup(vs.Close)

	requestConfig := `{
		"url": "%s",
		"method": "POST",
		"body": "%s",
		"auth": {
			"type": "basic_auth",
			"config": {
				"user":     "me",
				"password": "12345"
			}
		}
	}`
	verificationStartRequest := fmt.Sprintf(requestConfig, vs.URL+"/start", mapperFile)
	verificationCheckRequest := fmt.Sprintf(requestConfig, vs.URL+"/check", mapperFile)

	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(recovery.RecoveryStrategyCode)+".external_sms_verify", fmt.Sprintf(`{
			"enabled": true,
			"verification_start_request": %s,
			"verification_check_request": %s
		}`, verificationStartRequest, verificationCheckRequest))

	return vs
}
