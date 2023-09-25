// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jarcoal/httpmock"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestConfig(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)

	t.Run("case=should fetch provider config from configuration file", func(t *testing.T) {
		var c map[string]interface{}
		require.NoError(t, json.NewDecoder(
			bytes.NewBufferString(`{"config":{"providers": [{"provider": "generic"}]}}`)).Decode(&c))
		conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeOIDC), c)

		s := oidc.NewStrategy(reg)
		collection, err := s.Config(ctx)
		require.NoError(t, err)

		require.Len(t, collection.Providers, 1)
		assert.Equal(t, "generic", collection.Providers[0].Provider)
	})

	t.Run("case=should fetch provider config from external source", func(t *testing.T) {
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		httpmock.RegisterResponder("GET", "https://example.com/identity/providers/oidc/google",
			func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, json.RawMessage(`{"id": "google", "provider": "google", "scope": ["profile"]}`))
			},
		)

		var c map[string]interface{}
		require.NoError(t, json.NewDecoder(
			bytes.NewBufferString(`{"config": {"providers_request":{"url": "https://example.com/identity/providers/oidc","method": "GET","auth": {"type": "api_key","config": {"name": "Authorization","value": "token", "in": "header"}}}, "providers": [{"provider": "generic"}]}}`)).Decode(&c))
		conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeOIDC), c)

		s := oidc.NewStrategy(reg)
		collection, err := s.Config(ctx)
		require.NoError(t, err)

		p, err := collection.Provider(ctx, "google", reg)
		require.NoError(t, err)

		assert.Equal(t, "google", p.Config().Provider)
	})

	t.Run("case=should not try to call external source and return error", func(t *testing.T) {
		s := oidc.NewStrategy(reg)
		collection, err := s.Config(ctx)
		require.NoError(t, err)

		_, err = collection.Provider(ctx, "google", reg)
		require.Error(t, err)
	})
}
