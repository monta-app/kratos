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

		httpmock.RegisterResponder("GET", "http://external.source.example/identity-provider/google",
			func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, json.RawMessage(`{"id": "google", "provider": "google", "scope": ["profile"]}`))
			},
		)
		s := oidc.NewStrategy(reg)
		collection, err := s.Config(ctx)
		require.NoError(t, err)

		collection.BaseServiceIdentityURI = "http://external.source.example"

		p, err := collection.Provider(ctx, "google", reg)
		require.NoError(t, err)

		assert.Equal(t, "google", p.Config().Provider)
	})
}
