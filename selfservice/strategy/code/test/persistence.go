package test

import (
	"context"
	"testing"
	"time"

	"github.com/bxcodec/faker/v3"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/persistence"
	"github.com/ory/kratos/selfservice/strategy/code"
	"github.com/ory/kratos/x"
)

//goland:noinspection GoNameStartsWithPackageName
func TestCodePersister(ctx context.Context, p persistence.Persister) func(t *testing.T) {
	return func(t *testing.T) {
		var newCode = func(t *testing.T) *code.Code {
			var r code.Code
			require.NoError(t, faker.FakeData(&r))
			r.FlowId = uuid.Must(uuid.NewV4())
			return &r
		}

		t.Run("case=should create and fetch a code", func(t *testing.T) {
			expected := newCode(t)
			err := p.CreateCode(ctx, expected)
			require.NoError(t, err)

			actual, err := p.FindActiveCode(ctx, expected.FlowId, expected.ExpiresAt.Add(-time.Minute))
			require.NoError(t, err)

			assert.NotNil(t, actual)
			assert.EqualValues(t, expected.ID, actual.ID)
			assert.EqualValues(t, expected.Identifier, actual.Identifier)
			x.AssertEqualTime(t, expected.ExpiresAt, actual.ExpiresAt)
		})
	}
}
