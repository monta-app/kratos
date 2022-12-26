// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState(t *testing.T) {
	assert.EqualValues(t, StateSent, NextState(StateChooseMethod))
	assert.EqualValues(t, StatePassedChallenge, NextState(StateSent))
	assert.EqualValues(t, StatePassedChallenge, NextState(StatePassedChallenge))

	assert.True(t, HasReachedState(StatePassedChallenge, StatePassedChallenge))
	assert.False(t, HasReachedState(StatePassedChallenge, StateSent))
	assert.False(t, HasReachedState(StateSent, StateChooseMethod))
}
