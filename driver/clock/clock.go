// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clock

import (
	"github.com/benbjohnson/clock"
)

type Provider interface {
	Clock() clock.Clock
}
