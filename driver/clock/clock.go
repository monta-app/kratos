package clock

import (
	"github.com/benbjohnson/clock"
)

type Provider interface {
	Clock() clock.Clock
}
