// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"strings"

	"github.com/ory/x/randx"
)

func RandomEmail() string {
	return strings.ToLower(randx.MustString(16, randx.Alpha) + "@ory.sh")
}

func RandomPhone() string {
	return "+458001" + randx.MustString(4, randx.Numeric)
}
