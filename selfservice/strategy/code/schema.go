// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	_ "embed"
)

//go:embed .schema/recovery.schema.json
var recoveryMethodSchema []byte

//go:embed .schema/verification.schema.json
var verificationMethodSchema []byte

//go:embed .schema/login.schema.json
var loginSchema []byte

//go:embed .schema/registration.schema.json
var registrationSchema []byte
