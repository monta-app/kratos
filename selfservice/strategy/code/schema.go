package code

import _ "embed"

//go:embed .schema/login.schema.json
var loginSchema []byte

//go:embed .schema/registration.schema.json
var registrationSchema []byte

//go:embed .schema/verification.schema.json
var verificationSchema []byte
