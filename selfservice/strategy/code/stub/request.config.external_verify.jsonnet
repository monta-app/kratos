function(ctx) {
  code: ctx.VerificationCode,
  [if "TransientPayload" in ctx then "transient_payload"]: ctx.TransientPayload
}
