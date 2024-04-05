function(ctx) {
  code: ctx.Code,
  [if "TransientPayload" in ctx then "transient_payload"]: ctx.TransientPayload
}
