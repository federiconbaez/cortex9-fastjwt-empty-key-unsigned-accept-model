# Limitations

- **Construction + hasKey + allowlist only.** Signature cryptography is not
  modelled. A real key plus a signature is labelled
  `PROCEEDS_TO_SIGNATURE_CHECK`: the outcome depends on `verifySignature`,
  which this model does not run. `ACCEPT` is reserved for the path where
  neither a key nor a signature exists.
- **Key preparation is not modelled.** `detectPublicKeyAlgorithms` and
  `prepareKeyOrSecret` run for any truthy non-function key. In JS `[]`, `{}`
  and `Buffer.alloc(0)` are truthy, so they enter that branch in both pre and
  post; the model labels them `KEY_PREP_UNMODELED` rather than guessing.
  Note that an empty Buffer is truthy at construction but `hasKey` is
  `key.length` (0) at verify; the fix's `!key` check does not catch it.
  Whether key preparation rejects it is not established here.
- **Algorithm names are not validated against the supported list.** Cases
  with `'None'` or `'hs256'` in the allowlist only show that the fix's
  `allowsOnlyNone` check is case-sensitive (`=== 'none'`) and that post still
  demands a key. Whether the token decoder or later code rejects such names is
  not modelled.
- **Async key functions** are accepted at construct but not exercised at
  verify.
- JS `typeof null === "object"` and JS truthiness are reproduced deliberately.
- This is not a finding. Nothing is attributed beyond the commits listed in
  SOURCES.md and the public CVE.
