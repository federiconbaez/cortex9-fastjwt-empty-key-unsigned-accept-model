# Limitations

- **Construction + hasKey only.** Signature cryptography is not modelled;
  a non-empty signature with a real key is labelled ACCEPT without
  verifying bytes.
- **Async key functions** are accepted at construct but not exercised at
  verify.
- JS `typeof null === "object"` is reproduced deliberately.
- This is not a finding. Nothing is attributed beyond the commits listed in
  SOURCES.md and the public CVE.
