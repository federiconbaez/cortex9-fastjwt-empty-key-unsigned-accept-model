# cortex9-fastjwt-empty-key-unsigned-accept-model

Offline differential model of **CVE-2026-107720** (GHSA-8wpc-h4q6-8fxv):
fast-jwt `createVerifier` accepted an unsigned JWT when `key` was `''` or
`null` and `algorithms` was a non-empty allowlist. Educational, offline,
deterministic. No cryptographic verification is performed.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Two semantics, always side by side

| | pre (`378422c6`) | post (`e22a151e`) |
|---|---|---|
| Empty/null key + allowlist | construction OK; verify sees no key and no signature → ACCEPT | construction throws `invalidKey` |
| Real key + signature | `PROCEEDS_TO_SIGNATURE_CHECK` (crypto not modelled) | same |
| Diff | `src/verifier.js` lines 502–524 | diff lines 18–55 |

`ACCEPT` is used only when verification ends with no key and no signature,
i.e. nothing was checked (the bug path, or a legitimate `["none"]`-only
verifier). A token that carries a signature and meets a real key is labelled
`PROCEEDS_TO_SIGNATURE_CHECK`, never `ACCEPT`.

Cases: 3 positives, 5 negatives, 10 adversarial (odd key types, mixed-case
algorithm names, empty or non-list allowlists), modelled with explicit JS
`typeof` and truthiness.

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
