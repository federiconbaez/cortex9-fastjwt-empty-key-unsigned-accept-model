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
| Diff | `src/verifier.js` lines 502–524 | diff lines 18–55 |

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
