# cortex9-fastjwt-empty-key-unsigned-accept-model

Modelo diferencial offline de **CVE-2026-107720** (GHSA-8wpc-h4q6-8fxv):
`createVerifier` de fast-jwt aceptaba un JWT sin firma cuando `key` era
`''` o `null` y `algorithms` era una allowlist no vacía. Educativo,
offline y determinista.

`ACCEPT` solo se usa cuando la verificación termina sin clave y sin firma
(nada se comprobó). Un token con firma frente a una clave real se etiqueta
`PROCEEDS_TO_SIGNATURE_CHECK`, nunca `ACCEPT`. Casos: 3 positivos,
5 negativos y 10 adversariales (tipos raros de clave, algoritmos con
mayúsculas, allowlists vacías o que no son lista).

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Cómo ejecutarlo

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.
