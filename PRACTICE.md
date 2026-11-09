# Guía práctica (10 niveles)

Ejercicios offline sobre el gate de `key` en createVerifier. No se
verifica ninguna firma real.

1. `p01_empty_key_hs256`: ¿qué hace pre en verify? (`ACCEPT`)
2. Misma entrada en post: ¿qué código lanza? (`invalidKey`)
3. `n01_real_key_unsigned`: unsigned con clave real → `missingSignature` en ambos.
4. `n05_real_key_with_sig`: ¿por qué la etiqueta es
   `PROCEEDS_TO_SIGNATURE_CHECK` y no `ACCEPT`?
5. `n02_none_only_empty`: ¿por qué post también acepta?
6. `n03_none_only_with_key`: key truthy + only-none → `invalidOption` post.
7. `n04_empty_key_no_allowlist`: con `algorithms=[]` y sin clave, pre lanza
   `invalidAlgorithm` (el `includes()` es incondicional). ¿Por qué el CVE
   exige una allowlist no vacía?
8. Explica hasKey: `key instanceof Buffer ? key.length : !!key`, y por qué
   `Buffer.alloc(0)` es truthy en construcción (`a05_empty_buffer`).
9. `a06_alg_None_mixed`: `'None'` no es `'none'` para `allowsOnlyNone`.
   ¿Qué hace post?
10. Añade un caso con `algorithms=['none','HS256']` y documenta el resultado.

Más allá: regenera `fixtures/expected.tsv` con
`scripts/derive_expected.py` y comprueba el oráculo.
