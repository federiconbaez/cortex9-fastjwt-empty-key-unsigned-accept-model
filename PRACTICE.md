# Guía práctica (8 niveles)

Ejercicios offline sobre el gate de `key` en createVerifier. No se
verifica ninguna firma real.

1. `p01_empty_key_hs256`: ¿qué hace pre en verify? (`ACCEPT`)
2. Misma entrada en post: ¿qué código lanza? (`invalidKey`)
3. `n01_real_key`: unsigned con clave real → `missingSignature` en ambos.
4. `n02_none_only_empty`: ¿por qué post también acepta?
5. `n03_none_only_with_key`: key truthy + only-none → `invalidOption` post.
6. Explica hasKey: `key instanceof Buffer ? key.length : !!key`.
7. `n04_empty_no_algs`: allowlist vacía; ¿sigue siendo bypass pre?
8. Añade un caso con `algorithms=['none','HS256']` y documenta el resultado.

Más allá: regenera `fixtures/expected.tsv` y comprueba el oráculo.
