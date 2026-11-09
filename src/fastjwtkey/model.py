"""Offline model of fast-jwt createVerifier key gating (CVE-2026-107720).

Ports the construction-time checks of src/verifier.js at parent 378422c6
(pre, lines 502-524) and fix e22a151e (post; diff lines 21-55 of
diffs/CVE-2026-107720_fast-jwt_e22a151e83bf.diff), plus the hasKey and
allowlist gates of verifyToken (pre lines 265-280) and
validateAlgorithmAndSignature (pre lines 159-171).

JavaScript semantics are reproduced explicitly: ``typeof`` and truthiness
(empty arrays, empty objects and empty Buffers are truthy in JS).
Signature cryptography, detectPublicKeyAlgorithms and prepareKeyOrSecret
are NOT modelled.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field


class TokenError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def js_typeof(v) -> str:
    if v is None:
        return "object"  # typeof null
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if callable(v):
        return "function"
    return "object"  # bytes (Buffer), list (Array), dict (Object)


def js_truthy(v) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or (isinstance(v, float) and math.isnan(v)))
    if isinstance(v, str):
        return v != ""
    return True  # [], {}, Buffer.alloc(0), functions


def has_key(key) -> bool:
    """verifyToken: key instanceof Buffer ? key.length : !!key"""
    if isinstance(key, (bytes, bytearray)):
        return len(key) > 0
    return js_truthy(key)


def _key_prep(key) -> None:
    """`if (key && keyType !== 'function')` branch: detectPublicKeyAlgorithms +
    prepareKeyOrSecret. Not modelled except for non-empty strings/Buffers,
    which we treat as a usable secret."""
    if isinstance(key, str) and key:
        return
    if isinstance(key, (bytes, bytearray)) and len(key) > 0:
        return
    raise TokenError("KEY_PREP_UNMODELED", "key preparation not modelled for this value")


def create_verifier_pre(key, algorithms):
    allowed = list(algorithms) if isinstance(algorithms, list) else []
    kt = js_typeof(key)
    if kt not in ("string", "object", "function"):
        raise TokenError("INVALID_OPTION", "The key option must be a string, a buffer or a function...")
    if js_truthy(key) and kt != "function":
        _key_prep(key)
    return {"key": key, "allowed": allowed, "keyType": kt}


def create_verifier_post(key, algorithms):
    allowed = list(algorithms) if isinstance(algorithms, list) else []
    kt = js_typeof(key)
    only_none = len(allowed) > 0 and all(a == "none" for a in allowed)
    if only_none:
        if js_truthy(key):
            raise TokenError("invalidOption", 'key must not be provided when the only allowed algorithm is "none"')
    elif kt not in ("string", "object", "function"):
        raise TokenError("invalidOption", "The key option must be a string, a buffer or a function...")
    elif (not js_truthy(key)) and kt != "function":
        raise TokenError("invalidKey", 'The key option is required unless the only allowed algorithm is "none".')
    if js_truthy(key) and kt != "function":
        _key_prep(key)
    return {"key": key, "allowed": allowed, "keyType": kt}


def verify_token_model(v, header_alg: str, signature: str) -> str:
    hk = has_key(v["key"])
    if hk and not signature:
        raise TokenError("missingSignature", "The token signature is missing.")
    if (not hk) and signature:
        raise TokenError("missingKey", "The key option is missing.")
    # validateAlgorithmAndSignature: unconditional includes() check.
    if header_alg not in v["allowed"]:
        raise TokenError("invalidAlgorithm", "The token algorithm is invalid.")
    if signature:
        # verifySignature(...) runs here; cryptography is not modelled.
        return "PROCEEDS_TO_SIGNATURE_CHECK"
    # No key and no signature reach this point: nothing was verified (the bug).
    return "ACCEPT"


@dataclass(frozen=True)
class Case:
    id: str
    kind: str  # pos | neg | adv
    description: str
    key: object
    algorithms: object
    header_alg: str
    signature: str
    pre_construct: str
    post_construct: str
    pre_verify: str
    post_verify: str


CASES = [
    Case("p01_empty_key_hs256", "pos", "key='' + algorithms=['HS256'], unsigned token",
         "", ["HS256"], "HS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("p02_null_key_hs256", "pos", "key=null + algorithms=['HS256'], unsigned token",
         None, ["HS256"], "HS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("p03_empty_key_rs256", "pos", "key='' + algorithms=['RS256'], unsigned token",
         "", ["RS256"], "RS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("n01_real_key_unsigned", "neg", "key='secret' + HS256, unsigned → missingSignature",
         "secret", ["HS256"], "HS256", "", "ok", "ok", "missingSignature", "missingSignature"),
    Case("n02_none_only_empty", "neg", "algorithms=['none'], key='' → legitimate unsigned",
         "", ["none"], "none", "", "ok", "ok", "ACCEPT", "ACCEPT"),
    Case("n03_none_only_with_key", "neg", "algorithms=['none'] + truthy key → post invalidOption",
         "secret", ["none"], "none", "", "ok", "invalidOption", "missingSignature", "SKIP"),
    Case("n04_empty_key_no_allowlist", "neg", "key='' + algorithms=[] → empty allowlist rejects every alg",
         "", [], "HS256", "", "ok", "invalidKey", "invalidAlgorithm", "SKIP"),
    Case("n05_real_key_with_sig", "neg", "key='secret' + signature present (never verified here)",
         "secret", ["HS256"], "HS256", "sigbytes", "ok", "ok",
         "PROCEEDS_TO_SIGNATURE_CHECK", "PROCEEDS_TO_SIGNATURE_CHECK"),
    # --- adversarial: odd types, mixed-case algorithms, empty lists ---
    Case("a01_int_key", "adv", "key=5 (typeof number)",
         5, ["HS256"], "HS256", "", "INVALID_OPTION", "invalidOption", "SKIP", "SKIP"),
    Case("a02_zero_key", "adv", "key=0 (falsy number)",
         0, ["HS256"], "HS256", "", "INVALID_OPTION", "invalidOption", "SKIP", "SKIP"),
    Case("a03_list_key", "adv", "key=[] (truthy object in JS)",
         [], ["HS256"], "HS256", "", "KEY_PREP_UNMODELED", "KEY_PREP_UNMODELED", "SKIP", "SKIP"),
    Case("a04_dict_key", "adv", "key={} (truthy object in JS)",
         {}, ["HS256"], "HS256", "", "KEY_PREP_UNMODELED", "KEY_PREP_UNMODELED", "SKIP", "SKIP"),
    Case("a05_empty_buffer", "adv", "key=Buffer.alloc(0): truthy at construct, hasKey=0 at verify",
         b"", ["HS256"], "HS256", "", "KEY_PREP_UNMODELED", "KEY_PREP_UNMODELED", "SKIP", "SKIP"),
    Case("a06_alg_None_mixed", "adv", "algorithms=['None'] is not 'none' for allowsOnlyNone",
         "", ["None"], "None", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("a07_alg_NONE_header", "adv", "allowlist ['none'], header 'NONE'",
         "", ["none"], "NONE", "", "ok", "ok", "invalidAlgorithm", "invalidAlgorithm"),
    Case("a08_alg_lower_hs256", "adv", "allowlist ['hs256'] lowercase + empty key",
         "", ["hs256"], "hs256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("a09_algorithms_not_list", "adv", "algorithms='HS256' (string, coerced to [])",
         "", "HS256", "HS256", "", "ok", "invalidKey", "invalidAlgorithm", "SKIP"),
    Case("a10_null_key_none_list", "adv", "key=null + ['none','none']",
         None, ["none", "none"], "none", "", "ok", "ok", "ACCEPT", "ACCEPT"),
]


def _run(side: str, case: Case):
    ctor = create_verifier_pre if side == "pre" else create_verifier_post
    try:
        v = ctor(case.key, case.algorithms)
    except TokenError as e:
        return e.code, "SKIP"
    try:
        return "ok", verify_token_model(v, case.header_alg, case.signature)
    except TokenError as e:
        return "ok", e.code


def evaluate_case(case: Case) -> dict:
    pre_c, pre_v = _run("pre", case)
    post_c, post_v = _run("post", case)
    ok = (pre_c, post_c, pre_v, post_v) == (
        case.pre_construct, case.post_construct, case.pre_verify, case.post_verify)
    flips = pre_v == "ACCEPT" and post_c != "ok"
    return {
        "id": case.id, "kind": case.kind, "description": case.description,
        "pre_construct": pre_c, "post_construct": post_c,
        "pre_verify": pre_v, "post_verify": post_v, "ok": ok, "flips": flips,
    }
