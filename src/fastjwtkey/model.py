"""Offline model of fast-jwt createVerifier key gating (CVE-2026-107720).

Ports the construction-time checks from src/verifier.js at parent
378422c6 (pre) and fix e22a151e (post). Diff lines 18-55 of
diffs/CVE-2026-107720_fast-jwt_e22a151e83bf.diff.
"""
from __future__ import annotations
from dataclasses import dataclass


class TokenError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _key_type(key) -> str:
    if key is None:
        return "object"  # typeof null === "object" in JS
    if callable(key):
        return "function"
    if isinstance(key, (bytes, bytearray)):
        return "object"
    if isinstance(key, str):
        return "string"
    return type(key).__name__


def _truthy_key(key) -> bool:
    if isinstance(key, (bytes, bytearray)):
        return len(key) > 0
    return bool(key)


def create_verifier_pre(key, algorithms):
    allowed = list(algorithms) if isinstance(algorithms, list) else []
    key_type = _key_type(key)
    if key_type not in ("string", "object", "function"):
        raise TokenError("INVALID_OPTION", "The key option must be a string, a buffer or a function...")
    return {"key": key, "allowedAlgorithms": allowed, "keyType": key_type}


def create_verifier_post(key, algorithms):
    allowed = list(algorithms) if isinstance(algorithms, list) else []
    key_type = _key_type(key)
    allows_only_none = len(allowed) > 0 and all(a == "none" for a in allowed)
    if allows_only_none:
        if key:
            raise TokenError(
                "invalidOption",
                'The key option must not be provided when the only allowed algorithm is "none".',
            )
    elif key_type not in ("string", "object", "function"):
        raise TokenError("invalidOption", "The key option must be a string, a buffer or a function...")
    elif (not key) and key_type != "function":
        raise TokenError(
            "invalidKey",
            'The key option is required unless the only allowed algorithm is "none".',
        )
    return {"key": key, "allowedAlgorithms": allowed, "keyType": key_type}


def verify_token_model(verifier, header_alg: str, signature: str) -> str:
    key = verifier["key"]
    allowed = verifier["allowedAlgorithms"]
    has_key = _truthy_key(key)
    if has_key and not signature:
        raise TokenError("missingSignature", "The token signature is missing.")
    if (not has_key) and signature:
        raise TokenError("missingKey", "The key option is missing.")
    if allowed and header_alg not in allowed:
        raise TokenError("invalidAlgorithm", "The token algorithm is invalid.")
    return "ACCEPT"


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    description: str
    key: object
    algorithms: list
    header_alg: str
    signature: str
    pre_construct: str
    post_construct: str
    pre_verify: str
    post_verify: str


CASES = [
    Case("p01_empty_key_hs256", "pos", "key='' with algorithms=['HS256'], unsigned token",
         "", ["HS256"], "HS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("p02_null_key_hs256", "pos", "key=null with algorithms=['HS256'], unsigned token",
         None, ["HS256"], "HS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("p03_empty_key_rs256", "pos", "key='' with algorithms=['RS256'], unsigned token",
         "", ["RS256"], "RS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("n01_real_key", "neg", "key='secret' with HS256; unsigned must fail missingSignature",
         "secret", ["HS256"], "HS256", "", "ok", "ok", "missingSignature", "missingSignature"),
    Case("n02_none_only_empty", "neg", "algorithms=['none'], key=''; unsigned accepted for none",
         "", ["none"], "none", "", "ok", "ok", "ACCEPT", "ACCEPT"),
    Case("n03_none_only_with_key", "neg", "algorithms=['none'] with truthy key refused post",
         "secret", ["none"], "none", "", "ok", "invalidOption", "missingSignature", "SKIP"),
    Case("n04_empty_no_algs", "neg", "key='' with algorithms=[] (no allowlist)",
         "", [], "HS256", "", "ok", "invalidKey", "ACCEPT", "SKIP"),
    Case("n05_real_key_with_sig", "neg", "key='secret', non-empty signature placeholder",
         "secret", ["HS256"], "HS256", "sigbytes", "ok", "ok", "ACCEPT", "ACCEPT"),
]


def _run(side: str, case: Case):
    ctor = create_verifier_pre if side == "pre" else create_verifier_post
    try:
        v = ctor(case.key, case.algorithms)
        construct = "ok"
    except TokenError as e:
        return e.code, "SKIP"
    try:
        return construct, verify_token_model(v, case.header_alg, case.signature)
    except TokenError as e:
        return construct, e.code


def evaluate_case(case: Case) -> dict:
    pre_c, pre_v = _run("pre", case)
    post_c, post_v = _run("post", case)
    ok = (
        pre_c == case.pre_construct
        and post_c == case.post_construct
        and pre_v == case.pre_verify
        and post_v == case.post_verify
    )
    flips = case.kind == "pos" and pre_v == "ACCEPT" and post_c != "ok"
    return {
        "id": case.id,
        "kind": case.kind,
        "description": case.description,
        "pre_construct": pre_c,
        "post_construct": post_c,
        "pre_verify": pre_v,
        "post_verify": post_v,
        "ok": ok,
        "flips": flips,
    }
