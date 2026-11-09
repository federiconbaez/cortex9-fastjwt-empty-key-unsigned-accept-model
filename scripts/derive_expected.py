#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv for fast-jwt CVE-2026-107720.

Does NOT import the package. Re-derives each outcome from the JS rules read
in verifier.js (pre 378422c6, post e22a151e) with its own small JS-semantics
helpers, written separately from src/fastjwtkey/model.py.
"""

def typeof(v):
    return {type(None): "object", bool: "boolean", int: "number", float: "number",
            str: "string", bytes: "object", list: "object", dict: "object"}[type(v)]

def truthy(v):
    if v is None or v is False or v == "":
        return False
    if type(v) in (int, float):
        return v != 0 and v == v
    return True

def key_prep_ok(v):
    return (type(v) is str and v != "") or (type(v) is bytes and len(v) > 0)

def construct(side, key, algs):
    allowed = algs if type(algs) is list else []
    t = typeof(key)
    if side == "post":
        only_none = bool(allowed) and all(a == "none" for a in allowed)
        if only_none:
            if truthy(key):
                return "invalidOption", allowed
        elif t not in ("string", "object", "function"):
            return "invalidOption", allowed
        elif not truthy(key):
            return "invalidKey", allowed
    else:
        if t not in ("string", "object", "function"):
            return "INVALID_OPTION", allowed
    if truthy(key) and not key_prep_ok(key):
        return "KEY_PREP_UNMODELED", allowed
    return "ok", allowed

def verify(key, allowed, alg, sig):
    hk = len(key) > 0 if type(key) is bytes else truthy(key)
    if hk and not sig:
        return "missingSignature"
    if not hk and sig:
        return "missingKey"
    if alg not in allowed:
        return "invalidAlgorithm"
    return "PROCEEDS_TO_SIGNATURE_CHECK" if sig else "ACCEPT"

INPUTS = [
    ("p01_empty_key_hs256", "pos", "", ["HS256"], "HS256", ""),
    ("p02_null_key_hs256", "pos", None, ["HS256"], "HS256", ""),
    ("p03_empty_key_rs256", "pos", "", ["RS256"], "RS256", ""),
    ("n01_real_key_unsigned", "neg", "secret", ["HS256"], "HS256", ""),
    ("n02_none_only_empty", "neg", "", ["none"], "none", ""),
    ("n03_none_only_with_key", "neg", "secret", ["none"], "none", ""),
    ("n04_empty_key_no_allowlist", "neg", "", [], "HS256", ""),
    ("n05_real_key_with_sig", "neg", "secret", ["HS256"], "HS256", "sigbytes"),
    ("a01_int_key", "adv", 5, ["HS256"], "HS256", ""),
    ("a02_zero_key", "adv", 0, ["HS256"], "HS256", ""),
    ("a03_list_key", "adv", [], ["HS256"], "HS256", ""),
    ("a04_dict_key", "adv", {}, ["HS256"], "HS256", ""),
    ("a05_empty_buffer", "adv", b"", ["HS256"], "HS256", ""),
    ("a06_alg_None_mixed", "adv", "", ["None"], "None", ""),
    ("a07_alg_NONE_header", "adv", "", ["none"], "NONE", ""),
    ("a08_alg_lower_hs256", "adv", "", ["hs256"], "hs256", ""),
    ("a09_algorithms_not_list", "adv", "", "HS256", "HS256", ""),
    ("a10_null_key_none_list", "adv", None, ["none", "none"], "none", ""),
]

print("id\tkind\tpre_construct\tpost_construct\tpre_verify\tpost_verify")
for cid, kind, key, algs, alg, sig in INPUTS:
    row = [cid, kind]
    res = {}
    for side in ("pre", "post"):
        c, allowed = construct(side, key, algs)
        res[side] = (c, verify(key, allowed, alg, sig) if c == "ok" else "SKIP")
    print("\t".join([cid, kind, res["pre"][0], res["post"][0], res["pre"][1], res["post"][1]]))
