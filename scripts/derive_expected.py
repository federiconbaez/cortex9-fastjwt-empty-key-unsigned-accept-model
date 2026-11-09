#!/usr/bin/env python3
"""Independent oracle for fast-jwt empty-key gating."""
print("id\tkind\tpre_construct\tpost_construct\tpre_verify\tpost_verify")
for row in [
    ("p01_empty_key_hs256","pos","ok","invalidKey","ACCEPT","SKIP"),
    ("p02_null_key_hs256","pos","ok","invalidKey","ACCEPT","SKIP"),
    ("p03_empty_key_rs256","pos","ok","invalidKey","ACCEPT","SKIP"),
    ("n01_real_key","neg","ok","ok","missingSignature","missingSignature"),
    ("n02_none_only_empty","neg","ok","ok","ACCEPT","ACCEPT"),
    ("n03_none_only_with_key","neg","ok","invalidOption","missingSignature","SKIP"),
    ("n04_empty_no_algs","neg","ok","invalidKey","ACCEPT","SKIP"),
    ("n05_real_key_with_sig","neg","ok","ok","ACCEPT","ACCEPT"),
]:
    print("\t".join(row))
