import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from fastjwtkey.model import (CASES, evaluate_case, create_verifier_post, verify_token_model,
                              js_truthy, js_typeof, TokenError)


class TestDifferential(unittest.TestCase):
    def test_all_match(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))

    def test_positives_flip(self):
        rows = [evaluate_case(c) for c in CASES if c.kind == "pos"]
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(r["pre_verify"], "ACCEPT")
            self.assertEqual(r["post_construct"], "invalidKey")

    def test_accept_only_without_key_and_signature(self):
        for c in CASES:
            r = evaluate_case(c)
            for side in ("pre", "post"):
                if r[f"{side}_verify"] == "ACCEPT":
                    self.assertEqual(c.signature, "", c.id)
                    self.assertFalse(js_truthy(c.key) and not isinstance(c.key, bytes), c.id)

    def test_signature_with_key_never_accept(self):
        r = evaluate_case(next(c for c in CASES if c.id == "n05_real_key_with_sig"))
        self.assertEqual(r["pre_verify"], "PROCEEDS_TO_SIGNATURE_CHECK")
        self.assertEqual(r["post_verify"], "PROCEEDS_TO_SIGNATURE_CHECK")

    def test_independent_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT / "scripts" / "derive_expected.py")], text=True)
        self.assertEqual(out, (ROOT / "fixtures" / "expected.tsv").read_text())
        by = {c.id: c for c in CASES}
        lines = [l for l in out.splitlines()[1:] if l]
        self.assertEqual(len(lines), len(CASES))
        for ln in lines:
            cid, kind, pc, poc, pv, pov = ln.split("\t")
            r = evaluate_case(by[cid])
            self.assertEqual((pc, poc, pv, pov), (r["pre_construct"], r["post_construct"], r["pre_verify"], r["post_verify"]))


class TestAdversarial(unittest.TestCase):
    def test_js_semantics(self):
        self.assertEqual(js_typeof(None), "object")
        self.assertEqual(js_typeof(5), "number")
        self.assertEqual(js_typeof([]), "object")
        self.assertTrue(js_truthy([]))
        self.assertTrue(js_truthy({}))
        self.assertTrue(js_truthy(b""))
        self.assertFalse(js_truthy(0))
        self.assertFalse(js_truthy(float("nan")))

    def test_mixed_case_none_is_not_only_none(self):
        for alg in ("None", "NONE", "nOnE"):
            with self.subTest(alg):
                with self.assertRaises(TokenError) as ctx:
                    create_verifier_post("", [alg])
                self.assertEqual(ctx.exception.code, "invalidKey")

    def test_lowercase_hs256_post_still_requires_key(self):
        with self.assertRaises(TokenError) as ctx:
            create_verifier_post(None, ["hs256"])
        self.assertEqual(ctx.exception.code, "invalidKey")

    def test_empty_allowlist_rejects_every_header(self):
        v = {"key": "", "allowed": [], "keyType": "string"}
        for alg in ("HS256", "none", "", "RS256"):
            with self.assertRaises(TokenError):
                verify_token_model(v, alg, "")

    def test_function_key_passes_construct(self):
        self.assertEqual(create_verifier_post(lambda: "x", ["HS256"])["keyType"], "function")


class TestResults(unittest.TestCase):
    def test_regen(self):
        from fastjwtkey.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv", "summary.csv", "SHA256SUMS"):
                self.assertEqual((ROOT / "results" / name).read_bytes(), (Path(tmp) / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
