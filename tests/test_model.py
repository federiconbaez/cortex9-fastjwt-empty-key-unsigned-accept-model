import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from fastjwtkey.model import CASES, evaluate_case, create_verifier_post, TokenError

class TestDifferential(unittest.TestCase):
    def test_all_match(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))
    def test_pos_flip(self):
        flips = [evaluate_case(c) for c in CASES if c.kind == "pos"]
        self.assertEqual(len(flips), 3)
        for r in flips:
            self.assertTrue(r["flips"], r)
    def test_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT / "scripts" / "derive_expected.py")], text=True)
        lines = [ln for ln in out.splitlines() if ln and not ln.startswith("id")]
        by = {c.id: c for c in CASES}
        self.assertEqual(len(lines), len(CASES))
        for ln in lines:
            cid, kind, pc, poc, pv, pov = ln.split("\t")
            c = by[cid]
            self.assertEqual((pc, poc, pv, pov), (c.pre_construct, c.post_construct, c.pre_verify, c.post_verify))

class TestAdversarial(unittest.TestCase):
    def test_empty_bytes(self):
        with self.assertRaises(TokenError) as ctx:
            create_verifier_post(b"", ["HS256"])
        self.assertEqual(ctx.exception.code, "invalidKey")
    def test_function_key(self):
        v = create_verifier_post(lambda: "x", ["HS256"])
        self.assertEqual(v["keyType"], "function")

class TestResults(unittest.TestCase):
    def test_regen(self):
        from fastjwtkey.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv", "summary.csv", "SHA256SUMS"):
                self.assertEqual((ROOT / "results" / name).read_bytes(), (Path(tmp) / name).read_bytes())

if __name__ == "__main__":
    unittest.main()
