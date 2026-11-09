from __future__ import annotations
import argparse, csv, hashlib, sys
from pathlib import Path
from .model import CASES, evaluate_case

def _write_results(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = [evaluate_case(c) for c in CASES]
    fields = ["id","kind","pre_construct","post_construct","pre_verify","post_verify","ok","flips","description"]
    with (out/"cases.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k: r[k] for k in fields})
    with (out/"summary.csv").open("w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["metric","value"])
        w.writerow(["cases", len(rows)])
        w.writerow(["ok", sum(1 for r in rows if r["ok"])])
        w.writerow(["pos", sum(1 for r in rows if r["kind"]=="pos")])
        w.writerow(["pos_flips", sum(1 for r in rows if r["kind"]=="pos" and r["flips"])])
        w.writerow(["neg", sum(1 for r in rows if r["kind"]=="neg")])
        w.writerow(["adv", sum(1 for r in rows if r["kind"]=="adv")])
        w.writerow(["adv_flips", sum(1 for r in rows if r["kind"]=="adv" and r["flips"])])
        w.writerow(["accept_with_signature", sum(1 for c, r in zip(CASES, rows) for s in ("pre_verify","post_verify") if r[s]=="ACCEPT" and c.signature)])
    with (out/"SHA256SUMS").open("w") as fh:
        for name in ("cases.csv","summary.csv"):
            fh.write(f"{hashlib.sha256((out/name).read_bytes()).hexdigest()}  {name}\n")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("case"); c.add_argument("id")
    r = sub.add_parser("results"); r.add_argument("dir")
    args = p.parse_args(argv)
    if args.cmd == "case":
        if args.id == "all":
            for case in CASES:
                row = evaluate_case(case)
                print(f"{row['id']}\tpre={row['pre_construct']}/{row['pre_verify']}\tpost={row['post_construct']}/{row['post_verify']}\tok={row['ok']}\tflips={row['flips']}")
            return 0
        case = next(c for c in CASES if c.id == args.id)
        print(evaluate_case(case)); return 0
    _write_results(Path(args.dir)); return 0

if __name__ == "__main__":
    raise SystemExit(main())
