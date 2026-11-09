# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only on 2026-11-09. Advisory: GHSA-8wpc-h4q6-8fxv.
CVE: CVE-2026-107720.

| Source | Used for | SHA-256 of copy |
|---|---|---|
| NVD / GHSA JSON | ID + versions ≤6.3.0 → 6.3.1 | see `sources/cve2026/SHA256SUMS` |
| commit `e22a151e83bf6d5e54e281216982d204d5665534` diff | the fix | `8bce3700953e3a48e79e3113f2805cdf0206612e8e9507a01e71916eb6683a16` |
| `src/verifier.js` at parent `378422c6` | pre | `95dfc09c102c001bcd4f7eb4f5bdf8572aaf5febe268c192972d78c06e219704` |
| `src/verifier.js` at `e22a151e` | post | `db565a05d0625c788debf142a8852172591d0a4ee3a4def2e0d5e2dd50af05d0` |

No source contained instructions addressed to a tool or agent.
