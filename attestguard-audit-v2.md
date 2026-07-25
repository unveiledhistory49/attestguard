# AttestGuard v2 — Audit

## Verdict

Genuine, meaningful progress — not cosmetic. `HMAC_SECRET` now fails loudly instead of falling back. `isolate_pod_network` makes real `kubectl` subprocess calls with honest success/failure reporting. `create_github_issue` makes a real authenticated HTTP call to the GitHub API when a token is present, and honestly reports when it isn't. Cosign now does real cryptographic signing and verification of a real artifact. The metrics calculation in `run_e2e.sh` was substantially rewritten to compute from real events instead of hardcoded constants. A new function, `patch_gatekeeper_constraint`, closes exactly the gap I flagged last time between the response service and the live cluster policy. This is real engineering work, not window dressing.

Two things stop this from being a clean pass:

1. **The stack still isn't deployed in the tested path.** A genuinely real `deploy/install_cluster_stack.sh` now exists — but nothing calls it. Not `e2e.yml`, not the Makefile, not `run_e2e.sh`. And even if it were called, it still wouldn't install Falco — its own header comment claims it deploys "Falco eBPF," but there's no such step in the script. I grepped the entire repo for any Falco installation command: zero matches outside the static config files. Pillar 3 is still config that has never run.
2. **The README wasn't updated to match the code.** This is the interesting one — for the first time, the *code* is more honest than the *documentation describing it*. The metrics table still has the same "measured from execution of attack syscall to Falco event generation" methodology text and the same-looking static numbers as before, even though `run_e2e.sh` now computes several of these for real. Nobody re-ran it and updated the table, or wired the table to regenerate from real output.

**Rough split rating: the code moved from ~4/10 to ~6.5/10. The README is still ~4/10 — and is now actively behind what the code can prove.**

---

## Fix list from the last audit — item by item

**1. `run_e2e.sh` Stage 4 real computed metrics** — **Substantially fixed.** `TOTAL_ATTACKS`/`TOTAL_BENIGN` are parsed from real log output. `TRUE_POSITIVES` is now conditionally set based on a real HTTP response code from a real HMAC-signed request sent to the live Flask app. MTTD/MTTR are real wall-clock timers, and — genuinely good — now *honestly labeled* as "wall-clock attack script duration" and "wall-clock HMAC alert to quarantine" rather than implying full pipeline latency. Residual gap: `FALSE_POSITIVES=0` is still a bare literal, never computed from what `benign_activity.sh` actually produced. That's the one number in this stage still asserted rather than measured — and it's the one that matters most for proving the detector isn't just saying yes to everything.

**2. Actually deploy the stack in `e2e.yml`** — **Not fixed, but the pieces now exist.** `install_cluster_stack.sh` is real (`kubectl apply` against the official Gatekeeper manifest, applies your constraint templates, constraints, network policy, and CIP) — but it's orphaned. Nothing in the repo invokes it. This is the single highest-leverage remaining fix: wiring one existing, correct script into the workflow unlocks items 2 and 6 simultaneously.

**3. Real `docker build` + `cosign sign` + `exit-code: 1` in `ci.yml`** — **Not fixed in `ci.yml`** (byte-for-byte the same as last time: still `exit-code: '0'`, still no image build, still `cosign version` as the only cosign usage). **But fixed elsewhere** — `run_e2e.sh` now does real `cosign generate-key-pair` / `sign-blob` / `verify-blob` against the actual SBOM file. Different scope than originally planned (signing an SBOM blob, not a container image, since nothing builds an image yet), but it's real, working cryptography, not a version check. One residual note: the success message isn't strictly gated on `verify-blob`'s real exit code (`|| true` on both sign and verify) — worth tightening once you're confident the happy path is solid.

**4. `slsa-github-generator` provenance** — **Not fixed.** `slsa-verifier version` is still the only invocation, still nothing to verify. Lowest-effort path: add the reusable `slsa-framework/slsa-github-generator` workflow to `ci.yml` once there's an actual build artifact for it to attest.

**5. Make `isolate_pod_network()` / `create_github_issue()` real** — **Substantially fixed, well done.** Both now make real calls (kubectl subprocess, GitHub REST API) with honest internal success/failure tracking (`k8s_api_executed`, `api_executed`) rather than blind success returns. One nitpick: `isolate_pod_network`'s outer `"status"` field still always says `"quarantined"` even when `k8s_api_executed` is `False` — a caller reading only the top-level status wouldn't see the real outcome without checking the nested field. Small fix: make `status` reflect `k8s_api_executed` directly.

**6. Wire the missing digest-revocation ↔ live Constraint link** — **Code is right, can't run yet.** `patch_gatekeeper_constraint()` does exactly the right thing — a real `kubectl patch` targeting the exact `K8sBlockRevokedDigests` object. But since nothing deploys that Constraint to the cluster in the tested path (see item 2), this currently fails gracefully every time it runs in CI rather than actually closing the loop. This is genuinely one fix away from working.

**7. Remove the hardcoded HMAC fallback** — **Fully fixed.** Now raises at startup if the env var is missing. No fallback value anywhere.

**8. Falco rule-level testing** — **Partially fixed.** New `tests/falco/validate_rules.py` does real, working structural validation — checks required fields, valid priority enums, required rule names present. Genuinely useful, genuinely real. It doesn't yet run `falco --validate` against the real Falco binary, and can't do behavioral testing, because (again) Falco is never deployed anywhere to test against. Small naming nitpick: its own docstring calls itself a "Behavioral Syntax Test Suite" — nothing in it is behavioral; it's schema validation. Minor, but it's the same "docstring claims more than the code does" pattern from your own contract, just much smaller in scope than previous instances.

---

## New finding: the README is now behind the code

This is worth calling out on its own because it's a different failure mode than last time. The metrics table (`## 4. Empirical Security & Performance Metrics`) still reads:

> **MTTD** — 12ms — *"measured from execution of attack syscall inside workload container to Falco event generation"*

But no Falco event generation happens anywhere in this pipeline right now — there's no Falco. And the script that computes MTTD today honestly labels its own number as "wall-clock attack script duration," which is a different, narrower thing than what the README describes. The README wasn't regenerated or re-checked against the improved script. Same story for FPR (`0.0%`, presented with a formal-looking $\frac{FP}{FP+TN}$ formula) — the code computing that number hardcodes it, so the formula in the README implies a computation that isn't happening for that specific figure.

Practical fix: either have `run_e2e.sh` write its real output into the README's metrics table automatically (a small script step), or replace the static table with "run `make test-e2e` for current numbers" until that's built. A stale table with a scientific-looking formula next to it is worse than no table — it looks more authoritative than it is.

---

## Small items

- `apps/response-service/__pycache__/app.cpython-313.pyc` is still committed even though `.gitignore` now correctly excludes it — the ignore rule doesn't retroactively untrack it. Run `git rm -r --cached apps/response-service/__pycache__` once, commit, done.
- `Makefile`'s `setup` target is unchanged — still `opa version && cosign version && ... && helm version` followed by `"[+] All security binaries verified."` This is the exact pattern named in the integrity contract's "pattern to watch for" section. Consider renaming the echo to something honest like `"[+] All security binaries are installed."` — installed and verified are different claims.

---

## Prioritized next fix list (shorter than last time — the gap has genuinely narrowed)

1. **Call `install_cluster_stack.sh` from `e2e.yml`**, after cluster creation and before `run_e2e.sh` runs. This one change makes items 2 and 6 demonstrably real.
2. **Add a real `helm install falco` step** to `install_cluster_stack.sh` — it already claims to do this in its own header comment.
3. **Regenerate or remove the static README metrics table** so it can't drift from what the code actually proves.
4. **Compute `FALSE_POSITIVES` for real** in `run_e2e.sh` — send a benign-labeled payload through the same path as the attack payload and check the response, the same way you already fixed `TRUE_POSITIVES`.
5. **Point the already-working cosign signing at a real built image** once `ci.yml` gets a `docker build` step, then add `slsa-github-generator` for provenance on that same image.
6. **`git rm --cached` the committed `__pycache__` file.**

Items 1–2 are the ones that turn "the pieces exist" into "the system actually runs," and they're small — you're closer to a fully-wired demo than the last two audits combined would suggest.
