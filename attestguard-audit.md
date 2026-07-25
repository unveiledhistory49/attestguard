# AttestGuard v1 — Audit

## Verdict

You set yourself six guardrails after SecureLoop, specifically to prevent claims outrunning implementation. Real, visible effort went into that — CI exists this time, the Rego test suite is genuine, HMAC auth is correctly built and tested. But four of the six guardrails are violated in the actual code, in specific and traceable ways, and one violation (the hardcoded benchmark numbers) is more serious than anything in SecureLoop — it's not an inflated interpretation of a real measurement, it's numbers that were never computed at all.

**Same rating logic as last time: as a narrated demo, ~7/10. As a repo someone reads line by line, ~4/10** — and the fabricated metrics specifically would be the kind of finding that ends an interview early if discovered live, because it looks deliberate in a way the SecureLoop issues didn't.

---

## Guardrail-by-guardrail scorecard

**1. "Authentic binary executables... invoked directly"** — **Partial.** Syft is genuinely invoked (`syft dir:apps/target-service -o json`). Trivy is genuinely invoked. But `cosign` is installed and only ever has `cosign version` run against it — it never signs an image, because no image is ever built in this pipeline. `slsa-verifier` is installed and only ever has `slsa-verifier version` run — there's no provenance file anywhere for it to verify, and the actual `slsa-github-generator` workflow that would produce one is absent entirely.

**2. "Provable CI/CD... fail explicitly on bad inputs"** — **Fails as configured.** `trivy-action` is called with `exit-code: '0'`, which means the scan step cannot fail the job regardless of what it finds. There's no step anywhere that actually builds a container image, so nothing gets scanned-as-deployed or signed. `ci.yml`'s job is literally named "Build, SBOM, Vulnerability Scan & SLSA Provenance" — of those four things, only SBOM generation happens for real.

**3. "Dual-corpus... True-Positive and True-Negative... for every OPA Rego policy and Falco eBPF rule"** — **True for Rego, not demonstrated for Falco.** `tests/rego/` has real test files with real TP/TN assertions, and they run in CI via `opa test`. Genuinely good. But there is no `helm install falco` (or any Falco install) anywhere in the repo — I grepped the whole tree. `deploy/falco/rules/attestguard_rules.yaml` is a real, syntactically reasonable rules file, but nothing ever loads it into a running Falco instance, so its detection behavior is unverified, TP or TN.

**4. "Empirical... exact measurement methodology"** — **Fails, and this is the important one.** In `tests/e2e/run_e2e.sh`:
```bash
TOTAL_ATTACKS=3
TRUE_POSITIVES=3
FALSE_POSITIVES=0
TOTAL_BENIGN=3
TRUE_NEGATIVES=3
...
MTTR_MS=125
```
These are bare constant assignments, not computed from anything the preceding `exploit_rce.sh` / `benign_activity.sh` calls actually did. The script would report the identical "100% TPR / 0% FPR" even if it detected nothing, because nothing here reads Falco/Falcosidekick output — and as noted above, nothing here even deploys Falco. `MTTD_MS` is at least *derived* from a real timer, but it's timing how long the bash script `exploit_rce.sh` takes to execute on the CI runner — not "attack syscall to Falco alert," which is what the README claims it measures. The README's metrics table presents all of this with a statistical formula ($\frac{TP}{TP+FN}$) that implies real computation. It isn't.

**5. "Zero hardcoded secrets"** — **Mostly true, one gap.** `HMAC_SECRET` correctly reads from an env var — real improvement over SecureLoop's fully-hardcoded key. But the fallback default is a string literal in source: `os.environ.get("ATTESTGUARD_HMAC_SECRET", "attestguard-dev-secret-key-32bytes!")`. If the env var isn't set (easy to forget in a demo or a misconfigured CI job), it silently signs with a value anyone reading the repo already knows. Fine to have a dev default; not fine for it to be silently usable in anything resembling production.

**6. "Specific parameterized revocation... exact digests"** — **True at the policy layer, missing the live wiring.** `k8sblockrevokeddigests.rego` and its test are genuinely well done — matches on exact digest strings, has real TP/TN cases. But this rule reads `input.parameters.revokedDigests`, which in real Gatekeeper usage comes from the `Constraint` object's parameters field in the live cluster. Nothing in this codebase updates that live object when the response service writes a new digest to its local JSON file. The two halves are each correct in isolation; there's no code connecting them.

---

## What's genuinely real and good

- The `opa test` suite is real, runs in CI, and has honest true-positive/true-negative pairs for every constraint template.
- HMAC signature verification in the response service is correctly implemented (`hmac.compare_digest`, proper rejection on missing/invalid signature) and correctly unit-tested, including the 401 paths.
- Syft SBOM generation is a real, working step.
- The digest-revocation Rego logic itself, and its tests, are solid.
- Writing the six guardrails into the README as an explicit contract is a genuinely good practice — it made this audit faster because I had a rubric you'd already agreed to.

## The pattern to watch for going forward

Across several places, "the binary is installed and its `--version` runs" got treated as equivalent to "the tool did its job": `cosign version`, `slsa-verifier version`, `Makefile`'s `setup` target checking seven tools with `--version`/`version` calls and declaring "[+] All security binaries verified." Installing a tool correctly is necessary but proves nothing about the pipeline — worth a specific gut-check before shipping: *does this line call the tool to do the actual work, or just confirm it exists?*

## Prioritized fix list

1. **Fix `run_e2e.sh` Stage 4 immediately.** Have it actually parse the output of the attack/benign scripts (or, once Falco is deployed, query Falcosidekick/Falco's own output) to compute TP/FP/TN/FN for real. If a real number isn't available yet, print "not yet measured" — don't print a plausible-looking fake one. This is the highest-priority item by a wide margin.
2. **Actually deploy the stack in `e2e.yml`**: `helm install` policy-controller, Gatekeeper, and Falco into the `kind` cluster before running any tests against them. Right now the cluster is created and then nothing is installed into it.
3. **Add a real `docker build` + `cosign sign --keyless` step to `ci.yml`**, and set `exit-code: '1'` on the Trivy step (or explicitly justify why not, in the README, rather than silently defeating the gate).
4. **Add the actual `slsa-framework/slsa-github-generator` container workflow** to produce a provenance file, then have `slsa-verifier` verify that specific file — not just print its own version.
5. **Make `isolate_pod_network()` and `create_github_issue()` real** — a Kubernetes client call (patch/apply the quarantine NetworkPolicy against a real API server) and a real authenticated call to GitHub's REST API. Keep the existing unit tests; add ones that mock the external calls and assert they were made with the right arguments, rather than just asserting the function returns a success-shaped dict.
6. **Wire the missing link**: something that reads the response service's revoked-digest file and patches the live Gatekeeper `Constraint`'s `parameters.revokedDigests`, so the feedback loop is closed in a running cluster, not just correct in two separate unit tests.
7. **Drop the hardcoded HMAC fallback default**, or fail startup loudly if the env var isn't set.
8. **Add Falco rule-level testing** — at minimum `falco --validate` in CI, plus one behavioral test per custom rule once Falco is actually deployed in the e2e job.

Items 1–3 are the ones to do before anyone else looks at this.
