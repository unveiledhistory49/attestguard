# AttestGuard — Secure Software Supply Chain & Workload Protection

*(working title — rename freely)*

## Guardrails (learned from SecureLoop, applied from day one)

Before any architecture: a short contract this project has to satisfy that the last one didn't.

1. Every tool named in the README is an actual CLI/binary invocation somewhere in the code — no hand-rolled script standing in for a real tool while claiming its name.
2. Every automation claim is backed by a real `.github/workflows/*.yml` that runs on `pull_request` — provable by showing it fail on a bad input.
3. Every detection or policy ships with both a true-positive *and* a true-negative test. No rule merges without proof it doesn't fire on benign input.
4. Every metric in the README states its measurement methodology in the same sentence as the number.
5. No secrets — including "internal" ones like signing or HMAC keys — hardcoded in source. Use env vars, OIDC, or keyless flows.
6. Anything "auto-generated" (a policy, a rule, a test) is parameterized by the specific finding, not a generic template that happens to be valid syntax.

## The pitch

SolarWinds and the 2024 xz-utils backdoor are the two incidents every AppSec team now points to when justifying supply-chain security budget — they're not abstract anymore. This project treats the build pipeline and the runtime cluster as the security boundary: you can't trust an image just because it built successfully, and you can't trust a pod just because it passed admission — so you verify at build time, verify again at deploy time, and watch it at runtime.

It's also the real version of what SecureLoop's Pillar 1 only pretended to be — same underlying goal (shift-left supply chain security), actually wired this time.

## Architecture overview

```
 BUILD                DEPLOY                    RUNTIME
 ┌────────────┐       ┌───────────────────┐     ┌──────────────────┐
 │ CI: build   │       │ kind cluster       │     │ Falco (eBPF)      │
 │ → Syft SBOM │──────▶│ policy-controller  │────▶│ watches syscalls  │
 │ → Trivy scan│ push  │ (verifies cosign   │deploy│ in running pods   │
 │ → cosign    │ image │  signature)        │     │                    │
 │   keyless   │       │ + Gatekeeper/Rego  │     │ Falcosidekick →    │
 │   sign      │       │ (non-root, no      │     │ Slack + response   │
 │ → SLSA prov.│       │  privileged, no    │     │ service            │
 │   (slsa-gh- │       │  :latest, limits)  │     └────────┬───────────┘
 │   generator)│       └────────────────────┘              │
 └────────────┘                 ▲                          │
        ▲                       └────── feedback loop ──────┘
        └─────────────────── (confirmed runtime compromise →
                               deny that exact image digest +
                               file GitHub issue)
```

## Component breakdown

**Target workload** — two small services, each with a `vulnerable` and `hardened` Dockerfile:
- `vulnerable`: full `node:18` base (not slim), runs as root, one deliberately pinned dependency with a known CVE, `ADD` instead of `COPY`, leftover shell/curl in the final image, `:latest` tag, a secret baked into an `ENV` instruction.
- `hardened`: multi-stage build → distroless or minimal Alpine base, non-root `USER`, pinned digest not tag, patched dependency, secret injected at runtime via a mounted Kubernetes Secret, not baked into the image.

**Pillar 1 — Build-time supply chain security** (real, CI-wired from the start)
- GitHub Actions: build → SBOM via **Syft** → vulnerability scan via **Trivy** against the SBOM, failing the build on critical/high CVEs → sign the image with **cosign** using GitHub OIDC keyless signing (no private key to manage or leak) → generate provenance via the `slsa-framework/slsa-github-generator` container workflow, run as an isolated job separate from the build step. This is a real, off-the-shelf, GA tool — used correctly, it genuinely produces **SLSA Build Level 3** compliant provenance, verifiable with `slsa-verifier`. Only put that claim in the README once `slsa-verifier` actually validates your attestation in CI — that's the difference between this and SecureLoop's unearned SLSA claim.
- Push signed image + SBOM + provenance attestation to GHCR (free for public repos).

**Pillar 2 — Deploy-time admission control**
- Local **kind** cluster (free, no cloud cost, can even run inside GitHub Actions for CI-level e2e tests).
- **Sigstore policy-controller** — installed via Helm, opted in per-namespace via the `policy.sigstore.dev/include: "true"` label, enforcing a `ClusterImagePolicy` that rejects any image without a valid cosign signature. This is the purpose-built tool for this specific job — first-class cosign integration, no extra plumbing required.
- **OPA Gatekeeper + Rego** for everything else: deny root containers, deny `privileged: true`, deny missing resource limits, deny `:latest` tags. Every `ConstraintTemplate` gets a companion `_test.rego` file tested with `opa test` — real unit tests, both true-positive (bad spec → denied) and true-negative (compliant spec → allowed).

**Pillar 3 — Runtime workload protection**
- **Falco** deployed in-cluster (real eBPF/kernel syscall monitoring — CNCF project, industry-standard for this).
- Stock rules plus 2–3 hand-written custom rules for realism and to prove you can author them, not just enable defaults — e.g. shell spawned inside a container, a package manager (`apt`/`apk`) executed in a *running* pod (classic post-exploitation tooling install), an unexpected outbound connection off an allowlist.
- **Falcosidekick** routes alerts to Slack (real webhook, verifiable delivery) and to a small response service.
- Automated response: on a high-severity alert, the response service calls the Kubernetes API to isolate the pod — apply a deny-all `NetworkPolicy` and/or delete it — and this gets *verified*, not just logged: the e2e test confirms the pod is actually gone or network-isolated afterward, the way SecureLoop's IP-block was genuinely verified (keep doing that part).

**The feedback loop, done right this time** — when Falco confirms a real compromise indicator on a specific pod, the system does two things automatically: (1) updates the Gatekeeper policy to deny that *exact image digest* going forward — not a generic pattern that happens to be valid Rego — and (2) files a GitHub issue linking the specific syscall event to the image, prompting a rebuild. The test for this component should assert the generated policy actually blocks a redeploy of that digest and does *not* block an unrelated, clean image — which is exactly the specificity check SecureLoop's synthesizer failed.

## Testing strategy

1. **Unit** — `opa test` against every Rego rule: bad pod spec denied, compliant pod spec allowed. Falco rules validated with `falco --validate`, then behaviorally confirmed by generating the exact syscall pattern in a sandboxed container and checking the rule fires.
2. **Integration** — CI test that deliberately adds a known-CVE dependency and asserts the Trivy step fails the build; a `kind` cluster spun up inside CI where you `kubectl apply` an unsigned-image manifest and assert it's rejected, then a compliant manifest and assert it's accepted — real API server responses, not mocks.
3. **E2E** — full pipeline: build a vulnerable image → CI blocks it → fix it → CI passes, signs, generates provenance → deploy to `kind` → exec into the running pod and issue a real attack command (spawn a shell, install `netcat`) → confirm Falco fires within a measured window → confirm the Slack alert lands → confirm the response service actually isolates the pod.
4. **Red-team regression + false-positive control** — a corpus of N attack simulations *and* a corpus of M benign operational actions (normal startup, legitimate health-check curl, routine log rotation). Compute real TPR *and* real FPR from the combined corpus — this is the exact test SecureLoop skipped.
5. **Detection-of-absence** — an external heartbeat check on Falco/Falcosidekick's own health; if the runtime monitor goes dark, that itself alerts.
6. **Honest metrics** — MTTD measured as real wall-clock time from "attack script executes the syscall-triggering command" to "alert received by the Slack webhook receiver," averaged over multiple trials, methodology stated in the README next to the number.

## Milestone plan (~7–9 weeks, part-time)

| Phase | Focus | Est. time |
|---|---|---|
| 0 | Scaffold, guardrails contract, pin tool versions | 2–3 days |
| 1 | Vulnerable + hardened Dockerfiles for the target workload | 3–5 days |
| 2 | Real CI: build → SBOM → scan → cosign sign → SLSA provenance, actually gating PRs | 1.5–2 weeks |
| 3 | `kind` + policy-controller + Gatekeeper/Rego, with `opa test` coverage on every rule | 1.5–2 weeks |
| 4 | Falco + Falcosidekick + Slack + custom rules, validated | ~1 week |
| 5 | Automated pod isolation response, verified end-to-end | 4–5 days |
| 6 | Feedback loop (digest-specific deny policy + GitHub issue) | 3–4 days |
| 7 | Adversary emulation + benign-traffic FP corpus + honest metrics | ~1 week |
| 8 | README, architecture diagram, demo clip, write-up | 3–5 days |

## Cost note

Genuinely $0 to build: `kind` runs locally (or inside free GitHub Actions minutes), GHCR is free for public repos, Slack webhooks are free, Sigstore's Fulcio/Rekor keyless signing is free public infrastructure. No cloud VM needed this time.

## What this proves to a reviewer

Real Kubernetes admission control experience — a genuinely specialized skill most candidates only have opinions about, not implementations of. Real runtime security with eBPF-based monitoring, which is rarer still. Real supply-chain security (SBOM, signing, provenance) mapped to the exact incidents (SolarWinds, xz-utils) that made this a board-level concern. And if you mention the SecureLoop postmortem in your writeup — here's a mistake I made, here's the checklist I built so I wouldn't repeat it — that's a stronger interview story than either project alone.

## Stretch goals

- Extend `slsa-verifier` checks into the admission layer itself — reject not just unsigned images but images whose provenance doesn't match an expected source repo/branch.
- A drift detector comparing what's actually running in the cluster against what CI last approved, flagging anything deployed outside the pipeline.
- Chaos-test the response service itself: kill it mid-incident and confirm the isolation action still eventually completes (retry/idempotency), rather than silently failing.
