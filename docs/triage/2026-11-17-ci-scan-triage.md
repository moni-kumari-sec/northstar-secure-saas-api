# CI scan triage: first run of Semgrep and Trivy

Date: 2026-11-17 · Branch: `main` · Workflow: `.github/workflows/appsec.yml`

## Results

| Tool | Findings | Notes |
| --- | --- | --- |
| Semgrep (C# and OWASP Top 10 rules) | 7 | All the same rule, all in the workflow file. None in application code. |
| Trivy (dependencies, secrets, misconfiguration, HIGH and CRITICAL) | 0 reported | Run passed. |

## Finding: `github-actions-mutable-action-tag` (7 alerts)

- **What it means:** the workflow referenced actions by a version tag such as `actions/checkout@v4`. A tag can be moved to different code by whoever controls the action's repository, or by an attacker who gets their credentials.
- **Is it real?** Yes. This is the same weakness exploited in March 2026, when attacker-controlled tags on `aquasecurity/trivy-action` ran an infostealer in CI pipelines. See the [GitHub advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23).
- **Severity here:** low in practice (this repo has no secrets and only `contents: read` plus `security-events: write`), but the pattern is a real supply-chain risk and worth fixing in every pipeline.
- **Decision:** fix.
- **Fix:** pin each action to a full commit SHA, with the version in a comment so it stays readable. Done in the commit that adds this note.

## Related incident during setup

My first run failed because I pinned `aquasecurity/trivy-action@0.28.0`, a tag that no longer existed after the maintainers cleaned up following the compromise. The job stopped before running anything. I switched to `0.35.0`, the version the advisory lists as safe, then to its commit SHA.

## What these tools did not find

Neither scanner can see SEC-01 to SEC-03. No line of code looks dangerous in those bugs. The tenant check, the role policy and the request type are business rules, and only the tests (and a human reviewer) catch them. SAST and SCA complement testing. They do not replace it.

## Follow-ups

- Turn on Dependabot for GitHub Actions so SHA pins get update pull requests.
- Make Semgrep fail the build on new high-severity findings after the baseline is clean.
