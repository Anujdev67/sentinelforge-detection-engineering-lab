# Security policy

## Supported version

Security fixes are applied to the current `main` branch. SentinelForge is a local,
synthetic-data portfolio lab and is not an internet-facing security product.

## Report a vulnerability

Do not open a public issue containing a secret, exploit detail, personal data, or
unpatched vulnerability. Use GitHub's **Private vulnerability reporting** feature on
the repository Security tab. If that feature is unavailable, contact the repository
owner privately through the verified contact method on the GitHub profile and share
only the minimum reproduction details.

Include the affected path, impact, safe reproduction steps, and suggested mitigation.
Do not test against systems, tenants, identities, or data you do not own.

## Secret exposure response

1. Revoke or rotate the exposed value at its issuing platform.
2. Review provider and GitHub audit logs for use.
3. Remove the value from the working tree and Git history using an approved history
   rewrite process.
4. Invalidate caches and artifacts that could contain the value.
5. Run Gitleaks across the full history and rerun all security workflows.
6. Document the incident without reproducing the secret.

## Security boundaries

- Synthetic telemetry only; no production or customer data.
- The API has no authentication and is restricted to loopback by the supported
  Docker Compose configuration.
- External reputation lookups are read-only, disabled by default, use fixed provider
  endpoints, reject unsafe observables, and read keys only from ignored environment
  configuration.
- SOAR containment remains approval-gated local simulation.
- Terraform is validation-only; no project command runs `terraform apply`.
- This repository cannot guarantee the security of unsupported public deployments.
