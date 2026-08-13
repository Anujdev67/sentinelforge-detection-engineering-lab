# Security policy

This repository is a defensive training lab. It must only contain synthetic data and must never include production credentials, customer data, or real incident evidence.

## Supported scope

- Active development branch (`main`) and open pull requests.
- Repository configuration, CI workflows, detection content, API code, dashboard code, and documentation in this repository.

## Reporting vulnerabilities

Please report vulnerabilities privately through **GitHub Security Advisories** for this repository (`Security` tab → `Report a vulnerability`).

If Security Advisories are unavailable for your account tier, open a private maintainer channel first and do **not** post exploit details or secrets in public issues/discussions.

## Required repository security settings

Configure and keep the following GitHub settings enabled:

1. **Commit signing on `main`**
   - Require signed commits for the `main` branch.
2. **Branch protection for `main`**
   - Require a pull request before merging.
   - Require at least **1 approving review**.
   - Dismiss stale approvals when new commits are pushed.
   - Require status checks to pass before merging.
   - Require branches to be up to date before merging.
   - Require conversation resolution before merging.
   - Block direct pushes to `main` except approved admins/automation as needed.
3. **Branch cleanup**
   - Enable automatic deletion of head branches after merge (`delete_branch_on_merge`).
4. **Secret scanning**
   - Enable GitHub secret scanning and push protection when available for your plan.
   - Keep `.github/workflows/secret-scan.yml` enabled for CI secret detection.

## Merge strategy review

All three merge types are currently enabled. Recommended baseline for this repository:

- **Preferred:** `Squash merge` for linear, reviewable history of feature work.
- **Optional (maintainers):** `Rebase merge` for small, clean branches where preserving individual commits adds value.
- **Usually disable:** `Merge commit` to avoid noisy history unless maintaining multi-commit context is explicitly required.

If you choose stricter history control, keep only squash merge enabled and disable merge-commit/rebase in repository settings.

## Secure local contributor setup

1. Copy `.env.example` to an ignored `.env` and use only local, non-production values.
2. Enable commit signing locally:

   ```bash
   git config --global commit.gpgsign true
   git config --global tag.gpgSign true
   git config --global user.signingkey <your-signing-key-id>
   ```

3. Install and run local checks before pushing:

   ```bash
   make lint
   make test
   make validate
   ```

## Recommended local git hooks

Use local hooks to block unsigned commits and obvious secret leaks before push.

### `pre-push` (block unsigned commits)

Create `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if git show-ref --verify --quiet "refs/remotes/origin/main"; then
  range="origin/main..HEAD"
elif git rev-parse --verify --quiet HEAD~1 >/dev/null; then
  range="HEAD~1..HEAD"
else
  range="HEAD"
fi

for sha in $(git rev-list "${range}"); do
  if ! git verify-commit "${sha}" >/dev/null 2>&1; then
    echo "ERROR: commit ${sha} is not signed/verified."
    exit 1
  fi
done
```

### `pre-commit` (secret scan)

Create `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --no-git --config .gitleaks.toml
else
  echo "WARNING: gitleaks not installed; run 'make validate' before pushing."
fi
```

Mark hooks executable:

```bash
chmod +x .git/hooks/pre-commit .git/hooks/pre-push
```
