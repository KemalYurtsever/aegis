# Repository publication privacy

The repository distributes application code, synthetic fixtures, reviewed demo
screenshots, and public IEEE vendor-prefix registries. It must not distribute
operator inventory, scan/capture output, addressing plans, device identifiers,
operational status, credentials or machine-specific validation reports.

Screenshots show a **synthetic DEMO inventory**, not an operator's network.
Documentation uses reserved example addresses; tests use documentation or
benchmarking ranges. Loopback, multicast, netmask and explicitly listed public
DNS examples are generic protocol/configuration values, not observed targets.
IEEE registries map vendor prefixes to public organization records; they are
not a list of discovered devices or individual device MACs.

## Local gate

From the repository root:

```powershell
.\backend\.venv\Scripts\python.exe tools/test_repository_privacy.py
.\backend\.venv\Scripts\python.exe tools/repository_privacy.py --worktree
.\backend\.venv\Scripts\python.exe tools/repository_privacy.py --history HEAD
git config --local core.hooksPath .githooks
```

The commands respectively test the guard, inspect versionable local files,
inspect every reachable committed file/message version, and enable local
pre-commit/pre-push hooks. The guard uses Python's standard library and reports
only paths/rules, never matched identifier values. If running without a backend
virtual environment, use a working Python 3 interpreter instead.

Pre-commit scans staged content; pre-push scans the actual commit graph being
pushed. The GitHub workflow scans history too, but CI is detection **after** a
push: it cannot prevent initial public exposure. Enable the local hooks.

The guard rejects runtime/secret artifacts, non-synthetic address/MAC literals,
personal hostnames/paths, common credential material and unreviewed binary
files/images/documents. Reviewed assets and public vendor registries are
allowlisted by exact SHA-256 digest in `tools/privacy-approved-files.json`.
Changing their bytes requires review, not automatic reapproval.

Never commit `.env`, local secret files, SQLite databases, database sidecars,
logs, reports, backups, attachments or PCAPs. Sanitized `*.example` configuration
files may be published. Keep private audit reports and recovery bundles outside
the Git repository.

## Review boundaries

Pattern checks are not a semantic proof: a free-text device alias, an encoded
identifier, an image or a data export can carry information without matching
an address pattern. Inspect proposed diffs and review images before approval.
Do not publish real-network data merely because the guard passes.

History cleanup changes commit IDs. Old clones must be replaced or carefully
rebased onto the cleaned history, never merged back. GitHub may retain old
commit views after a force push; forks/clones cannot be recalled by this
project. Complete server-side removal can require GitHub Support to remove
cached views and garbage-collect unreferenced objects.
[GitHub's removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
