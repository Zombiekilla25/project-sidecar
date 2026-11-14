# Logging and Evidence

Project Sidecar keeps two different classes of records.

## Public GitHub record

GitHub should contain concise, sanitized engineering history:

- milestone summaries;
- qualification results and test counts;
- architecture decisions;
- public-safe failure/root-cause summaries;
- release notes and reproducible non-sensitive tests.

For longer-running development, a useful convention is:

`docs/run-logs/YYYY-MM-DD-short-description.md`

These files should summarize the result rather than mirror terminal output line-for-line.

## Private runtime evidence

Raw runtime logs and hardware evidence should remain outside the public repository when they contain or may reveal:

- local IP addresses or host paths;
- hardware serial numbers, DNA, or other machine identifiers;
- wallet addresses or credentials;
- private authority/signing material;
- proprietary binaries or FPGA bitstreams;
- private environment details;
- large repetitive traces with no public documentation value.

A public milestone can cite counts, PASS/FAIL results, hashes that are safe to publish, and a description of the root cause without uploading the underlying private evidence.

## GitHub Actions logs

If Project Sidecar later uses GitHub Actions, workflow and job logs can be inspected directly in GitHub and are useful for reproducible CI/test output. They should still avoid printing secrets or private hardware identifiers.

## Local Codex sessions

Local Codex terminal output is not automatically a GitHub log. When a session reaches a useful milestone, generate a short public-safe summary and commit that summary to the repository.

This keeps the GitHub history useful without turning the repository into a dump of private or multi-megabyte runtime traces.

## Daily milestone publication requirement

On each active Project Sidecar development day, publish at least one dated, public-safe milestone note on GitHub covering completed work, measured test/qualification results, known failures, and the next blockers. Use `docs/run-logs/YYYY-MM-DD-short-description.md` for the dated entry and link major results from the changelog or milestone index.

An agent reporting `COMMITTED` or `WORKTREE_CLEAN` is **not** proof of GitHub publication. Require a successful push to the authorized repository/branch and independently verify the remote commit SHA and web URL. If no upstream or credentials are available, preserve a local bundle/patch and explicitly report `GITHUB_PUBLICATION_BLOCKED` instead of claiming a completed daily update. Do not invent a new remote, force-push, or merge unreviewed code.

Do not publish private logs, environment identities, production secrets, unreviewed source, or unsupported qualification claims simply to meet the cadence. A documentation-only milestone may be published while code integration is blocked; identify that distinction clearly.

If a day is missed, publish a dated catch-up record clearly identifying the work date and publication date. Do not backdate the commit.
