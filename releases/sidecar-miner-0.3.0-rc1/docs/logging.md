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
