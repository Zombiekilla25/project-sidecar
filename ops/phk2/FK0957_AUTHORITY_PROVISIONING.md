# FK0957 issuer trust provisioning (administrator action required)

This repository contains only the canonical **NON-PRODUCTION template**
`FK0957_REMOTE_TRUST_TEMPLATE.json`. Its Ed25519 key slots are empty. The
source-pinned template SHA256 is
`64ced3c5dafb6d585d3ffa10c022599722dd85e2313bb68bb4bcae6f57a22dc1`; that
hash authenticates the template bytes, not an issuer or a production key.
Empty slots are rejected by the endpoint.

An authorized administrator must create or import the release-authority and
maintenance-handoff public keys through the organization's approved offline
key ceremony, retain private signing keys in the approved HSM/key custody
system, and record issuer identity and key fingerprints. This software run
does not generate, select, or install production keys.

Provisioning procedure:

1. Copy the canonical template to `/etc/sidecar/fk0957/remote-trust.json`.
2. Install raw 32-byte Ed25519 public keys at the distinct paths named by
   `release_public_key_path` and `handoff_public_key_path`; set each matching
   SHA256 field. Private signing keys remain in the approved HSM/key custody
   system and are never copied into this package. The template pins the key
   paths and policy; the source hash of the populated trust JSON is separately
   reviewed and compiled into the endpoint and launcher. Keep issuer names,
   `/var/lib/sidecar/fk0957/consumed-release-authorizations`,
   120-second authorization lifetime, and 86400-second manifest age unchanged
   unless a separately reviewed policy change authorizes otherwise.
3. Canonicalize with UTF-8 JSON, sorted keys, compact separators, no NaN, and
   one final newline. Set owner `root:root`, mode `0400`, one regular-file
   link, beneath root-owned non-writable `/etc/sidecar/fk0957`.
4. Independently verify issuer fingerprints and calculate the exact file
   SHA256. Update the endpoint's source-pinned `TRUST_CONFIG_SHA256` and the
   trust-config hash in the signed runtime-manifest payload in a reviewed
   release commit. Re-run the endpoint, supervisor, manifest-tampering, and
   single-use authorization tests.
5. Have the approved release authority sign the exact runtime manifest and
   handoff authority sign operation-bound handoff records. Verify signatures
   with the provisioned public keys before installation.
6. Install only through the separately reviewed administrator deployment.
   Run the dry-run package verifier before installation and the installed
   verifier after installation. Never use the template itself as production
   authority.

## Signature chain

* `FK0957_RELEASE_AUTHORITY` signs both the runtime-manifest payload and the
  release-authorization payload. The manifest binds the exact Git HEAD, clean
  state, source path/hash inventory (including the live CLI), all ten native
  runtime identities, trust-config hash, and transaction-profile hash.
* `FK0957_MAINTENANCE_AUTHORITY` signs the handoff payload. The release
  authorization binds the canonical handoff SHA256; the handoff carries the
  same authorization ID and operation ID, target, bridge release and USBFS
  observations, manifest hash, HEAD, profile, and validity window.
* The supervisor verifies all three signed objects, then creates one exclusive
  ledger entry keyed by the canonical authorization digest before child
  launch. Endpoint and transport only revalidate; they do not consume or
  replace the authorization. Public keys and signatures may be distributed;
  issuer private keys remain in administrator-controlled key custody. The
  separate evidence-signing key remains RGB-local.
* Unit tests generate ephemeral Ed25519 keys in test code only. They are not
  serialized as defaults or installed by the package.

Until these steps are complete, issuer verification, handoff verification,
supervised acquisition, and live operation remain unavailable by design.

The runtime verifier is `tools/phk2_host/verify_fk0957_runtime_manifest.py`;
the installed static launcher exposes the same verification as
`fk0957-safe-launcher --verify-runtime-manifest`. After the trust configuration
and signed manifest are provisioned at their protected paths, this command
checks the canonical Ed25519 envelope, issuer, freshness, exact
source set and bytes, Git HEAD/clean state where available, native hashes and
build IDs, trust-config hash, and fixed transaction-profile hash. The command
prints only a bounded verified/refused result. It does not sign manifests or
create issuer keys.
