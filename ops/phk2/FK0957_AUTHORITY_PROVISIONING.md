# FK0957 issuer trust provisioning (administrator action required)

This repository contains only the canonical **NON-PRODUCTION template**
`FK0957_REMOTE_TRUST_TEMPLATE.json`. Its Ed25519 key slots are empty. The
source-pinned template SHA256 is
`54f448b1b04385c267c20525738195610c96875b056da83ad16bf7f68dc0b019`; that
hash authenticates the template bytes, not an issuer or a production key.
Empty slots are rejected by the endpoint.

An authorized administrator must create or import the release-authority and
maintenance-handoff public keys through the organization's approved offline
key ceremony, retain private signing keys in the approved HSM/key custody
system, and record issuer identity and key fingerprints. This software run
does not generate, select, or install production keys.

Provisioning procedure:

1. Copy the canonical template to `/etc/sidecar/fk0957/remote-trust.json`.
2. Fill the two public-key slots with base64-encoded 32-byte Ed25519 public
   keys. Keep issuer names, `/var/lib/sidecar/fk0957/consumed-release-authorizations`,
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
