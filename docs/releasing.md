# Releasing

Releases are built by GoReleaser from a `v*` tag on `master` (see `.goreleaser.yaml` and
`.github/workflows/release.yml`).

## Artifacts

- Archives for Linux, macOS and Windows on amd64 and arm64, with `LICENSE`, `NOTICE` and
  `README.md`.
- `checksums.txt` covering every archive.
- An SPDX software bill of materials per archive (syft).
- Multi-architecture images at `ghcr.io/clavis-id/clavis`, based on
  `gcr.io/distroless/static-debian13:nonroot`, tagged with the version and, for stable
  releases, `MAJOR.MINOR` and `latest`. Images carry a BuildKit SBOM attestation.
- Once the repository is public: a keyless cosign signature bundle for `checksums.txt`
  (`checksums.txt.sigstore.json`), keyless cosign signatures for the images, and GitHub build
  provenance attestations. These are skipped while the repository is private, because they are
  recorded in public transparency logs.

Binaries are built with `CGO_ENABLED=0`, `-trimpath`, stripped symbols and commit-based file
times, so a release can be rebuilt bit for bit from its tag.

## Cutting a release

1. Make sure `develop` is green, then open a pull request from `develop` to `master` and merge
   it with a merge commit.
2. Tag the merge commit on `master` with a semantic version, for example `v0.1.0-alpha.1`, and
   push the tag. Versions with a pre-release suffix become GitHub pre-releases.
3. The Release workflow creates a draft GitHub release. Its notes list the commits since the
   previous tag, grouped by type, followed by the image name and a link to the verification
   steps. Add a short summary of the release at the top, review the artifacts, then publish it.

Test the configuration locally with `make release-snapshot` (no signing, no SBOM, nothing
published). Pull requests that change release files run the same snapshot in CI, including a
smoke test of the image and the release binary size check.

## Running the image

Generate the key encryption key once and store it in a secrets manager:

```
clavis keys new-encryption-key
```

Then pass the same key every time the container starts, here from an environment variable of
the calling shell:

```
docker run -d -p 8080:8080 \
  -e CLAVIS_ISSUER=https://auth.example.com \
  -e CLAVIS_KEYS_ENCRYPTION_KEY \
  -v clavis-data:/var/lib/clavis \
  ghcr.io/clavis-id/clavis:<version>
```

Never generate the key inline in the run command: a container started with a different key
cannot decrypt the signing keys stored in the volume.

The image runs as an unprivileged user, stores the SQLite database in `/var/lib/clavis`,
listens on port 8080 and, when `CLAVIS_TELEMETRY_METRICS_ENABLED=true`, serves metrics on
port 9464. To apply migrations as a separate step, run `clavis migrate` with only the
`CLAVIS_DATABASE_*` settings and start the server with `CLAVIS_DATABASE_AUTO_MIGRATE=false`.

## Verifying a release

Available once releases are signed:

```
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/clavis-id/clavis/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt

cosign verify ghcr.io/clavis-id/clavis:<version> \
  --certificate-identity-regexp '^https://github.com/clavis-id/clavis/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify clavis_<version>_linux_amd64.tar.gz --repo clavis-id/clavis
```
