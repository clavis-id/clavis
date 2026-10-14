# OpenID conformance suite

This directory runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against the current commit of Clavis (ADR 0017). CI runs it nightly on `develop`, on pull
requests that change protocol code, and on demand.

## Running it

```
make conformance
```

The run needs Docker, Go and `openssl`, and takes a few minutes. It writes to `results/`:

- one exported archive per plan, with the full logs;
- `clavis.log`, the Clavis logs;
- `suite.log`, the suite logs.

Run selected plans by passing `<plan> <configuration file>` pairs:

```
conformance/run.sh oidcc-config-certification-test-plan config/clavis-oidcc.json
```

With `KEEP=1`, the containers stay up afterwards. The suite's web interface is then available at
https://localhost.emobix.co.uk:8443; the name resolves to 127.0.0.1. Stop the containers with
`docker compose --file conformance/compose.yaml --profile runner down --volumes`.

## How it works

`run.sh`:

1. Downloads the suite's runner scripts (`run-test-plan.py` and the modules it imports) at the
   pinned suite commit, and checks each file against its pinned SHA-256.
2. Builds a static Linux binary of Clavis for the Docker host's architecture.
3. Starts the services in `compose.yaml`:
   - the suite and its MongoDB and nginx;
   - Clavis with a fresh SQLite database and key encryption key;
   - Caddy, which terminates TLS for the issuer `https://clavis.test`.
4. Runs the plans in a Python container. That container installs the hash-pinned
   `requirements.txt`, waits for Clavis to be ready, and calls `run-test-plan.py`.

Every image is pinned by digest. The suite images and `SUITE_COMMIT` in `run.sh` must come from
the same suite release.

## Expected results

`expected-failures.json` lists the conditions that are known to fail or warn, and
`expected-skips.json` the test modules that are known to be skipped. Each entry states its
reason in `comment`, usually the work item that will fix it.

The run fails on:

- any failure, warning or skip not listed;
- any listed entry that no longer happens.

The second rule keeps the lists accurate and shrinking: a pull request that makes a test pass
removes its entry in the same change. When a run fails on an unexpected result, the log prints
a ready-made entry for it; investigate before copying it into the list.

## Plans and configuration

`PLANS` in `run.sh` lists the plans that run by default. Each plan uses a configuration file in
`config/` that names the discovery URL, the clients and the browser steps that fill the login
form. Plans are added as the plan for Phase 1 lands their features
(see [`docs/plans/phase-1.md`](../docs/plans/phase-1.md#conformance-progression)).

## Updating

- **Suite:** move the image tags and digests in `compose.yaml`, `SUITE_COMMIT` and the runner
  script digests in `run.sh` to the same release, then review the changes in the expected
  results.
- **Python dependencies:** edit `requirements.in` and compile `requirements.txt` in the pinned
  runner image:

  ```
  docker run --rm -v "$PWD/conformance:/w" -w /w python:3.13-slim@<digest from compose.yaml> \
    sh -c 'pip install --root-user-action=ignore -q pip-tools &&
           pip-compile --quiet --generate-hashes --strip-extras --allow-unsafe --no-header \
             -o requirements.txt requirements.in'
  ```

Dependabot proposes updates for the images and the Python dependencies.
