# 0017. OpenID conformance suite in CI

- Status: Accepted
- Date: 2026-10-14

## Context

ADR 0005 makes the OpenID Foundation conformance suite the main correctness gate for the own
protocol implementation, and the Phase 1 exit criteria name the plans that must pass. The suite
is a Java application with a MongoDB database, published as source with Docker Compose files
and a Python runner (`run-test-plan.py`) meant for CI. It drives the browser steps of each test
from configuration, and it supports lists of expected failures and skipped tests.

## Decision

- **Layout.** `conformance/` contains:
  - a Compose file that runs the suite (a pinned release, built from source and cached),
    MongoDB, and Clavis built from the current commit;
  - a throwaway certificate authority, so the suite reaches Clavis over HTTPS on the Compose
    network;
  - one configuration file per plan, including the browser steps that fill the login form;
  - the expected-failure and expected-skip files.
- **Plans.** Config OP and Basic OP with static clients (`client_secret_basic` and
  `client_secret_post`) first, then Form Post and RP-Initiated Logout.
- **Expected results.**
  - A failure that the lists do not contain fails the build.
  - An expected failure that passes also fails the build, so the list only shrinks and stays
    accurate.
  - Every entry in the lists states its reason.
- **Triggers.**
  - Nightly on `develop`.
  - On pull requests that change the protocol packages, the hosted UI or `conformance/`.
  - On manual dispatch.
  - Locally with `make conformance`.
- **Certification.** Submitting results to the OpenID Foundation remains part of the v1.0
  roadmap.

## Consequences

- Protocol regressions surface in CI with the official test suite instead of after
  certification attempts.
- The job is slow and needs Docker, so it does not run on every pull request.
- Suite upgrades are explicit changes reviewed like any dependency update.
