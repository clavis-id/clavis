# Security policy

Clavis is identity infrastructure, so security reports are the highest priority work on the
project.

## Supported versions

Clavis has not published a release yet. Until v1.0, only the latest release receives security
fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the issue, the affected version or commit, and the steps to reproduce it.

Do not open public issues, pull requests or discussions about a vulnerability before a fix is
released.

## What to expect

- Acknowledgement of the report within 7 days.
- An initial assessment, including severity, within 14 days.
- Coordinated disclosure: a fix and an advisory are published together, normally within 90 days
  of the report. Reporters are credited unless they prefer otherwise.

## Scope

In scope: the code in this repository, including protocol endpoints, cryptographic handling,
session management, the hosted UI, the admin API and the release artifacts.

Out of scope: vulnerabilities in third-party dependencies that do not affect Clavis (report them
upstream), and findings that require a compromised host or administrator account.
