# 0003. Apache-2.0 without an open-core tier

- Status: Accepted
- Date: 2026-10-12

## Context

Zitadel moved to AGPL-3.0 with its v3 release and Hanko's backend is AGPL-3.0; copyleft terms
may not suit teams that embed identity code in proprietary products. Ory Kratos and Hydra are
Apache-2.0, with SCIM, SAML, organization SSO and multi-tenancy primitives offered under the
commercial Ory Enterprise License. A central goal of Clavis is to be embeddable in any project,
commercial or not, with every feature available under the same license.

Sources (October 2026): https://zitadel.com/blog/apache-to-agpl,
https://github.com/teamhanko/hanko, https://www.ory.com/docs/oel/kratos/intro

## Decision

Clavis is licensed under Apache-2.0. All features, including organizations, enterprise SSO,
SCIM and multi-tenancy, are part of the open source core. There is no enterprise edition.

## Consequences

- Companies can embed and modify Clavis without legal friction, and receive an explicit patent
  grant.
- Third parties may offer Clavis as a hosted service without contributing back.
- Sustainability must come from adoption, sponsorship, support or a hosted offering, never from
  withholding features.
