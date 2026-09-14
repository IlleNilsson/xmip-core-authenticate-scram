# xmip-core-authenticate-scram

Authenticate by scram: verifies a SCRAM-SHA-256 exchange against stored verifiers. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

Declared and not yet written; `architecture.toml` carries the maturity. When
it is written it implements `Authenticator`, one mechanism at one gate (ADR-0050).
What it may depend on is `repository-model.md` section 4 and ADR-0044: its
capability, and no sibling.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
