# Security policy

Obscura's design, threat model and known limitations are documented in
[README.md](README.md#threat-model) and the full protocol in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" (Security Advisories) on this repository rather than
in a public issue. Include a description, affected component
(`packages/core`, `server`, `web`), and steps or a test case to reproduce.

Especially valuable reports:

* Any way for the relay server to learn message contents, file contents, or the sender of a sealed envelope.
* Any way to make a client accept keys that do not belong to the contact's account ID.
* Downgrades of the post-quantum ratchet, session desynchronisation, or replay.
* Content-Security-Policy bypasses or script injection in the web client.

## Supply chain

All cryptographic primitives come from audited, dependency-free libraries
(`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `@noble/post-quantum`) and
`hash-wasm` for Argon2id. Dependency versions are pinned and `npm audit`
reports no known vulnerabilities at release time.
