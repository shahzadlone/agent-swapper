# Shared Linux helper transport

The first runtime extraction moves the existing sequenced-packet transport and
bounded launch envelope into `agentswapper-linux-runtime`. Core helpers and the
isolated manager experiments now consume the same library. The crate has no
database, CLI, manager client, activation installer or process-custody receipt.
Linux production managed execution remains disabled.

This is an implementation boundary, not a new protocol. The transport retains
its descriptor truncation/refusal checks, record-versus-EOF distinction,
absolute transfer deadlines and private socket requirements. The envelope keeps
its byte/item bounds, OS-string handling, environment validation, zeroizing
buffers and cross-process argv-canary test. Its fields remain private and it has
no Debug or serialization implementation. Encoding and decoding are private;
consumers use validated capture and bounded transfer operations.

Normal dependencies are only rustix and zeroize, already used by the core.
Dependencies are Linux-targeted; other platforms compile an empty library and
the core does not depend on it there. The dependency-boundary check rejects
database, CLI, encryption application, or manager dependencies in this first
helper slice. The isolated observer lock now also pins the same zeroize version
as the root lock. No existing registry dependency version changes.

The implementation and its 17 tests moved together. One ignored receiver role
is invoked by the passing cross-process test; it is not an untested gate. The
Linux-only temporary-path test uses standard canonicalization directly instead
of the platform portability wrapper. Core compatibility imports preserve older
helper consumers; qualification consumers import the library directly.

Local validation passed 16 runtime tests (plus the receiver role they invoke),
20 remaining core supervision tests, the cross-process admission probe,
60 isolated-manager tests, strict Clippy for the runtime/core and all isolated
targets, both locked dependency audits and the dependency-boundary check.
Hosted platform, terminal, packaging and rebuild qualification remains pending.
The [production integration sequence](linux-production-integration.md) describes
the remaining installation, fresh helper, exec/journal and retirement work.
