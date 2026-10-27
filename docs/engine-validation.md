# Optional gents engine validation

Evidence date: 2026-10-27. Scope: the experimental **attached chat client**,
not a managed gents runtime, live subscription or automatic switching engine.
The source contract is gents 0.21.0 at
`89f1b6760e2297b3d8a09d347c43eaf6978a8b31`.

## Local checks

Environment: Rust 1.98.0, Linux `6.18.54.1-microsoft-standard-WSL2`.

- 90 nextest tests passed; one intentionally ignored custody fixture entry.
- Documentation example passed.
- Formatting and Clippy with warnings denied passed.
- Dependency policy passed: advisories, licenses, sources and bans. Existing
  duplicate-version warnings remain; this change adds no new resolved package.
  The CLI directly uses the existing locked `uuid` package for session parsing.

The engine tests cover:

- explicit profile/engine consistency, exact case-sensitive agent IDs, IPv4/IPv6
  loopback validation and refusal of zero ports or remote addresses;
- fixed chat argv, session UUID, direct execution without a shell, selected-home
  writes, environment filtering, including inherited native authentication;
- per-engine opt-ins in both the CLI and core API, raw argument and login refusal;
- missing, mismatched, malformed and oversized local runtime records, including upstream's unbracketed IPv6 form and a copied
  record naming a different home;
- external custody after client exit, failed spawn and operator attestation;
- refusal of exit labels belonging to the other engine or unobserved clients;
- leased rebinding, address uniqueness, stale-plan refusal and retained homes;
- backed-up schema 1/2/3 upgrades, preservation of observed pending runs, and
  rollback without erasing projection or schema tampering;
- comparison output without opening storage and dashboard ownership disclosures.

## Review

Claude Opus 5.5 at xhigh effort reviewed the architecture read-only. Its findings
led to dedicated agent-ID validation, strict binding invariants, engine-specific
custody, local runtime address checks, environment isolation, leased rebinding
and explicit listener/authentication disclosure. Its migration suggestion was
checked against SQLite behavior; the implementation copies child projections,
drops children before the parent with foreign keys enabled, restores actual
rows, removes scratch tables, then verifies against journal replay before commit.

A second read-only Opus 5.5 xhigh review found an IPv6 compatibility issue in
the runtime-state comparison, confirmed against upstream source and fixed with
a regression fixture. It also prompted more accurate session help, a home-path
check, clearer stale-profile errors, and richer migration/property tests. The
fixture uses independently frozen schema-3 DDL from `f780f97`, plus mappings,
retired/reused aliases, a finished run, an observed pending run, and the previous
schema-1-to-3 DDL shape.

The implementation also preserves native event serialization and refuses stale
launch plans after rebinding. The gents state filename and CLI arguments were
checked against pinned source, rather than accepted solely from a model review.
Review is supplemental to tests, not proof of provider or runtime isolation.

## Cross-platform CI

[Run 40559571403](https://github.com/shahzadlone/agent-swapper/actions/runs/40559571403)
passed all four jobs for code commit `5c84881`: Ubuntu, macOS, Windows and
security/dependency policy. This includes formatting, Clippy, the fixture suite,
doctests, ten Windows journal lifecycle stress iterations, the Windows Job
custody probe and the Linux delegated-cgroup probe. These custody probes test
their own primitives; they do not contain the external gents runtime.

The first macOS run caught three new migration fixtures using the `/var` parent
alias directly. `test(registry): normalize migration fixture roots on macOS`
resolved the fixture paths before calling the private-path checker, matching the
existing migration tests. The safety checks and assertions were preserved; the
corrected run passed on all three CI platforms.

## Remaining evidence

Real authenticated runtime setup, provider/account pairs, refresh persistence,
reasoning/tool replay, macOS Keychain custody and Windows ACL privacy remain
unverified. No live credentials or provider requests were used for these checks.

The wrapper does not authenticate a local listener, contain the external runtime,
measure quota, import native sessions, control agent-wide model changes, or
perform automatic switching. A matching `runtime.json` and a free client lease
must not be interpreted as any of those guarantees.
