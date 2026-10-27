# Optional gents engine validation

Evidence date: 2026-10-27. Scope: the experimental **attached chat client**,
not a managed gents runtime, live subscription or automatic switching engine.
The source contract is gents 0.21.0 at
`89f1b6760e2297b3d8a09d347c43eaf6978a8b31`.

## Initial attached-client checks

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

## Durable session continuation checkpoint

The next slice adds a UUID to every new gents launch intent, exact binding
metadata, an optional resume-source run ID and explicit `run --resume`.
Schema 5 preserves unknown session IDs on legacy runs and backs up schema 4
before adding the projection column. Its independent fixture uses schema-4 DDL
frozen from `6112a37`, a rebound gents profile and an observed pending native run.

On the same local Rust/WSL2 environment, all 105 nextest tests passed (one
intentionally ignored fixture entry). Formatting, Clippy with warnings denied,
the doctest and dependency policy passed. No new resolved packages were added.
[CI run 40578435624](https://github.com/shahzadlone/agent-swapper/actions/runs/40578435624)
passed all four jobs for implementation commit `da6b2d9`: Linux, macOS, Windows
and dependency policy. Tests and doctests passed on all three platforms;
Windows journal lifecycle stress (ten iterations), the Windows Job probe and
the Linux delegated-cgroup probe also passed. No test retries or gate changes
were needed for this checkpoint.

Local regression coverage includes:

- exact UUID agreement between CLI preview, child argv and durable run history;
- default new sessions, explicit UUID selection and same-session resume chains;
- resume after rename, refusal after binding drift, and native `-- --resume` forwarding;
- refusal past failed, nonzero, pending, attested or legacy latest attempts;
- stale plans after a newer run, wrong session/source/profile references, and
  rollback without appending an intent on refusal;
- persistence across supervisor loss before spawn and reopen;
- journal-order selection across backward clock changes, source read-only replay,
  invalid historical resume transitions and session projection tampering;
- schema-4 migration backup, unchanged legacy history and rollback on tampering.

A read-only Opus 5.5 xhigh review found no blockers in source validation,
transaction ordering or migration. Follow-up changes made preview non-reservation
explicit in text and JSON, removed argument-position assumptions, exercised a
second registry connection, expanded invalid replay/property cases and covered
pending legacy gents runs. UUIDs retain typed parsing and canonical serialization;
JSON session metadata uses the same camelCase form as run-history output.
Exact binding restoration permits manual resume, with the identity limitation
now documented and tested. Long-chain performance beyond the existing replay
and lifecycle fixtures remains unmeasured.

The client-success gate is local bookkeeping. It does not establish remote
session existence, runtime shutdown, successful task completion or safe replay
of unfinished tools. This remains manual continuation behind the experimental
engine opt-in. No dependencies or provider calls are added.

## Remaining evidence

Real authenticated runtime setup, provider/account pairs, refresh persistence,
reasoning/tool replay, macOS Keychain custody and Windows ACL privacy remain
unverified. No live credentials or provider requests were used for these checks.

The wrapper does not authenticate a local listener, contain the external runtime,
measure quota, import native sessions, control agent-wide model changes, or
perform automatic switching. A matching `runtime.json` and a free client lease
must not be interpreted as any of those guarantees.
