# Dependency decisions

The workspace and all dependency versions are locked. Own code is Apache-2.0;
dependencies retain their original licenses. `cargo deny --locked check` checks
advisories, licenses, dependency versions, and sources. Never globally disable
an advisory category to pass CI. Accepted exceptions need a specific rationale.

## Handover encryption

The manual handover feature pins `age = 0.11.3`, with optional CLI helpers,
plugins, SSH identities, and asynchronous support disabled. It uses the standard
age-v1 passphrase format, through the library's authenticated streaming API.
The application does not implement its own encryption construction. Encryption
and decryption work factors are bounded explicitly.

Age 0.12.1 was evaluated. Its unconditional HPKE/P-256 dependency graph pulls in
`crypto-bigint 0.5.5`, affected by timing variability in constant-time operations.
That dependency is absent from the selected 0.11.3 graph. No exception for this
vulnerability is present. Re-evaluate upgrading when a suitable dependency graph
passes the audit. [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).

Two narrowly scoped unmaintained-package notices are accepted in `deny.toml`:

- `RUSTSEC-2026-0374`: `basic-toml`, reached through `i18n-config` while compiling
  age's translation macros. It parses checked-in crate build metadata rather
  than imported handover files. [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0374.html).
- `RUSTSEC-2026-0173`: `proc-macro-error2`, used by the same translation macro
  chain during compilation. It does not process runtime handover input. The
  compiler is pinned; future Rust upgrades must address its compatibility warning.
  [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0173.html).

These are maintenance exceptions, not accepted cryptographic vulnerabilities.
Wrapper restrictions in `deny.toml` reject a new direct or runtime dependency
path to these packages; only the reviewed translation-macro chain is allowed.
Remove them when the translation dependency chain is maintained without adding
an affected runtime dependency. Re-check the actual graph with `cargo tree`
before changing the rationale. Do not infer audit cleanliness merely from a
package's age, version number, or continued compilation.

## Windows custody verification

The experimental Windows supervision backend and its custody examples use
exact Windows-target dependencies `process-wrap 10.0.1` and `win32job 2.0.3`,
both MIT OR Apache-2.0, plus the Microsoft Windows bindings. Native launch uses it only with the explicit experimental Windows containment
option. Only std, Job Object, and creation-flag support is enabled in
process-wrap; Tokio and tracing are disabled. The two libraries currently use
different Windows binding versions, both recorded and audited in Cargo.lock.

Source review found that process-wrap's std Job wrapper alone lacks
kill-on-close and an adequate empty-Job wait. The verification example supplies
separate root ownership and membership checks. The reusable backend instead
creates a private kill-on-close Job for each run, without assigning the
supervisor itself. Its `spawn_with` callback runs after `pre_spawn` adds
CREATE_SUSPENDED and before `wrap_child` resumes the target. It assigns the
owned process handle and invokes durable admission before returning the child.
Only the known JobObject wrapper is installed; arbitrary creation flags are
not accepted. Inner-Job termination and outer-Job membership queries avoid the
completion-port wait. `into_inner` is never called (it leaks the Job handle).

Source inspection confirmed that win32job creates an unnamed Job with null
security attributes (non-inherited handle). Its fixed membership buffer returns
query errors on overflow; those errors fail closed. A successful query's returned
PID list is the observation used here. Targeted termination uses process-wrap's
nested Job; before resume both Jobs contain exactly the suspended initial child,
so descendants inherit both. The outer Job provides kill-on-close independently.
Neither library's presence nor a clean advisory scan proves these invariants;
[backend fixtures](custody.md) must exercise them on Windows. Some internal
process-wrap failure cleanup uses an unbounded native wait; the wrapper's own
normal stop polling and admission-guard waits are bounded. A crash before the
first assignment can leak a suspended process. No new advisory or licensing
exception was added.

## Licensing and distribution

BSD-3-Clause is allowed for the RustCrypto/Dalek dependencies. The existing
MPL-2.0 exception is limited to unmodified `option-ext 0.2.0`, used by the
platform-directory helper. Preserve its license and source availability when
packaging binaries. Preserve applicable notices from every dependency; passing
cargo-deny does not itself generate a distribution's notice bundle. Provider
artwork notices remain in `assets/brand/THIRD_PARTY_NOTICES.txt`.

Upstream implementation code has not been copied into the Rust application.
The research clones and model-review transcripts are excluded from the repository.
