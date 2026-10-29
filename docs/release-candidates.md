# Internal release candidates

CI can build an **unsigned developer-preview candidate** after the platform and
dependency jobs pass. It does not publish a GitHub release or establish that
provider isolation, automatic switching, signing, or platform notarization is
ready. Treat these archives as test artifacts.

The matrix builds the two optimized executables on its Linux, macOS and Windows
host targets using the pinned Rust toolchain. `cargo-about 0.9.3` generates the
dependency license text using [about.toml](../about.toml), with crate-specific
MPL acceptance restricted to `option-ext`. Source for `option-ext 0.2.0` is
read from the published registry archive after its SHA-256 is checked against
`Cargo.lock`; links, special files, path traversal and excessive source size
are refused. Available dependency NOTICE files and the project's license and
notices are included. This generation is a starting point for a release-specific
license and notice review; it is not a legal determination.

Before installation, CI checks the exact tool and SPDX crate archives and
extracted source against pinned hashes, then audits the tools' locked graphs.
Its [separate advisory policy](../tools/build-tools-deny.toml) has three scoped
zstd exceptions: the reviewed tools use a fresh read decoder on a built-in
SPDX cache, not the reusable-context, seekable or write-decoder APIs identified
in those advisories. These exceptions do not apply to AgentSwapper's runtime
dependency policy. Re-audit the pinned source and remove the exceptions when
the tools can use corrected dependencies. The checker is rebuilt with the
reviewed lockfile after a stock checker bootstraps its audit; development-only
dependencies are excluded from that tool audit because they are not installed.
The build marker checks that the cached binary matches the recorded build, but
is unsigned and cannot authenticate it against an attacker who can replace both.
The cached attribution tool is also not separately signed or attested.

The ZIP contains `BUILD-INFO.json` with the revision, dirty state, Rust host,
toolchain, lockfile hash, and hashes of its other contents. The build remaps
workspace and home paths, and packaging refuses binaries containing those local
paths. A build marker binds both binary hashes and the lockfile hash to the
source revision and clean/dirty state; for clean builds the packager rejects
binaries from a different revision. Dirty previews cannot prove their exact
source contents. The marker is unsigned and does not establish independent
build provenance. Entry order,
timestamps and modes are fixed. Both extracted command names are smoke-tested
with an isolated temporary home before the archive and its separate SHA-256
file are written. A clean working tree is required in CI; `--allow-dirty` is
only for local experimentation and is recorded in the manifest. Checksums
detect corruption but do not authenticate an unsigned artifact.
The packager also reruns the pinned `cargo-deny` policy on the application
graph; a successful attribution report does not replace this security check.

To reproduce the local check from a clean checkout with Python 3.11 or newer:

```sh
cargo install cargo-deny --version 0.20.2 --locked
python tools/build_audited_deny.py
python tools/build_audited_deny.py --verify-only
python tools/audit_attribution_tool.py
cargo install cargo-about --version 0.9.3 --locked --features cli
python tools/build_candidate_binaries.py
python -m unittest discover -s tools -p test_release_candidate.py
python tools/release_candidate.py --output target/release-candidate
```

The tool refuses to replace an existing archive or checksum. CI keeps unsigned
candidates as short-lived workflow artifacts. Signed distribution, artifact
attestation, reproducible-build verification, source and license review for the
final dependency graph, and macOS notarization remain release gates.
