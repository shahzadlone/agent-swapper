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
Candidate and separate-runner rebuild jobs use explicit `ubuntu-24.04`,
`macos-15`, and `windows-2025` labels and record runner image, OS, compiler,
libc and Rust information. GitHub can still update those images within a label;
these labels do not pin an image digest or prove independent toolchain supply.
GitHub documents both the available [runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories)
and that [latest labels migrate](https://github.com/actions/runner-images#available-images).
The report is generated to a temporary file, using cargo-about's documented
file-output mode, so a PowerShell ancestor does not block the Windows build.

Packaging and pre-attestation checks also reject Unicode control/format
characters, non-NFC names, common case collisions, file/directory conflicts,
and Windows reserved device names. These conservative checks do not model
every filesystem's name-equivalence rules.

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
Build markers check that each cached tool binary matches the recorded build, but
are unsigned and cannot authenticate either binary against an attacker who can
replace it and its marker. They do not establish independent build provenance.

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
python tools/build_audited_about.py
python tools/build_audited_about.py --verify-only
python tools/build_candidate_binaries.py
python -m unittest discover -s tools -p test_release_candidate.py
python tools/release_candidate.py --output target/release-candidate
```

The tool refuses to replace an existing archive or checksum. CI keeps unsigned
candidates as short-lived workflow artifacts. For a push to `main`, a separate
job downloads the three candidates from that same run, verifies the target set,
checksums, source revision, lockfile hash and archive inventory, and signs a
provenance attestation. Before signing, a separate fresh hosted runner per
platform rebuilds both executables with the candidate build script, validates
its clean checkout and build marker and the matching candidate, and compares
each executable's SHA-256 against the same bounded archive snapshot whose
checksum and contents were validated. The later attestation action reads the
archive path separately, so the workflow still trusts the runner and its other
actions not to replace that path between verification and signing. This detects
differences across those runners but does not establish independent control of
the runner images, toolchain or dependency sources. It also compares the workspace version and project
license and notices with the checked-out source. It verifies the Sigstore bundle against the repository,
workflow, ref, commit and GitHub-hosted runner before storing the bundle as a
short-lived artifact. Build jobs do not receive attestation or OIDC write
permissions. Pull requests do not create attestations.

The attestation signs a statement about archive digests and the workflow that
attested them; it is not an operating-system code signature, independent proof
that source produced the bytes, or evidence that a provider is isolated. The
workflow and its actions remain part of the trust boundary. Do not select the
expected ref or commit solely from an untrusted archive when verifying it.
Signed distribution, independently reproducible builds, source and license
review for the final dependency graph, and macOS notarization remain release
gates. Attestation availability is subject to the repository's GitHub policy;
an unsuccessful attestation job must not be described as verified.

At `f206a3b`, [CI run 40822335892](https://github.com/shahzadlone/agent-swapper/actions/runs/40822335892)
successfully built the three preview archives and completed the separate
candidate verification, signing, Sigstore verification and bundle upload steps.
This evidence applies to that commit and the verifier in that run; subsequent
changes require their own successful run.

As a local reproducibility experiment, commit `ee229d5` was exported twice
with `git archive` to distinct source directories on one WSL2 Linux host
(`x86_64`, kernel `6.18.54.1-microsoft-standard-WSL2`, GCC `14.2.1`, Rust
`1.98.0`). Each clean tree was built offline with a separate target directory,
the same home and source path remaps, and `SOURCE_DATE_EPOCH=0`. Byte comparison
matched both binaries: `aswp` SHA-256
`c42683b314a8e925dc2d7e6e997c583509bb58a885217a9490e0b635789de397`, and
`agentswapper` SHA-256
`bf6a9e9e22e79685bbbc2b6a9de6a5b887efceb0d7a809728f5d0ce744ba29e6`.
Both builds shared a host, toolchain and dependency cache, and were not compared
to a candidate archive. This is not independent reproduction or cross-platform
evidence; the release gate remains open.

The first separate-runner comparison with diagnostics at `faa2c5e` did not
reproduce both candidate executables: the Linux `agentswapper` and Windows
`agentswapper.exe` hashes differed, and signing was skipped. See the
[Linux job](https://github.com/shahzadlone/agent-swapper/actions/runs/40829068872/job/123301885114)
and [Windows job](https://github.com/shahzadlone/agent-swapper/actions/runs/40829068872/job/123301885194).
The tool stopped at the first mismatch, so those results do not determine
whether the `aswp` binaries matched. The cause has not been established.
