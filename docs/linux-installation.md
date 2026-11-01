# Linux installation contract

The runtime validates selected installation metadata and retains the original
artifacts through real service binding. The normal managed launcher is still
disabled. These readers do not install a service, change provider configuration,
or establish namespace provenance.

## Fixed paths and identity

`SelectedInstallation::open` derives the current ordinary UID and primary GID,
requires matching real/effective identities, and reads
`/etc/agentswapper/installations/<uid>/active.json`. The production constructor
accepts no caller-selected path, UID or generation and no environment override.
The selector has exactly `schema: 1` and a nonzero, 32-character lowercase
hexadecimal `generation`.

That generation selects
`/etc/agentswapper/installations/<uid>/<generation>.json`. Its exact fields are
`schema`, `protocol`, `version`, `generation`, `user`, `group`,
`guardian_sha256`, `session_helper_sha256`, `exec_shim_sha256`,
`service_template_sha256` and `socket_unit_sha256`. Schema and protocol are 1;
version matches the runtime package version. Identity and generation must match
the selection. Each hash is nonzero lowercase hexadecimal of length 64.
Missing, duplicate, unknown or incompatible fields refuse with fixed diagnostics.

The manifest contains no executable paths or command arguments. Its validated
identity and generation derive the following locations:

| Asset | Fixed location |
| --- | --- |
| Guardian, session helper, exec shim | `/usr/libexec/agentswapper/<uid>/<generation>/{guardian,session-helper,exec-shim}` |
| Service template | `/usr/lib/systemd/system/agentswapper-<uid>-<generation>@.service` |
| Socket unit | `/usr/lib/systemd/system/agentswapper-<uid>-<generation>.socket` |
| Endpoint | `/run/agentswapper/<uid>/<generation>.sock` |

`InstalledManifest::open` and `InstalledArtifacts::open` are lower-level metadata
readers. A caller-selected generation does not create a `SelectedInstallation`,
service policy, launch permission or retirement receipt. Custom path/layout
constructors and the raw-path service policy are qualification-only; default
API doctests and dependency-feature checks enforce that separation.

## Retained file checks

The shared opener resolves components through validated root-owned directory
handles. It refuses symlinks, writable ancestry, devices, FIFOs and unprotected
regular files. Opens use close-on-exec, nonblocking and no-controlling-terminal
flags. Configurations must have mode 0644 and at most 16 KiB. Executable images
must have mode 0755, no file capabilities, and an executable, non-nosuid mount.
The caller must establish a trusted namespace independently: root UID metadata
alone is not provenance.

Every installed file must have exactly one hard link both at opening and when
its original stamp is captured. The stamp covers inode identity, link count,
size, modification/change times, mode and ownership. Later checks validate the
retained inode and reopen its protected pathname. Replacing a file with identical
bytes, replacing an ancestor or overlaying the pathname still refuses.

`InstalledArtifacts` retains the original manifest and all three images and two
unit files. Each file must match its own manifest hash. Image hashing uses bounded
positional reads up to 128 MiB; configuration keeps its 16 KiB limit. Checks before
and after reading detect changes without disturbing shared file offsets. Hashes
use the existing locked `sha2 0.10.9` dependency. The package version alone cannot
distinguish builds; artifact hashes supply that comparison.

These checks do not freeze files against trusted root or prove which bytes
systemd previously loaded. They also do not authenticate the activation endpoint.

## Admission and active generations

`ServicePolicy::installed` captures ordinary credentials, matches the manifest's
identity, validates template text, and retains the complete selection. Binding
corroborates the original manager invocation, process image, credentials and
scope. It rechecks the selector and every retained artifact before completing
admission. A selector change during admission refuses, including identical-byte
replacement. An already-admitted policy cannot be reused for another binding.

After successful binding, the policy retains its original manifest and artifacts
independently of the selector. Updating the selector does not terminate an
admitted run, including a bound run that has not yet prepared its target. Later
preparation and observation use that original binding and key. Original artifact
changes still refuse revalidation. Retirement remains independently observable
and does not manufacture an unknown target exit.

An installer must publish a new generation with independent inodes, then replace
only the selector. It must keep old generations while admitted runs retain them,
and must not hardlink-deduplicate, chmod, chown, touch or rewrite active assets.
Root can revoke availability by changing these files; this is not an immutability
or revocation protocol. Safe installation, update, rollback, removal and restart
recovery still require their own implementation and evidence.

## Qualification and evidence

The hosted fixed-user fixture uses protected metadata under its unique `/run`
prefix, two distinct generation manifests, and the actual hashes of its installed
binary and unit files. The same fixed binary occupies all three executable roles;
this is not a production three-helper installation. No local root service or real
provider account is used.

The administrator reserves names exclusively, authenticates its root-only
ownership marker and exact assets before mutation/service control, and rolls back
partial creation using retained inode identities. Generation controls atomically
replace only a reserved selector and restore the original choice. Cleanup checks
all owned metadata, image, endpoint and unit names, including dangling symlinks.
Privileged Python roles use isolated startup and explicit sibling-module loading.

| Checkpoint | Evidence |
| --- | --- |
| Installation selection, complete digests and real service policy | Full CI through `7df8703`, including both native Ubuntu suites and independent rebuilds: [41304842096](https://github.com/shahzadlone/agent-swapper/actions/runs/41304842096) |
| Path reopening with unchanged retained inode metadata | Full CI at `7791f02`: [41303860668](https://github.com/shahzadlone/agent-swapper/actions/runs/41303860668) |
| Selector replacement before final admission, after successful binding, and original image changes | Both native Ubuntu suites passed at `241ded2`: [41306656317](https://github.com/shahzadlone/agent-swapper/actions/runs/41306656317); full pipeline pending at documentation time |
| Missing/premature admission-transition mutations in ordinary observers | Both mutants built locally; native results pending |
| Vendor-unit `/lib` versus `/usr/lib` spelling | Hosted measurement added; results pending |
| Single-link admission and link additions after observation | Ordinary runtime tests passed; native controls pending |

The admission barrier and deliberately mutated observers exist only in test
builds/disposable source copies. The installed guardian remains unmodified, and
a mutation must fail at its exact intended boundary. The protected-asset matrix
also tests bounded/ambiguous JSON, every artifact's distinct hash, absent assets,
protected positive controls, replacement, in-place edits, permissions and links.

The first full installed-policy attempt exceeded an aggregate fixture deadline
because repeated hashes used an unoptimized development dependency. Optimizing
only the pinned SHA-256 dependency resolved it; no checks, bounds or deadlines
were relaxed. Both native suites and independent rebuilds passed at `71ab9af`
([41302398455](https://github.com/shahzadlone/agent-swapper/actions/runs/41302398455)).

See [production integration](linux-production-integration.md) and
[review follow-up](linux-release-review.md) for the remaining namespace,
loaded-unit/socket, clean helper bootstrap and launch-integration gates.
