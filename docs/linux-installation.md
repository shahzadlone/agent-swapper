# Linux installation metadata

The shared runtime can read a bounded, root-protected installation manifest.
This is a metadata checkpoint; the production managed launcher remains disabled.
No installer, root service or provider configuration is created by this code.

`InstalledManifest::open` derives the location from an ordinary UID and a
32-character lowercase hexadecimal generation:
`/etc/agentswapper/installations/<uid>/<generation>.json`. It uses the retained
`ProtectedConfig` descriptor and rejects symlinks, writable ancestry, incorrect
ownership or mode, oversized data and changes since opening. The caller must
independently establish a trusted namespace; root ownership alone is insufficient.

The JSON has exactly these fields: `schema`, `protocol`, `version`, `generation`,
`user`, `group`, `guardian_sha256`, `session_helper_sha256`, `exec_shim_sha256`,
`service_template_sha256` and `socket_unit_sha256`. Schema and protocol are 1;
the version must equal the runtime crate's package version. UID and primary GID
must match the supplied ordinary identity. Generations and hashes must be
nonzero lowercase hexadecimal strings of exactly 32 and 64 characters.
Missing, duplicate, unknown or incompatible fields fail with a fixed diagnostic
that does not echo file contents.

The manifest contains no executable paths or arbitrary command arguments. Paths
are derived from the validated identity and generation:

| Asset | Fixed location |
| --- | --- |
| Guardian, session helper, exec shim | `/usr/libexec/agentswapper/<uid>/<generation>/{guardian,session-helper,exec-shim}` |
| Service template | `/usr/lib/systemd/system/agentswapper-<uid>-<generation>@.service` |
| Socket unit | `/usr/lib/systemd/system/agentswapper-<uid>-<generation>.socket` |
| Endpoint | `/run/agentswapper/<uid>/<generation>.sock` |

The returned hashes are expected values, not proof that the artifacts match.
A caller-selected generation does not authorize launching anything. A protected
generation selector, retained artifact hash verification, loaded-unit matching,
clean helper bootstrap and installation/upgrade/removal procedures remain open.
The package version check alone cannot distinguish two builds with the same
version; artifact hashes must establish that later boundary.

Local validation covers incompatible fields and identities, bounded input,
duplicate fields, the public API boundary, strict runtime/evaluation Clippy and
dependency boundaries. The hosted asset matrix adds six manifest controls:
valid protected data, protocol mismatch, user mismatch, unknown field, duplicate
field and a symlink. The fixture obtains the runtime version from its ordinary
probe before entering a disposable private mount namespace; missing or invalid
version input refuses before creating or mounting a fixture. Root drops its
identity before running the probe, and no fixture image is executed. Native
qualification of this checkpoint is pending.

## Retained artifact digests

`ProtectedImage::require_sha256` compares an expected SHA-256 against the
retained descriptor using bounded positional reads. Images are limited to
128 MiB; configuration retains its 16 KiB limit. Hashing does not disturb shared
file offsets. Both image and configuration reads check the original metadata
before and after reading. Reopening an image path also requires the original
inode and metadata, so identical-byte replacement refuses. Running-executable
corroboration now checks the retained image's original metadata too.

These APIs verify caller-supplied expected values; they do not yet connect all
five manifest assets or select an authorized generation. They assume trusted
root and namespace provenance, and do not freeze files against later root
changes. Hash mismatches and malformed expected hashes produce fixed messages
without echoing contents or supplied values.

The hash implementation reuses the application's locked `sha2 0.10.9` graph.
The isolated evaluator adds those same eight existing package versions; no
registry version changes in the application lockfile. The dependency-boundary
check compares their versions and checksums between the two locks.

Local digest controls cover published SHA-256 test vectors, mismatched bytes,
malformed hashes, exact size limits, overflow, empty files, multiple read blocks
and preserved file offsets. The hosted matrix adds eight controls: image and
configuration hash matches/mismatches, retained-image stability, identical-byte
replacement, in-place edits and mode changes. No fixture image is executed.
Native qualification of these digest controls remains pending.

## Complete retained artifact set

`InstalledArtifacts::open` consumes a protected manifest, derives all five paths,
opens the three executable images and two unit files, and checks each against
its own manifest hash. It retains every descriptor and the original manifest.
Before returning, it revalidates every protected path and the manifest. Later
`require_current` checks detect changes relative to those original observations.
The value is not cloneable; custom fixture locations require the qualification
feature and are absent from ordinary application builds.

This closes the connection between expected manifest hashes and retained files.
It still does not prove which unit bytes systemd loaded, select the authorized
generation, authorize execution, or freeze files against trusted-root changes.
No production launcher consumes this value yet.

The hosted matrix adds ten full-set controls with distinct bytes and hashes for
each artifact: a valid set, one mismatched file for each of the five roles,
a missing helper, and identical-byte replacement of a retained guardian,
service template or manifest. All artifacts are inert and never executed.
Local runtime tests, positive and negative API doctests, strict runtime/evaluator
Clippy, dependency boundaries and harness refusal tests pass. Native results for
the full-set controls are pending.

## Protected generation selection

`SelectedInstallation::open` reads
`/etc/agentswapper/installations/<current-uid>/active.json`. It accepts no path,
UID or generation override and requires matching real/effective ordinary UID
and primary GID. The bounded, mode-0644 protected selector has exactly two
fields: `schema: 1` and a nonzero 32-character lowercase hexadecimal `generation`.
Unknown or duplicate fields, path-like strings and incompatible schemas refuse
without echoing their contents.

The selected generation determines the manifest and all five artifacts. The
selector is retained and rechecked around artifact validation. Missing or
incompatible generations fail; the reader does not try another generation or
fall back to uncontained execution. A selector update during admission refuses,
including replacement with identical contents. This is metadata admission under
a trusted namespace, not permission to launch a process.

After admission, `into_artifacts` performs a final recheck and transfers the
admitted generation to its active-run owner. That owner must retain those
artifacts instead of selecting a newer generation during a live run. An eventual
installer must keep old assets while admitted runs still need them. No installer,
upgrade transaction, active-run transition or managed production launcher is
implemented by this reader.

The hosted matrix adds ten selection controls: valid selection, path-like
generation, unknown/duplicate fields, absent generation, incompatible manifest
version, replaced selector, replaced manifest, changed guardian and a switch
to a second complete valid generation while the first observation is held.
Custom fixture layouts remain qualification-only. Local runtime tests and
thirteen API doctests, strict runtime/evaluator Clippy, dependency boundaries
and harness refusal tests pass; native selection qualification is pending.
