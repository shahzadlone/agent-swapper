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
check compares their versions and registry sources between the two locks;
Cargo validates the locked archive checksums.

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

The first digest checkpoint (`5f3469c`) passed the asset matrix on both native
runners. Ubuntu 22.04 then stopped at the dependency-boundary step, whose new
`tomllib` import required Python 3.11. The checker now uses Cargo's JSON metadata
on the older interpreter too. Native rerun of that correction is pending.

## Selected artifacts in service policy

`ServicePolicy::installed` captures the current caller's ordinary credentials,
requires the selected manifest identity to match, and retains the complete
selection. It checks the retained template's text and uses its actual protected
path and guardian handle during the existing loaded-service and original-process
checks. The selector remains live through the final binding recheck. Only then
does the policy retain the admitted artifacts independently of the selector.
Active rechecks validate all original artifacts and the original manifest.

The read-only `ServicePolicy::require_current` supports checking retained files
before connection. It does not observe a manager or admit a process. The explicit
fixed-path policy remains available for independently authorized locations.
Neither constructor grants execution authority or verifies the loaded socket
unit and endpoint; production connection/bootstrap integration is still open.

Native selection controls now hold the actual selected service policy before
mutating its files. A paired control hands off the admitted artifacts before
switching to another complete generation and requires those original artifacts
to remain valid. This tests installation metadata lifetime; it is not yet a
real manager binding through the new installed constructor. Existing native
service binding uses the explicit constructor. Both paths still need their
stated evidence before a production managed launcher is enabled.

Local runtime/manager tests, nineteen combined doctests, all 49 evaluator tests,
strict manager/evaluator Clippy and dependency boundaries pass. The added policy
constructor and generation-lifetime controls require their native CI result.

## Real-service qualification consumer

The fixed-user activation fixture now creates an additional protected manifest
and selector under its unique `/run/aswp-activation-<run>-<attempt>` prefix. It
uses the exact installed guardian and unit-file hashes. The one fixture binary
contains all test roles, so its image occupies the three image roles in this
qualification layout; this is not a production three-helper installation.
Explicit custom locations are feature-gated and still undergo the same identity,
generation, file-protection and digest checks.

The ordinary observer reports the runtime version before any privileged fixture
operation. The administrator validates that bounded value, exclusively creates
the metadata, records the version in its root-only ownership marker, and verifies
the metadata before service control and removal. Invalid versions and changed
metadata refuse before creating files or controlling services. Partial creation
uses the existing inode-specific rollback. Cleanup reconstructs expected data
from the original marker rather than trusting a later environment value.

All activated client and independent-witness policies now use
`ServicePolicy::installed`, including the real journal/terminal consumer and
opaque-retirement tests. Mutable-template refusal still requires no accepted
connection and restores the original mode. The complete native activation suite
must qualify this new path; local controls do not substitute for that result.
No local root service, provider account or production installer is used.
