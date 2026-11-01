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
