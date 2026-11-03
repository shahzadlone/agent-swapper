# Loaded Linux socket policy

This candidate verifies the socket configuration reported by the authenticated
system manager against a retained installation selection. It does not connect
to the endpoint, start a service, send launch data or establish process custody.
Production managed launch remains disabled.

`SocketPolicy::installed` derives the unit, endpoint and ordinary UID/GID from
the selection. The socket and service template must share the same installed
directory and stem. Only qualification builds can override the endpoint layout.
The borrowed selection retains namespace origin and all original file handles.

`LoadedSocket::observe` queries only the original manager's unique bus name and
requires an already loaded, active, listening, non-transient unit. Its fragment
must match the selected file exactly, with no drop-ins or pending reload. The
socket must have exactly one `SequentialPacket` listener at the expected path,
`Accept=yes`, the exact numeric user/group, mode 0600, directory mode 0755 and
`RemoveOnStop=yes`. The invocation must be nonzero and unchanged across reads.

The observation retains its manager-connection identity, unit path, invocation
and selection. Rechecking repeats the configuration and selection checks;
another manager connection or a new invocation refuses. Each observation and
recheck has its own eight-second asynchronous deadline. Returned facts are
diagnostics and cannot create a launch or retirement capability.

## Qualification

Unit controls cover a valid configuration and 21 individual protocol, state,
path, identity, permission, listener and invocation changes. A paused-time test
checks the bounded unresponsive path. Default builds lack the endpoint override.
The hosted probe uses the actual installed fixture and authenticated bus. It
observes, rechecks, refuses a second authenticated connection, and reports the
selected unit/endpoint/identity/invocation. The controller independently checks
the invocation against the manager, and requires zero accepted connections and
an empty worker directory throughout the observation controls.

The hosted controller changes only its owned unit's timestamp, then opens a
fresh selection. The retained contents still match the manifest, but stale
loaded configuration must refuse until a daemon reload. A second control holds
the original `LoadedSocket` across a restart of the owned listening unit. The
manager must report a different nonzero invocation, and rechecking the retained
object must refuse that specific change. The unchanged held observation and
fresh observations after reload and restart must pass. Neither control connects
to the socket or starts a guardian. Administrator roles validate the ownership
marker, installation hashes and exact unit contents before any action. Cleanup
restores loaded metadata and reaps the owned observer on failure.

Local result controls reject foreign or malformed invocation evidence, crashes,
unexpected output and unrelated diagnostics; only the intended refusal counts.
Native results are pending. Endpoint
ancestry/inode checks, kernel listener credentials, accepted-guardian binding,
and composition around the actual connection remain separate open gates.
Configuration observations cannot promise stability under later administrator
changes; admission must recheck at its actual boundaries.

The property contract was checked against the primary systemd
[249 socket bus interface](https://github.com/systemd/systemd/blob/v249/src/core/dbus-socket.c),
[255 socket bus interface](https://github.com/systemd/systemd/blob/v255/src/core/dbus-socket.c)
and [socket-unit documentation](https://www.freedesktop.org/software/systemd/man/249/systemd.socket.html).
