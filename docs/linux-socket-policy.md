# Loaded Linux socket policy

This candidate verifies the socket configuration reported by the authenticated
system manager against a retained installation selection. Observing that policy
does not connect or start a service. A separate checked connection operation may
activate the ordinary guardian, but sends no bytes and establishes no process
custody. Production managed launch remains disabled.

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

## Endpoint connection

`LoadedSocket::connect_endpoint` rechecks the original observation before
opening the endpoint. `ProtectedSocket` walks root-owned, non-writable directory
handles without following symlinks, then holds an `O_PATH | O_NOFOLLOW | O_CLOEXEC`
handle to the ordinary user's mode-0600 socket. It requires the selected UID/GID
and one hard link, and compares the retained inode and metadata with a fresh
protected path lookup before and after connecting. Access time is excluded.

The connection uses nonblocking `SOCK_SEQPACKET` with close-on-exec and enables
per-message credentials before connecting. Kernel peer credentials must identify
UID 0, GID 0, PID 1. Backlog refusal is not retried. Loaded policy, original
manager connection and endpoint are rechecked before returning the descriptor,
under the operation's eight-second deadline. No request bytes are sent here.

The listener's credentials identify the system manager, not the accepted
guardian. The qualification client sends its fixed request only after these
checks, validates the offer's actual message sender, then binds the original
service. The same authenticated manager connection spans socket observation,
endpoint connection and service binding. This path is shared by the fixed
activation, generation, journal and Store/terminal consumers. A later socket
restart cannot retarget an already connected descriptor; admitted work retains
the original service observation instead of selecting a new socket invocation.

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
Both native Ubuntu control suites passed the observation controls at `425db79`
([41666325873](https://github.com/shahzadlone/agent-swapper/actions/runs/41666325873));
that complete pipeline also passed. These results predate the endpoint connection.

Endpoint unit controls use ordinary temporary sockets to check identity, mode,
hardlinks, symlink leaves, replacement, descriptor flags and refusal of temporary
unprotected ancestry. The hosted fixture changes only its ordinary-owned socket
to mode 0660 and requires the connection consumer to refuse before the accepted
count or worker directory changes. It restores the original inode's mode on
failure too; ordinary local controls exercise timeout, unexpected success and
unexpected activation cleanup. Native endpoint and full composition results are
pending. Additional adversarial path replacement during connection, production
helper installation and actual launcher composition remain open gates.

The connection-race control pauses after pinning the endpoint or after checking
the kernel listener. The ordinary socket owner changes mode to 0660, then releases
the observer. Both phases must refuse the specific retained-inode change before
sending any bytes. The controller checks the accepted count (zero new connections
before connect, exactly one after), restores the original inode's mode, and
requires no worker artifacts and retirement of any activated guardian. These
barriers are absent from default builds and cannot skip production checks.
This control covers permission changes, not replacement of the pathname.
Its native CI result remains pending.
Configuration observations cannot promise stability under later administrator
changes; admission must recheck at its actual boundaries.

The property contract was checked against the primary systemd
[249 socket bus interface](https://github.com/systemd/systemd/blob/v249/src/core/dbus-socket.c),
[255 socket bus interface](https://github.com/systemd/systemd/blob/v255/src/core/dbus-socket.c)
and [socket-unit documentation](https://www.freedesktop.org/software/systemd/man/249/systemd.socket.html).
