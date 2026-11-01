# Surviving owner for terminal restoration

Status: all nine local-owner cases and all 19 composed managed cases passed
on Ubuntu 22.04 and 24.04 at `150dd2c` in
[run 41275848735](https://github.com/shahzadlone/agent-swapper/actions/runs/41275848735).
The full platform/package/rebuild pipeline passed. Earlier background-cancellation
(`4da522e`, run `41274945822`), composed-owner (`baf6965`, run `41275197416`)
and error-path restoration (`2f25bbb`, run `41275464820`) checkpoints also passed
their full pipelines. Independent source review remains pending; no production
integration is claimed.

The two-terminal relay now passes its normal and loss cases on both Ubuntu
runners (`f79f800`, run `41274299505`). Its explicit SIGKILL case confirms that
the manager can remove the whole original scope while the outer terminal
remains raw. A destructor cannot fix an uncatchable process death.

The experiment keeps a small parent alive as the outer terminal owner.
It captures the initial attributes before its fixed child starts terminal I/O,
then leaves all reads and writes to that child. Both stay in the same outer
foreground process group. The parent exclusively waits for its direct child;
after observing child stop or exit, it may restore the saved attributes only
while that original group still owns the foreground.

Keeping one outer group avoids transferring the terminal to another group or
using a child's numeric group ID after reaping it. It also lets a normal shell
continue the whole job. The child handles the inner terminal's authenticated
stop/resume protocol; the surviving owner adds restoration after unexpected
child death. This is terminal ownership, not an all-writer stop or a custody
receipt. Manager retirement must remain independently observed.

The local `terminal_owner` probe uses only a fixed child and an owned PTY, with no
manager, provider, credentials, or arbitrary command. It must observe real
child death before claiming restoration, exercise complete attribute equality,
and preserve the original shell's foreground ownership. A private fixture
admission record is not a proposed production launch protocol. Normal child
exit, child SIGKILL and parent SIGTERM each restore every original termios
field. Real shell tests cover child self-stop and uncatchable child SIGSTOP,
followed by background/foreground continuation and complete `stty` snapshots.
The SIGSTOP case caught a child assuming that SIGCONT restored foreground
ownership; it now waits for the original foreground group before re-entering
raw mode. The child has a parent-death signal with parent checks around its
installation. Stopped-parent loss is qualified below; active parent-loss
restoration remains unqualified.

Two additional cases cancel the parent after `bg`, including a child resumed
from SIGSTOP. Before cancellation, the shell changes its flow-control setting.
The parent and child terminate without restoring over that new foreground
owner's settings. An exit in the background records that distinction instead
of claiming a final mode restoration. Both retained process handles must show
exit, and complete shell snapshots must preserve the deliberate change.

Later gates include active parent loss, whole-group death, long sessions and
the production entry-point and descriptor handoff. No surviving-owner guarantee is possible if every process able to
restore the terminal is killed; the caller's shell remains an independent
owner with its own job-control behavior.

The parent is now extracted into a shared qualification module. A managed mode
executes only the fixed relay child of the same executable, forwarding a small
hosted-fixture environment allowlist. The child enters the shared foreground
group only after checking its direct parent and registering its parent-death
signal. The existing direct relay remains separately tested. The new combined
cases are described in the [relay report](linux-managed-terminal-relay.md).

A subsequent source audit tightened error cleanup: the bounded child destructor
can time out, so returning from that destructor is not evidence that the child
has stopped changing the terminal. The owner now retains a separate process
pidfd and restores on Drop only after that original descriptor reports exit or
reap, with no polling error. Without `PIDFD_THREAD`, readiness waits for the
whole thread group; see [pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
Explicit normal stop restoration still follows the exclusive waiter's stop
event. An eighth local case exercises refusal of an unsupported external stop:
the owned child exits, and the error path restores every original attribute.
Unknown child retirement never grants error-path restoration authority.

A parent-loss regression additionally uses a fixed Rust bootstrap that makes
its interactive bash a child subreaper. When the owner is killed while both
owner and relay are stopped, the shell adopts the relay in the same session
but a different group. This prevents orphan-group SIGCONT from masking a bug.
Before the fix, the local negative control observed the relay still stopped,
with parent-death SIGTERM pending and its pidfd unreadable after adoption.

The fixed relay helpers now use parent-death SIGKILL, with parent checks around
registration. This affects only the outer helper, never the inner guardian or
target. Nine local owner cases pass; the new one kills the stopped owner and
requires child exit without sending SIGCONT. Its modes were restored before
the loss, and the shell's complete settings remain unchanged afterwards.
The corresponding hosted case also retains the original scope and descendant
handles and requires manager-owned removal without client cleanup. Active
whole-group terminal restoration remains unqualified.
