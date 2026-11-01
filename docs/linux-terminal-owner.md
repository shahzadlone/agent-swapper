# Surviving owner for terminal restoration

Status: seven local cases passed. The initial five cases at `ceb0a0a` passed both
Ubuntu manager jobs in
[run 41274736525](https://github.com/shahzadlone/agent-swapper/actions/runs/41274736525).
Background cancellation and composed managed execution require their own
hosted results. No production integration is claimed.

The two-terminal relay now passes its normal and loss cases on both Ubuntu
runners (`f79f800`, run `41274299505`). Its explicit SIGKILL case confirms that
the manager can remove the whole original scope while the outer terminal
remains raw. A destructor cannot fix an uncatchable process death.

The next experiment keeps a small parent alive as the outer terminal owner.
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
installation, but parent-loss behavior remains separately unqualified.

Two additional cases cancel the parent after `bg`, including a child resumed
from SIGSTOP. Before cancellation, the shell changes its flow-control setting.
The parent and child terminate without restoring over that new foreground
owner's settings. An exit in the background records that distinction instead
of claiming a final mode restoration. Both retained process handles must show
exit, and complete shell snapshots must preserve the deliberate change.

Later gates include combining this parent with the managed relay, cancellation before continuation,
parent loss, whole-group death, and the production entry-point and descriptor
handoff. No surviving-owner guarantee is possible if every process able to
restore the terminal is killed; the caller's shell remains an independent
owner with its own job-control behavior.

The parent is now extracted into a shared qualification module. A managed mode
executes only the fixed relay child of the same executable, forwarding a small
hosted-fixture environment allowlist. The child enters the shared foreground
group only after checking its direct parent and registering its parent-death
signal. The existing direct relay remains separately tested. The new combined
cases are described in the [relay report](linux-managed-terminal-relay.md).
