# Fresh terminal-owner entry

Status: isolated self-exec experiment. The local owner scenarios and managed
composition passed hosted qualification. It accepts only its fixed
fixture roles and no arbitrary command, launch envelope or production receipt.

The initial fixture starts a real second thread, then executes its own image
with a cleared environment and an explicit fixture allowlist. The new owner
must have one thread and the exact original PID and foreground group. This
preserves shell job membership while letting the shared signal owner initialize
in a fresh process. A dedicated canary verifies that other inherited environment
values do not enter the new owner.

Original stdin travels as a capability queued on a private sequenced-packet
socket. The new image checks that the peer credentials name its own unchanged
PID and user/group, receives exactly the transport's expected descriptor, checks
the owned terminal identity, and restores stdin before starting the owner.
The bootstrap socket is then closed. Stdout and stderr remain inherited terminal
streams. Failed exec restores the separately retained original stdin and joins
the fixture thread; it never enters the owner.

Four added local cases cover ordinary input/exit after fresh entry, interactive
shell stop/bg/fg, refusal of an unbootstrapped owner role, and failed exec without
terminal mutation. Together with the existing nine owner cases, all 13 pass.
Strict qualification Clippy and the 12 activation-coordinator checks pass.
Two additional managed cases exercise bytes, hidden/raw input, resize and final
output, plus shell stop/bg/fg and exact target signal status. Those bring the
managed suite to 34 cases plus its separate long-session case.

This qualifies a process-entry mechanism only. There is no real Store bootstrap,
target secret transfer, installed helper, TUI return path or profile-reuse
authority. The Opus review of the preceding managed composition identified
admission cancellation, paused/final-output outcome handling and error-path
retirement gaps; those remain separate required fixes before product integration.

Native Ubuntu 22.04 and 24.04 manager jobs 124773906844 and 124773906885
passed in [run 41281405713](https://github.com/shahzadlone/agent-swapper/actions/runs/41281405713).
That complete run also passed Linux/macOS/Windows tests, dependency checks,
unsigned candidate packaging and independent rebuilds. Its manager suite contains
34 cases plus the separate long-session check. This evidence applies to the
fixed fixture entry and shared runtime at `e938dd7`, not arbitrary provider launch.
