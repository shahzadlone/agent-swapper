# Exec and terminal composition review

Opus 5.5 completed an independent source-only review on 2026-11-01 against
`5be7b7f`. It did not execute tests. The review found no bypass of the held-exec
journal ordering, authenticated exit acceptance, separate scope retirement, or
the corrected revoke-before-decode wait ownership. That is a scoped review
result, not proof of production readiness.

The following findings require resolution before product integration:

| Finding | Disposition |
| --- | --- |
| Cancellation can remain pending through admission and release | Cancellation guards now bracket journaling and run after the last recheck, immediately before GO/release; qualified in the complete 815a878 run |
| A target dying while the relay is paused can lose its queued outcome | Queued final reports are checked before resume; qualified in the complete 082629f run |
| A known target exit can be replaced by a drain-timeout failure | Known exits keep their status after bounded output truncation; qualified in the complete 082629f run |
| Socket reset can hide a queued final report | Reproduced locally; bounded retry qualified in the complete 815a878 run |
| Early relay errors discard their retirement witness | Admission and post-entry errors now attempt explicit retirement using retained witnesses; qualified in the complete 815a878 run |
| Guardian resume/hangup/marker paths can discard a terminal wait result | One raw terminal-status handler now serves ordinary and resume waits; qualified in the complete 082629f run |
| External stops during cooked admission/cleanup windows | Explicitly outside the current fixture contract; define and qualify phase-specific behavior before production |

For the reset finding, two real socketpair regressions failed against the old
code with ECONNRESET. Both now pass. Readiness and credential-bearing receive
consume at most one reset before inspecting the remaining queue, under the
original deadline. Credential, framing, descriptor and phase validation remain
unchanged. A reset with no packet remains closure; an empty record remains an
error and never becomes a final report. The kernel sets the peer error when a
sequenced-packet endpoint closes with unread input, as shown in
[Linux's Unix socket release code](https://github.com/torvalds/linux/blob/v6.8/net/unix/af_unix.c#L604-L610).

All 65 isolated Rust tests and strict qualification Clippy pass locally for
this correction. Hosted evidence remains pending. It introduces no production
receipt or profile-reuse authority.

The terminal-guard branch's Ubuntu 24.04 job in
[run 41280763165](https://github.com/shahzadlone/agent-swapper/actions/runs/41280763165)
refused installation because that runner's `/run` mount was noexec. Its local
terminal cases and Ubuntu 22.04 manager job passed. The disposable fixture now
puts its executable image under protected `/usr/lib`; its socket, unit files and
ownership marker stay under `/run`. Both the installer and Rust guardian check
the new root-owned, non-writable parent. Installation still refuses a noexec
image filesystem; no host mount is changed. Exclusive creation, recorded image
hash, ownership-bound cleanup and unrelated-file preservation are unchanged.
Fourteen coordinator tests pass, including the noexec-runtime case, a noexec
image refusal and untrusted image-parent refusals. New hosted evidence is pending.

The review recommends wiring the real Store through the shared runtime with
fixed targets before accepting arbitrary launch envelopes. Production also
needs a policy for signals before the exec event, executable/wrapper identity,
ptrace/LSM compatibility, protocol upgrades, guardian liveness and meaningful
structured outcomes. A first-image exec observation is not provider readiness.
Installation, provider qualification and CLI/TUI composition remain separate.

The admission correction retains the Closed witness across prepare, hold,
journal and transport failures. Post-admission errors use the same restoration
and retirement path as normal exit, including a marker error after entering raw
mode. Observation failure remains unresolved; a failed manager-connection close
after proven retirement is separately diagnosed. No file marker completes a run.

Thirteen new native cases hold the actual relay at pre-journal or final-send
boundaries. They cover direct and surviving-owner SIGTERM, cooked terminal
Ctrl-C, refused existing intent/spawn files, and a marker failure after raw entry.
The harness retains original guardian/target pidfds and the original cgroup
directory before releasing the barrier. It checks terminal modes, scope removal,
lease release and (for withheld admission) absence of target instructions. The
fixture barrier is bounded and available only in the hosted qualification helper.
The checks do not make cancellation atomic with a later successful send.

All 65 isolated Rust tests, 14 coordinator tests and strict qualification Clippy
pass locally for the admission correction. The expanded 45-case native manager
suite is pending; this remains qualification code, not a production launcher.

The first alternate-path run, 41281817958, refused `/opt` on both hosted
runners because that directory did not meet the root-owned/non-writable
requirement. The correction uses `/usr/lib` and validates every ancestor,
including `/usr`; it does not loosen ownership or mode policy. Each refusal
still occurs before installation. Native qualification passed in the complete 815a878 run.

The next composition correction checks the control queue again after an outer
stop. A valid queued stop followed by retirement advances only protocol sequence;
it cannot grant live stop/resume authority, and only an authenticated final
report with the original child pidfd dead can resolve it. A failed resume recheck
likewise accepts only that final report. Receipt of another stop, malformed
data or expiry still fails closed.

Known final status now has a five-second idle drain budget and fifteen-second
overall cap. Actual read/write progress refreshes only the idle budget. While
backgrounded, the relay does no terminal I/O and waits within those bounds for
foreground reacquisition. Expiry records output truncation and preserves the
verified target status. Missing target status retains the earlier two-second
bounded failure policy. Cancellation, terminal restoration and original-scope
retirement remain independent. These are fixture bounds, not product defaults.

The guardian reports every raw terminal wait through one handler, including a
terminal event observed inside the resume branch, before best-effort marker I/O.
It checks terminal wait status before terminal hangup. Eleven new native cases
cover stopped SIGKILL through fg, bg/fg and background expiry, a held resume
with concurrent target death, a three-second reader pause, permanently blocked
final output, and refused diagnostic marker replacement. Local Rust and strict
Clippy pass; the 58-case combined managed suite (including fresh entry) passed native qualification on both hosts.

The preceding admission checkpoint `815a878` passed all 45 managed cases plus
the long-session check on Ubuntu 22.04/24.04 in jobs 124777197243 and
124777197393 of [run 41282533178](https://github.com/shahzadlone/agent-swapper/actions/runs/41282533178).
The `/usr/lib` image-path and queued-report correction also passed both native
manager jobs in [run 41282501325](https://github.com/shahzadlone/agent-swapper/actions/runs/41282501325).
Full candidate/rebuild results are checked separately before main integration.

An additional real-Store fixture now cancels at the final GO and held-exec
release guards. A second Store connection verifies the committed intent/spawn
observation before refusal. Both cases retain original witnesses, observe
retirement, confirm no target instructions, then reopen SQLite and verify
consistent replay and unresolved profile policy despite an available OS lease.
This composes journal durability with withdrawal; it is not yet a Store-backed
terminal frontend. Strict core Clippy and coordinator checks pass locally; the
privileged fixture is run only on disposable native CI.

The first combined run (41282864768) stopped at the existing terminal-hangup
journal test: reporting an already reaped target before checking terminal
hangup omitted its diagnostic marker. The correction preserves both observations,
reporting terminal status first and recording a separately observed HUP as
best-effort diagnostics. The existing hangup assertion remains unchanged.


The full [run 41283540204](https://github.com/shahzadlone/agent-swapper/actions/runs/41283540204)
passed on `082629f`, including native manager jobs 124780142287 (Ubuntu 24.04)
and 124780142313 (Ubuntu 22.04), platform tests, dependency checks, unsigned
candidate builds and independent rebuilds. Both native jobs ran the 58 managed
terminal cases, the separate long-session check and the real-Store final-guard
withdrawal regression. The paused-outcome branch also passed its complete
[run 41283538949](https://github.com/shahzadlone/agent-swapper/actions/runs/41283538949).

Two earlier combined runs failed a terminal-snapshot assertion on opposite
hosts. The harness now waits for the `after` snapshot to contain data and prints
both snapshots on mismatch. This addresses the shell redirection/create-before-write
race; the original empty-snapshot cause cannot be proved from those older logs.
The corrected combined source is integrated unchanged into main; main CI checks
that integration again. These results qualify the fixed-target test harness,
not a production managed launcher or authority to complete an unresolved run.
