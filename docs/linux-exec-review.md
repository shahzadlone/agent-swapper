# Exec and terminal composition review

Opus 5.5 completed an independent source-only review on 2026-11-01 against
`5be7b7f`. It did not execute tests. The review found no bypass of the held-exec
journal ordering, authenticated exit acceptance, separate scope retirement, or
the corrected revoke-before-decode wait ownership. That is a scoped review
result, not proof of production readiness.

The following findings require resolution before product integration:

| Finding | Disposition |
| --- | --- |
| Cancellation can remain pending through admission and release | Reproduce at explicit pre-GO and pre-release barriers, then retire without release |
| A target dying while the relay is paused can lose its queued outcome | Add stopped-target death tests through shell fg/bg and repair event/drain ordering |
| A known target exit can be replaced by a drain-timeout failure | Separate bounded output truncation from the authenticated target result |
| Socket reset can hide a queued final report | Reproduced locally; bounded retry implemented, hosted qualification pending |
| Early relay errors discard their retirement witness | Route post-binding failures through explicit retirement; preserve unresolved journal policy |
| Guardian resume/hangup/marker paths can discard a terminal wait result | Consolidate raw terminal-status handling and test the competing transitions |
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

The first alternate-path run, 41281817958, refused `/opt` on both hosted
runners because that directory did not meet the root-owned/non-writable
requirement. The correction uses `/usr/lib` and validates every ancestor,
including `/usr`; it does not loosen ownership or mode policy. Each refusal
still occurs before installation. Native qualification of this revision is pending.
