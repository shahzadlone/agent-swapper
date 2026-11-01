# Exec composition follow-up review

Opus 5.5 reviewed supplied source at `a490aa7` on 2026-11-01, without tools or
execution. It found no correctness defect in the earlier A1–A6 corrections and
identified evidence gaps, diagnostic omissions and test timing margins. This
review did not include the later Store adapter or cooked-suspension changes.

| Finding | Resolution and evidence |
| --- | --- |
| Shell snapshot files can exist before `stty` writes them | Managed snapshots publish by rename and compare complete values in `be8387d`; the standalone owner/outer harnesses now also publish by rename and print mismatches |
| Signal probe did not ensure interruption of a blocked receive | It now waits for the original child to sleep after readiness, then observes the actual trace stop before sending the grant |
| Actual shim start-message receive was outside the reviewed shared retry | Two new cases use the real journal start receiver; SIGWINCH reproduced EINTR and refused exec before the fix; SIGWINCH and SIGCHLD now reach held exec with the correct nonce and restored socket policy |
| Failed exit-report send suppresses guardian diagnostics | Reporting and diagnostic recording are both attempted; a send error still propagates and markers never authorize completion |
| Target can exit between the first wait and terminal HUP observation | Recheck the sole child's raw wait once after HUP; only an actually observed terminal status is reported |
| Background drain test left little scheduling margin | `be8387d` reduces its foreground-return delay to one second; the actual five-second idle policy is unchanged |

## Interrupted reads

The kernel distinguishes timed socket waits from restartable unlimited waits in
[`sock_intr_errno`](https://github.com/torvalds/linux/blob/v6.8/include/net/sock.h#L2464-L2470).
Suppressing a tracee's signal does not make the timed wait restart automatically.
The actual journal start gate used a credential-enabled, zero-control-capacity
peek to distinguish EOF from an empty record. That peek did not use the shared
receive retry. Its corrected loop retries only EINTR, recreates ancillary state
and recalculates the remaining original deadline each time. Credential mode and
the caller's receive timeout are restored on return. No send is retried; no new
inference about whether a grant was delivered is introduced.

Eleven real-process cases now cover advisory signals before initial tracing,
inside the shared timed receive, and inside the journal start receive, plus five
termination/stop/trap refusals. Successful targets verify they are detached before
instructions execute; all cases retain the original child pidfd and verify exit.
The old implementation failed the new start-receive negative control with EINTR.
The corrected cases and all 65 isolated tests pass locally, with strict Clippy.
Native qualification passed in the complete ae97a1d run recorded in
[the integration evidence](linux-exec-review.md).

The guardian's readiness/pre-GO polls still refuse an unexpected child stop.
Advisory-stop continuation is qualified in `OwnedChild`'s initial/exec waits,
not as a promise to accept arbitrary external signals in every startup phase.
Before GO the shim does not own the inner terminal's foreground group. The
outer helper's cancellation and suspension policies are qualified separately.

## Source checks outside the original review excerpt

- `activated_journal::gated_ready` publishes readiness with a temporary file and
  rename; the reader cannot observe its create-before-write window.
- `activated_terminal::shim` receives the slave through the bounded shared
  transport and the nonce through the actual journal start gate tested above.
- `activated_guardian::serve` marks inherited nonstandard descriptors CLOEXEC
  before spawning; its owned activation-channel clone is also CLOEXEC. Each
  child's three standard streams are explicitly replaced. Received leases use
  CMSG_CLOEXEC, and the final shim marks all nonstandard descriptors CLOEXEC again.
- The resume-hold file hooks remain confined to the opted-in disposable fixture.
  They must not be copied into a production guardian.

These source checks resolve the excerpt gaps; they are not provider isolation
results. Store completion, original-scope retirement, target outcome and terminal
restoration remain separate responsibilities. No fixture marker, client exit or
free lease supplies a production Linux completion receipt.
