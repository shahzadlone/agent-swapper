# Final exec held behind the durable spawn observation

Status: implemented fixed-target qualification candidate; hosted results pending.
Local protocol, compilation, dependency-boundary and strict Clippy checks pass.
No production execution
mechanism or provider cell is promoted by this experiment.

The current journal has a durable run intent and one spawn observation. A
successful exec is a separate kernel fact from shim creation, application
initialization, login, target exit and scope retirement. The standalone
[exec-event experiment](linux-exec-confirmation.md) can observe that fact while
holding the target before its first userspace instruction. The new `PTY3`
fixture combines it with the existing manager-owned guardian and terminal.

The implemented ordering is:

1. Commit the real Store run intent while retaining the profile lease.
2. Start the protected fixed shim under its direct guardian. It requests
   tracing, stops, and cannot pass its private GO gate until the guardian has
   enabled TRACEEXEC and EXITKILL. One non-Send owner handles every child wait.
3. Bind the guardian, original scope, shim PID and inner master using the
   existing authenticated admission path. Confirm the durable run intent
   before the first GO. No application instructions run at this phase.
4. Accept only the original child's exact kernel EXEC event. Hold that exec
   stop and send a bounded, authenticated notice bound to invocation, child
   and launch nonce. Ordinary traps and absent events never count as exec.
5. Recheck the live binding and record `RunSpawned` in the real Store while
   the target is still held. This uses the existing journal schema: there is
   no invented application-ready or custody event.
6. Send a distinct nonce/child-bound release frame only after that write
   succeeds. The guardian detaches, then normal PTY2 job control proceeds.
   The fixed target must observe no tracer when its code starts.

Legacy PTY1 and PTY2 keep their existing ordering and independent tests. The new
phase has a separate typed client value, so a pending exec stop cannot be
mistaken for an ordinary terminal stop or resumed with a job-control frame.
An uncertain release send closes the control channel and retains unresolved
journal policy. It does not mean release was withheld.

The hosted suite requires successful release with working terminal/job control,
SQLite write failure while held, disconnect while held, guardian loss while
held, and a bounded withheld-release deadline. Every refusal/loss case must
retain original process/scope handles and independently observe retirement.
General missing-event cases remain unresolved, even if no target marker is
seen. An explicit pre-GO kill is a narrower controlled case, not a basis for a
general no-exec assertion.

The release and exec-notice parsers have local refusal tests for wrong sender,
invocation, child, nonce, phase, unexpected fields, empty/oversized frames and
transferred descriptors. Rights must close on refusal and channel policy must
restore after timeout. An ordinary job resume cannot consume or release the
pending exec phase. The existing journal schema and production dependency graph
are unchanged; ptrace is enabled only in the isolated qualification crate.

The source and hosted behavior still require independent review. Provider sandbox/dumpability
compatibility, external signal behavior during the trace phase, final exit
receipts, production protocol/install design and real-provider qualification
remain separate gates. The guardian never reads target memory or registers.

The subsequent [target-exit experiment](linux-target-exit-observation.md) adds
an authenticated direct-child status after exec release. Its status and scope
retirement remain separate observations, with no journal completion authority.
