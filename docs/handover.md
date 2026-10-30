# Manual encrypted handover

AgentSwapper can package an existing task note, unlock its metadata, and prepare
a receiving agent's pickup note. This is an unreleased manual workflow. It does
not stop the outgoing agent, verify its descendants, transfer credentials,
launch a receiver, or claim seamless native resume.

## Carry a task

Write or refresh `HANDOVER.md` with your existing `/handover` skill, keeping the
original goal, governing instructions, constraints, measured state, unfinished
work, next steps, and open decisions. Review it for sensitive content. Then:

```sh
aswp handover pack --from work --input HANDOVER.md --output ../task.age
aswp handover inspect ../task.age
aswp handover pickup ../task.age --target codex
```

To give the receiver a file instead of printing decrypted context in terminal
logs, use:

```sh
aswp handover pickup ../task.age --target codex --output ../HANDOVER_PICKUP.md
```

This explicitly creates **plaintext**. Keep the encrypted pack for transport;
protect or remove the plaintext file when finished. The destination must be a
new `HANDOVER*.md` or `PICKUP*.md` file in an existing directory outside known
agent homes and AgentSwapper state. Standard instruction files such as
`AGENTS.md` and `CLAUDE.md` are refused. No receiving agent is launched.

Each command uses a hidden terminal passphrase prompt. Packing asks twice;
use a long, unique passphrase of at least 16 characters. The passphrase is not
stored or placed in arguments, environment variables, SQLite, or output. Ctrl-C
or Esc cancels the prompt and restores terminal input. AltGr characters,
repeated keys, and pasted text are preserved; unsupported editing keys and
pasted control characters produce an error instead of silently changing the
password. Losing the passphrase
makes the pack unrecoverable. Keep encrypted packs outside the repository.

On POSIX, external INT, TERM and HUP requests restore terminal settings and
discard unread secret input before re-raising the original signal. Signal
handling remains active through cryptography; cancellation is checked before
publishing a new pack or printing decrypted content. Cancelled entry creates no
pack. Pipe-based input keeps its existing noninteractive behavior.

On Windows, hidden entry captures the original console modes through owned
handles and restores and verifies them on success, cancellation and input
errors. Queued console input is discarded before restoring echo. On both POSIX
and Windows, flush or restoration failure reports `secret_input_cleanup_failed`
before encryption or decrypted output; restoration is still attempted if
flushing fails.
The new native ConPTY fixture checks a nondefault input mode, both password
phases, secret/context echo, prequeued secret disposal and cleanup refusal.
These twelve cases passed at `bb9a5f0` before that workflow's later registry
stress failure in [CI run 40993431486](https://github.com/shahzadlone/agent-swapper/actions/runs/40993431486).
Forced process termination remains unqualified. Other
applications sharing the console are not isolated from input or mode changes.
Input arriving after cleanup is outside the discarded queue.

`pack` uses a registered profile as an operator-supplied source label. No login
is required or inferred. `inspect` prints metadata, including document size,
source label, and workspace reference; it hides note content. `pickup` explicitly
prints a decrypted Markdown note on stdout for the selected receiving harness,
unless `--output` saves it to a file.
This output contains your context: avoid recording it in shared terminal logs.
You decide whether to give it to the target provider. No network request occurs.
Inspect and pickup work without creating local AgentSwapper state.

Before starting the receiving agent, stop the outgoing agent and check its work
and any jobs it started. Give the pickup note to the receiver and use your
`/handover-pick` skill, or its equivalent, to re-measure state before continuing.
The imported document is fenced as unverified data. Existing sections survive
inside that block; they are not reinterpreted as new permissions or silently
promoted to verified claims.

## Reconciliation

The optional `--workspace DIRECTORY` flag defaults to the current directory.
At pack and pickup time, AgentSwapper measures the canonical directory and,
when available, the current Git commit using a bounded read-only `rev-parse`.
Inherited `GIT_*` variables are removed, then lazy fetching, transports, and
authentication prompts are disabled for that child command. Imported paths
are metadata and are never automatically opened.

Pickup reports directory `same_path` or `relocated`, and HEAD `unchanged`,
`changed`, or `unknown`. A matching HEAD does not establish that tracked,
untracked, or ignored files are unchanged. Working-tree state is always
`not_checked` in this preview. No repository snapshot is captured, no index or
worktree is changed, and no command embedded in the note is executed. Git
absence, an unborn branch, or a failed/timed-out probe leaves HEAD unknown.
Pickup is manual; AgentSwapper does not enforce a read-only first agent turn.

## Automation and output

For scripts, `--passphrase-stdin` reads one passphrase line from a pipe, with an
optional LF or CRLF terminator. Extra lines, empty input, and oversized input
are rejected. The flag refuses an interactive terminal so it cannot echo a
typed password. Use a trusted secret manager to supply this pipe; do not put a
literal passphrase in a shell command or history. `--json` retains the CLI's
unstable schema-v0 envelope. Inspect JSON contains metadata only; pickup JSON
deliberately includes decrypted context and the reconciliation report. With
`pickup --output`, both normal and JSON stdout contain only the destination and
report metadata, including an explicit plaintext indicator in JSON. A broken
pickup pipe returns a failure. If file publication already succeeded before the
acknowledgement failed, the complete file remains; inspect it before retrying.

## Format and limits

The draft payload is `agentswapper.handover`, schema 0, inside a standard binary
age passphrase-encrypted file. It contains an opaque capsule ID, creation time,
source harness/profile ID, workspace reference, note text, and a note hash.
Everything, including hashes and paths, is encrypted on disk. Authenticated
encryption checks the complete payload before anything is rendered. A hash
binds note bytes; it does not establish the truth of their claims or the source
agent's identity. This draft is not the complete future capsule-v1 manifest.

Source notes are UTF-8 `.md`, `.markdown`, or `.txt` files, at most 256 KiB.
Control codes, lone carriage returns, direction overrides, and selected invisible
characters are rejected. CRLF notes are accepted. Symlinks, hardlinks, nonregular
files, application-state paths, standard agent credential directories, inherited
agent-home locations, and `.env*` names are refused. POSIX source ownership is
also checked. These checks reduce accidental credential packaging; they do not
detect every secret in an otherwise valid task note. There is no automatic
secret-redaction claim.

Decoded payloads are limited to 1 MiB; ciphertext allows an additional 16 KiB
of framing. Scrypt encryption uses `N=2^18, r=8, p=1`, about 256 MiB of memory.
Decryption refuses higher work factors before running that KDF. Only
passphrase-based age files are accepted. Password strength still matters if
someone obtains the encrypted file. See [dependency decisions](dependencies.md).

Windows cloud/reparse files, including some OneDrive Files-On-Demand files, are
deliberately unsupported pending filesystem-tag verification. Use an ordinary
local file in this preview. Ciphertext can be shared between users without
source-note ownership or hardlink restrictions; note inputs keep those checks.

Outputs use a temporary file, fsync, and exclusive publication in the same
directory. Existing files and symlinks are never overwritten. POSIX output mode
is checked as private (0600); Windows ACL privacy is not verified. Cancellation
before publication removes the temporary file; after publication the committed
artifact remains. Directory-sync
status is reported separately after publication: lack of support does not
misreport an already-written file as a failed export. Explicit ciphertext
exports are not a replacement for the future encrypted account-backup feature.
