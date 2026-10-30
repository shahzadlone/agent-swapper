# Terminal UX contract

The terminal experience must make account and agent switching easier to understand
and operate than the reference supplied by the user. Visual polish and working
flows are release requirements. The existing dashboard is a basic developer
preview and does not meet the final bar yet. It now includes responsive profile
details, keyboard availability changes, stable identity selection and privacy
labels, in-interface profile registration, reviewed foreground launches/login,
recorded gents session selection, rename/unregister dialogs, and local previews from the actual renderer.
Live usage, cross-agent context transfer and the full action set remain open.
POSIX dashboard exits now restore the terminal before re-raising external
interrupt, termination and hangup signals; actual PTY checks cover those paths.
Unix event input uses the TTY polling backend with bounded raw reads, so closed
terminals and incomplete Unicode/escape sequences cannot indefinitely defer
the next application signal check. See [dependency decisions](dependencies.md#bounded-terminal-input).
Signal restoration fixtures now keep a controlling-session owner alive while
they inspect the dashboard child's actual signal status, restored attributes
and alternate-screen exit bytes. A repeated macOS run had missed that final byte
sequence when inspecting an exited standalone PTY child. EOF races remain a
separate direct-child fixture: signal delivery and peer closure must happen in
the same actor. The strengthened session fixture passed on macOS at `16053be` in
[CI run 40975543816](https://github.com/shahzadlone/agent-swapper/actions/runs/40975543816/job/123802538852).

## Implemented foreground transition

Enter prepares a fresh native conversation or gents session; `l` prepares native
login; `c` prepares the latest eligible recorded gents session. The review
shows destination, executable, profile home, workspace ownership and continuity.
Readiness checks do not launch an agent or reserve a session. Native resume and
gents login are refused. Existing routing, shared-auth and legacy-home checks
apply; the dashboard offers no bypass for them.

Every launch requires Space to accept its experimental status, then Enter.
Masked reviews hide identifying fields and cannot start an agent; Ctrl-P
unmasks and resets acceptance. Agent output has its own privacy settings.
Page Up/Down and j/k scroll the review; shrinking below 40 x 14 disables launch
while keeping cancellation available.

The dashboard restores canonical terminal input and leaves its alternate screen
before execution. It removes its own POSIX signal registrations and lets the
agent receive foreground interrupts. When the direct agent or gents client
returns normally, the same dashboard reopens with its selection preserved and
the exit result shown. The core journal records the existing conservative custody
state: this does not establish that background or runtime work stopped. A launch
error exits to the shell; uncertain wait or terminal restoration errors must not
redraw a dashboard over a possibly active agent.

Provider-free POSIX PTY checks exercise all three native fixtures, login,
cross-brand selection, Ctrl-C, gents new/resumed sessions and terminal restoration.
Unit tests cover acceptance, masking, resize/scroll, unsupported actions, busy
profiles and availability changed after review. Windows ConPTY transitions
still require their own recorded evidence. No real-provider support
cell is promoted by these fixtures. The dashboard foreground flow passed hosted
Linux and macOS PTY checks at `8438909` in
[CI run 40956977506](https://github.com/shahzadlone/agent-swapper/actions/runs/40956977506).
That build's three-platform candidate rebuild and preview attestation also passed;
later terminal changes still need their own hosted evidence.

Windows launch now includes owned console-mode capture/restoration. A new
provider-free fixture creates a disposable console and deliberately changes
input/output modes during native direct and Job launches with console, stderr-only
and fully redirected streams. All six cases passed at `08facc1` in
[Windows CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40959372054/job/123747795279).
This fixture
does not qualify interactive ConPTY navigation, active screen buffers, crash
restoration or real agent compatibility.

A separate actual-ConPTY fixture now exercises the complete dashboard using
provider-free Claude, Codex, Kimi and gents stand-ins. It checks reviewed launch,
login, Ctrl-C, gents resume, resizing, masked/tiny-terminal launch refusal and
exact original console modes after exit. Each phase explicitly re-enables VT
output before drawing and restores the original snapshot before yielding the
terminal; cached ANSI support must not leave VT disabled on the next phase.
The initial six-launch ConPTY flow passed at `2362a0d` in
[Windows CI](https://github.com/shahzadlone/agent-swapper/actions/runs/40961568743/job/123755381322).
The test coordinator has its own
process-lifetime Job and fake agents expire; this does not add default Job
containment to production launches.

Rename (`n`) and unregister (`d`) now address the selected stable profile ID.
Unregister requires Space and Enter, refuses busy/unresolved work and retains
agent-owned files. Noticed peer label/binding changes reset review; an alias
reused by another profile cannot redirect the action. Privacy covers drafts,
labels and errors, including narrow/resized dialogs; cancellation preserves
the existing profile. POSIX PTY tests cover a peer rename/reused alias while
unregister review is open, file retention and mapping removal. Windows ConPTY
coverage for those added actions passed at `16053be` in
[CI run 40975543816](https://github.com/shahzadlone/agent-swapper/actions/runs/40975543816/job/123802538596).

## Entry and visual direction

Running `aswp` or `agentswapper` without a command opens the dashboard when stdin
and stdout are terminals. Piped invocations keep plain help; `--json` keeps its
machine-readable summary. `--help` stays available without opening storage.

Use the established Distinction identity: dark ink, readable neutral text,
teal primary actions and restrained yellow accents. Keep the command mark compact
so the first screen prioritizes useful account and workspace information. Provider
monograms and explicit labels must work without a special font or image protocol.
Themes need true-color, reduced-color and monochrome treatments; state cannot
be communicated through color alone.

The wide layout pairs the account list with the selected profile's details and
next action. Narrow terminals use a single focused list with contextual details.
Avoid making every field equally prominent or filling the screen with warnings.
Use the relay artwork's personality in onboarding and handover transitions where
it clarifies the task, without occupying the working screen with a large banner.

## Information that earns its place

- Show provider, engine, profile label and verified account identity distinctly.
  Enabled, selected, running and unresolved are different states. A registered
  profile is not proof of a logged-in subscription.
- Put confirmed active work and the current directory mapping near the top.
  Show the selected workspace, latest recorded activity and the next useful action.
- Where supported and measured, show named usage windows, readable bars, remaining
  capacity, reset countdown and absolute reset time. Display freshness and source.
  Unknown capacity is a neutral unmeasured state, never an empty usage bar or an
  available-account claim. Preserve provider-specific limits instead of forcing
  every provider into identical five-hour/week/model buckets.
- Show what a proposed switch will do: resume the same native session, resume an
  engine session, transfer a handover, or start a new conversation. Explain blockers
  and capacity decisions in the selected item, close to the action.
- Keep external engine ownership visible. A gents client exiting does not establish
  that runtime work has stopped. Local process cleanup is not credential isolation.

## Complete flows

The final interface includes overview, account actions, live watch, automation
status, run/handover history and settings. Account add, login, switch, enable/disable,
rename and removal must be usable without leaving the interface for a shell command.
Native and gents setup should explain their different ownership and permissions.

A switch flow previews its source, destination, continuity method, workspace and
reason. It must refuse unsupported or unresolved transitions. Automatic switching
shows the policy and next eligible choice only when real capability and custody
gates pass. Do not display a working automation toggle backed by placeholder data.

Live watch refreshes measurements outside the input/render path, shows stale/error
states, and preserves selection by stable profile ID across updates, reordering
and filtering. API fetches must not happen on every animation frame. Terminal resize
must preserve focus, scroll position and the pending action.

Closing or leaving a session view must make the ownership consequences clear;
there must be no silent orphaning or unexpected termination of background work.
Long-running operations expose progress and a meaningful cancellation path.

## Keyboard, privacy and recovery

Navigation works with arrows and j/k, search with `/`, actions with Enter and a
command palette, back with Escape, and context help with `?`. Discoverable shortcuts
stay visible at the bottom. No flow requires a mouse.

Privacy is global and available during search and modal flows. Mask account labels,
emails, organizations, agent IDs, paths where sensitive, event details and search
input. Retain stable nonidentifying labels so navigation still makes sense. Clear
previously rendered identifying messages when toggling privacy. Imported/provider
strings must not introduce terminal control sequences or directional spoofing.

Empty states give one clear next action. Errors preserve selection and useful input,
state what was completed, and identify the next safe recovery action. Incomplete
supervised launches identify the run to inspect. Technical evidence belongs in
inspectable details rather than dominating the default screen.

## Visual review and release gates

Render full terminal previews from actual UI components with fictional fixture
accounts; do not select a final layout from prose descriptions alone. Provide
locally viewable previews for populated, empty, live-watch, switch/handover,
blocked, stale-data, failure and privacy states before locking the full design.
Use the approved brand direction and offer meaningful alternatives when requested.

The minimum review matrix is 80 x 24, 100 x 32 and 160 x 48, with a useful narrow
fallback. Test both light and dark appearances, reduced colors, long/untrusted
labels and fully masked screens. Check actual PTY/ConPTY behavior, resize, focus,
Ctrl-C, terminal restoration and native-session transitions, not snapshots alone.

Acceptance requires every supported CLI action to be reachable, no identity canary
on any masked screen, no fabricated usage or active-account claims, and no hidden
unsupported switch. Visual reviews and task-based keyboard walkthroughs must show
that the next action and its consequence are clear. A screenshot comparison by
itself is not sufficient.
