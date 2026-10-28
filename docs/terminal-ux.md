# Terminal UX contract

The terminal experience must make account and agent switching easier to understand
and operate than the reference supplied by the user. Visual polish and working
flows are release requirements. The existing dashboard is a basic developer
preview and does not meet the final bar yet.

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
