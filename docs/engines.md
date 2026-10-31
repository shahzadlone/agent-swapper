# Choose an execution engine

AgentSwapper supports **native** profiles and an optional **gents** attached chat
client. Both are experimental. Choose when registering a profile; `aswp engines`
shows the comparison without opening local state. `aswp run --engine ENGINE`
checks that your selection matches the profile; it never silently changes engines.

| | Native | gents |
| --- | --- | --- |
| Frontend | Claude Code, Codex CLI or Kimi Code CLI | `gents chat` |
| Best fit | Keep the vendor terminal, tools, hooks and permission workflow | Use a common runtime and canonical conversation across supported providers |
| Credentials, tools and permissions | The selected native CLI | The gents runtime and agent configuration |
| Setup | Install the native CLI; authenticate the isolated profile | Install gents; initialize a dedicated home; configure/authenticate an agent; operate a local runtime |
| Workspace | Passed as the native client's working directory | Configured on the gents agent; client cwd does **not** set it |
| Continuity | Native resume where supported; manual handover between brands | Tracked UUIDs and explicit `--resume` with the bound agent; provider switching remains a gents operation |
| Local supervision | Uncontained by default; opt-in Windows Jobs stop their remaining members, with work outside the Job unverified | External runtime is not owned by AgentSwapper |
| Main tradeoff | Session formats and features differ across vendors | Separate runtime to maintain; native plugins, sessions and permissions do not automatically transfer |
| Lifecycle | Direct child observed by default; opt-in Windows Job emptiness recorded after cleanup | Chat client observed; external runtime work may continue after exit |
| Verification | Provider isolation unverified on every OS | CLI contract tested with fixtures; real runtime/provider pairs unverified |

Neither engine currently provides automatic quota routing or subscription
rotation. Canonical history is a useful gents capability, not proof that every
provider pair can replay every tool or reasoning item. Kimi Code subscription
support through gents is unverified. See the [deep evaluation](gents-evaluation.md).

## Native profiles

```sh
aswp profile add claude --engine native --alias work
aswp login work --experimental-native
aswp run work --engine native --experimental-native
```

The existing positional syntax works without `--engine native`. Native arguments
after `--` are passed through without a shell. See [CLI details](cli.md).

## Set up a gents profile

Register the future runtime address and an initial agent binding:

```sh
aswp profile add --engine gents --alias relay \
  --address 127.0.0.1:9191 --agent setup-pending
aswp profile show relay --json
```

`profile add gents` is an equivalent shorthand. The home is an opaque directory
under AgentSwapper state; `profile show` reports `data.profileHome`. Registration
creates no credentials or runtime. Use a dedicated home/listener per profile.
Addresses must be literal loopback IPs with a nonzero port; IPv6 uses `[::1]:PORT`.
Remote URLs, hostnames and duplicate active addresses are refused.

With the reported home in `GENTS_PROFILE_HOME`, initialize gents and configure its
tool workspace. These are gents commands, run separately by the operator:

```sh
gents init --home "$GENTS_PROFILE_HOME" --tool-root /absolute/path/to/project
gents server --home "$GENTS_PROFILE_HOME" \
  --http-addr 127.0.0.1 --http-port 9191 --p2p-transport none
```

The initial tool package is gents' read-only default. Configure the intended
model, provider login and tool permissions using the installed gents version's
setup workflow. Its reviewed CLI includes `claude-login` and `codex-login`, both
with an explicit `--home`. AgentSwapper neither performs those logins nor imports
native credentials. The runtime must be ready before launching chat.

Bind the exact agent ID reported by gents initialization/configuration (for
example its `default_agent_id`), replacing `YOUR_AGENT_ID` below:

```sh
aswp profile bind relay --address 127.0.0.1:9191 --agent YOUR_AGENT_ID
aswp run relay --dry-run
aswp run relay --engine gents --experimental-gents
aswp run relay --experimental-gents --resume
aswp runs
aswp run relay --experimental-gents --session EXISTING_SESSION_UUID
```

Agent IDs are case-sensitive, 1–128 printable ASCII characters without whitespace;
underscores, colons and hyphens are supported. A rebind retains the same home and
credentials. It requires a free client lease and no unresolved launch intent;
it does not stop work or change configuration in the external runtime.

Every new launch chooses a fresh UUID before spawning the client. The launch
intent records that UUID, the exact agent/address binding and, for `--resume`,
the source run ID. `aswp runs` and launch previews show these references;
conversation text and credentials are not stored. A dry-run UUID is a preview,
not a reservation.

`--resume` selects this profile's latest recorded attempt in journal order. It
requires a tracked session, the same binding, an observed client process and a
zero `external_client_exited` result. It refuses failed, unresolved, manually
attested, legacy or differently bound attempts without falling back to an older
conversation. The source is checked again under the profile lease and database
write transaction before spawn. Renaming a profile preserves its history.

`--session UUID` explicitly continues or creates that UUID under the current
binding; it cannot be combined with `--resume`. An unknown UUID creates a new
session in gents. Every turn uses the profile's bound agent, even when another
agent started the session. AgentSwapper does not check remote session existence
or detect a replaced runtime behind an unchanged binding. Restoring the exact
address and agent after a rebind allows manual resume again; binding equality
is not an identity or configuration-generation check. A recorded successful
client exit proves neither completed work nor stopped runtime tools. Review
uncertain work before manually continuing; there is no automatic retry.

The actual launch is limited to `gents chat`, the owned `--home`, bound
`--graphql` and `--agent-id`, and the chosen `--session-id`. There is no automatic
import of native conversations or discovery of sessions created outside this
wrapper. Older runs remain visible with an unknown session ID.
Use the gents interactive prompt for messages. Forwarded arguments and
`aswp login` are refused for gents profiles. `--experimental-native` cannot
authorize gents, including through the Rust API.

## Trust and lifecycle

Before an actual launch, AgentSwapper reads only a bounded, private, regular
`runtime.json` in the selected home and requires its `home` and `graphql` address
to match. This check runs after acquiring the profile lease and before recording
the run intent. The known unbracketed IPv6 form written by gents 0.21.0 is accepted
only when it exactly matches the bound address; the launched URL is bracketed.
Missing state appears in a setup preview and blocks launch. The check neither
contacts the server nor proves it is alive or authenticates its identity.
It checks the opened file's metadata, rejects links and multiple hardlinks, and
on Unix opens without following a final symlink or blocking on a FIFO. An atomic
replacement may leave the reader with the previous valid snapshot; this is not
an isolation boundary against another process running as the same user.
**The listener remains unverified: gents presents this home's authentication to
the bound address.** Use a runtime/listener you control; a stale or hostile local
listener can receive that authentication. This client adapter does not start,
stop, inspect or secure the runtime's other listeners.

The child receives an allowlist of terminal, locale, home and OS integration
environment variables. Proxy settings, dynamic-loader overrides, `GENTS_*`
overrides and unrelated secrets are not inherited. Native authentication and routing variables are also removed from the gents
client. Native-engine launches retain their conflict-refusal policy.
The external runtime has its own environment and permission policy.

A client exit is journaled as `external_client_exited`, with custody
`external_runtime_unknown`. This releases the **client** lease for another
explicit chat, not a runtime lock or permission to switch automatically. If the
supervisor crashes, the unfinished intent blocks reuse. After independently
stopping that client and its descendants, `aswp recover RUN_ID --confirm-stopped`
records an attestation; gents runtime custody remains unknown. A client spawn
failure also leaves external runtime custody unknown; `spawn_failed` describes
only the failed client launch.

Removing a profile retains its home and any macOS Keychain items. It neither
revokes login nor stops the runtime. Provider/model changes in the reviewed gents
version affect an agent and may affect other sessions sharing that agent. Use
separate agent scopes for independent tasks.

## Contract and qualification

The adapter was reviewed against gents 0.21.0 at
[`89f1b67`](https://github.com/gents-ai/gents/tree/89f1b6760e2297b3d8a09d347c43eaf6978a8b31).
It uses the CLI's own signed/authenticated requests; no gents crate, Codex shim,
HTTP proxy or credential-copying code is linked into AgentSwapper. Installed
versions are discovered without executing them; version compatibility is not
probed or enforced yet. `--executable` can select a trusted absolute binary.

Automated fixtures cover launch scope, environment, refusal paths, exit history,
recovery, rebinding and registry upgrades. They do not test a real authenticated
gents runtime, provider subscription or platform credential store. Full runtime
containment, provider-pair replay qualification, automated switching and managed
handover between engines remain in [roadmap G0](roadmap.md#g0---optional-gents-engine-qualification).
