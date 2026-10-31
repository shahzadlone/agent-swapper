# Linux manager transport evaluation

Read-only, provider-free **qualification code**, kept outside the production
workspace and binary dependency graph. It creates no service, requests no
privileges, reads no login data and issues no process-custody receipt.

This is the first checkpoint toward an authenticated managed-invocation
observer. The existing core parser validates text structure only. This tool
instead reads D-Bus properties directly and compares them with the disposable
system-manager fixture's independently collected observations.

The fixed endpoint is `/run/dbus/system_bus_socket`. Directory ancestry must be
root-owned and not writable by group/others; the socket must be root-owned.
The connected listener must report UID 0. This deliberately narrow policy is
an assumption to measure, not a claim about every Linux distribution. The
system-manager unique bus name must belong to UID 0 / PID 1, and an optional
received process descriptor must identify PID 1 in local `fdinfo`. The observer
requires full identity UID/GID maps and PID 1 in `/init.scope` on unified cgroup
v2. Unsupported layouts fail without fallback. `DBUS_SYSTEM_BUS_ADDRESS` is
ignored, and the harness verifies an override listener receives no connection.
Namespace metadata is read through a verified procfs directory, with the
kernel-generated self link resolved within that mount. Its PID view must agree
with the running process. `openat2` refuses mount crossings and symlinks below
the retained process/cgroup directories, so a bind-mounted file cannot supply
a forged full-range identity map. An unavailable `openat2` is a refusal, not a
fallback to ordinary path reads.

All manager calls use its unique bus name. Success replies require the expected
sender. Unit reads bracket properties with the invocation ID and recheck the
bus owner. `GetUnit` and `GetUnitByInvocationID` intentionally return different
object paths: the latter addresses one invocation and expires with it. The
observer reads properties through that invocation path and cross-checks its
identity with the named unit before and after. The unit must be an
active transient `aswp-managed-*.service` with the expected user/PID/cgroup,
`Delegate=false` and `KillMode=control-group`. The optional cgroup
`user.invocation_id` xattr is recorded only by length, equality and errno, and
is not relied on as a custody proof. Unknown properties, wrong field types,
changed identities and denied reads fail qualification.

Live-unit observations also retain a cgroup directory and a main-process pidfd
until the snapshot is complete. A descriptor-relative walk refuses mutable or
linked cgroup ancestry. The root, slice and unit migration controls must be
root-owned, and opening each for writing must fail with access denied. The
process's four user IDs and exact cgroup membership must agree, its pidfd must
remain live, and the held scope must report `populated 1`. The manager's
invocation is rechecked after kernel corroboration. The hosted fixture compares
the reported device/inode with its own scope observation. No numeric PID is
signalled, and a live snapshot alone does not establish continuous custody.

`--watch UNIT USER PID INVOCATION` retains those handles and the same bus
connection. It emits a `bound` record, then a `retired` record only after the
original directory loses its kernel `cgroup.events` entry, the held pidfd
reports exit, and the same authenticated manager reports that invocation
absent or inactive/failed. Name reuse never substitutes a new directory or
invocation. A manager error counts as absence only for the exact invocation
lookup and expected sender. An object collected during property reads needs
a fresh authenticated absence; other errors fail without a retired result.
The retired record carries the initial `unit` snapshot unchanged and separate
current `retirement` facts. This remains a local measurement, excluding work
delegated outside the service, root actions and hostile collaborators outside
the unit. It issues no production custody receipt.

The hosted name-reuse trial pauses the owned observer after its bound record,
retires the original service and creates a new invocation under the same unit
name before resuming observation. It requires retirement of only the original
held scope, a continuing replacement worker, and a specific refusal when a new
observer is given the old invocation ID with the replacement's current PID.
Both services retain bounded manager lifetimes and explicit cleanup. Native
results for this additional trial are pending.

Binding has an eight-second asynchronous budget including connect,
authentication and property queries, with two-second method timeouts. A plain
snapshot has a ten-second total budget including close; watch adds a bounded
twenty-second retirement phase within a thirty-second total budget. The four-message queue and
8 KiB **post-receive** reply check are not a custom wire-allocation cap: zbus
retains its own larger message limit. No signal subscriptions, proxy caches,
service activation calls, interactive authorization or mutating calls are used.
The system bus and root are trusted; this is not isolation from a compromised
bus/kernel or administrative changes. The result does not establish the
production namespace, journal, launch or terminal contract.
The async timer cannot preempt synchronous kernel/filesystem operations; the
hosted harness separately bounds and terminates its owned probe process.

Dependencies are pinned in the isolated lockfile: zbus 6.2.0 with only its Tokio
transport, Tokio 1.54.1 and rustix 1.1.6. Their graph passes the repository's
advisory, license, ban and source policies. This is dependency policy evidence,
not an independent audit of every dependency. No upstream implementation was
copied into the product.

```sh
cargo +1.98.0 test --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml
cargo +1.98.0 build --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml
python3 tools/linux-manager-evaluation/check_transport.py tools/linux-manager-evaluation/target/debug/aswp-linux-manager-evaluation
```

The local WSL2 check reports no system manager and refuses observation. CI on
disposable Ubuntu 22.04 and 24.04 must pass `--require-manager`, then compare
the live unit snapshots during graceful stop, forced stop and client loss.
The corrected identity-only observer at `6ab1fb6` passed all three trials on
both images in [run 41164083613](https://github.com/shahzadlone/agent-swapper/actions/runs/41164083613).
Both listeners reported UID 0/PID 1, and the manager credentials identified
UID 0/PID 1 without `ProcessFD`. Ubuntu 22.04 returned ENODATA (61) for the
optional invocation xattr; Ubuntu 24.04 returned the matching 32-byte hex ID.
Kernel corroboration subsequently passed on both images at `9c56a93` in
[run 41164302159](https://github.com/shahzadlone/agent-swapper/actions/runs/41164302159).
Retained-handle retirement subsequently passed all three trials on both images
at `181aab0` in [run 41164791650](https://github.com/shahzadlone/agent-swapper/actions/runs/41164791650).
The procfs-overlay and replacement-socket controls passed on both images at
`0622b60` in [run 41165405843](https://github.com/shahzadlone/agent-swapper/actions/runs/41165405843).
Each reported its intended refusal with no observation emitted. The only
service creation remains the existing explicitly gated hosted fixture. Never
spoof its CI guards locally.

The refusal fixture is additionally opted in with `ASWP_MANAGER_REFUSALS=1`.
Each case runs in its own private mount namespace on disposable hosted CI:
an overlaid identity map, a substituted ordinary directory at `/proc`, a
user-owned bus socket, and a root-owned socket inode whose actual listener
remains an ordinary user. It requires the specific refusal diagnostic, keeps
the real-host positive baseline, drops privileges before running the observer,
and cleans up only owned children. A root-side timeout independently bounds
the namespace process group. It never mounts on the user's host or a
self-hosted runner. These controls do not exhaust namespace or bus adversaries.

The first Ubuntu 22.04 run at `94b52d9` authenticated the root socket listener
and root/PID-1 manager, with no `ProcessFD` credential. Its live-unit check
refused because the initial code incorrectly required the two lookup paths to
be equal. The correction follows systemd's
[invocation-path implementation](https://github.com/systemd/systemd/blob/v249/src/core/dbus-manager.c)
and requires its own completed native run; the failed run is not unit-observer
qualification. The earlier architecture review made the same incorrect path
assumption, so its recommendation was not adopted unchanged.

Opus 5.5 xhigh reviewed the next-stage architecture and recommended this
measurement before selecting a production peer policy. Later checkpoints need
production API separation, broader live refusal/replacement fixtures and
independent source review. The design review
does not qualify this implementation. No production backend is enabled.
The requested follow-up implementation review could not run because Claude
reported its subscription session limit. It remains outstanding; the failed
request is not source-review evidence.

References: [systemd's D-Bus interface](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html),
[D-Bus credentials](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-connection-credentials),
and the pinned zbus 6.2.0 registry source. Version 6 uses the async API and
`zbus::wire`; older blocking-builder examples do not describe this version.
