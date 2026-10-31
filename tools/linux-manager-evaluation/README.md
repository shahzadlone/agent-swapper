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

The API budget is eight seconds including connect, authentication, queries and
explicit close, with two-second method timeouts. The four-message queue and
8 KiB **post-receive** reply check are not a custom wire-allocation cap: zbus
retains its own larger message limit. No signal subscriptions, proxy caches,
service activation calls, interactive authorization or mutating calls are used.
The system bus and root are trusted; this is not isolation from a compromised
bus/kernel or administrative changes. The result does not establish the
production namespace, kernel retirement, journal, launch or terminal contract.

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
Those native results are pending. The only service creation remains the
existing explicitly gated hosted fixture. Never spoof its CI guards locally.

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
typed bindings, kernel corroboration using retained descriptors, retirement
observations, refusal fixtures and independent source review. The design review
does not qualify this implementation. No production backend is enabled.
The requested follow-up implementation review could not run because Claude
reported its subscription session limit. It remains outstanding; the failed
request is not source-review evidence.

References: [systemd's D-Bus interface](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html),
[D-Bus credentials](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-connection-credentials),
and the pinned zbus 6.2.0 registry source. Version 6 uses the async API and
`zbus::wire`; older blocking-builder examples do not describe this version.
