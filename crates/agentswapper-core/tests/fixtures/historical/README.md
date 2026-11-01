# Historical registry fixtures

These databases were created by clean builds of actual historical AgentSwapper
revisions. They are not current databases with columns removed or a downgraded
schema number.

| Schema | Producer revision |
| --- | --- |
| 5 | `da6b2d931a38968277a8bdb24272ebdaa15f7c3b` |
| 6 | `533c3551377d4761fe6bf0b1192c353f2c8b6938` |
| 7 | `63ac7462c617d5d9d0f3a241e142e66c9b9d0e72` |

Each has seven original journal events and two Codex-labelled fixture profiles.
A local Rust stub exits 7 for one run. A second stub and its launcher are killed
in their owned process group after the spawn observation commits, leaving a
pending run. The stubs never call a provider, read credentials or contact a
network. Their environment points to an empty temporary home. No vendor files
are included. Stored PIDs are historical diagnostics and must never be signalled.

The JSON sidecars record source revisions, database and producer-binary hashes,
the stub hash and qualification results. During generation, a current executable
upgraded a copy to schema 9 and the historical executable refused that upgraded
copy with exit 125. The checked-in database remains at its original version.

The Rust tests migrate these bytes through the real Store, compare every event
and timestamp, check completed/pending state and lease behavior, verify the
pre-migration backup, and reopen the result. The matrices run on native Linux,
macOS and Windows; generation itself uses ordinary Linux processes.

To generate a new fixture, create a clean worktree at the matching pinned
revision, build the current `aswp`, then run from the current repository:

```sh
python3 tools/generate_historical_registry_fixture.py 5 \
  /absolute/path/to/historical-worktree \
  /absolute/path/to/build-directory \
  /absolute/path/to/new-output-directory \
  /absolute/path/to/current/aswp
```

The generator builds with the pinned Rust toolchain and locked dependencies.
Each revision uses a separate build directory. Existing fixtures are refused.
UUIDs, PIDs and timestamps vary between generations; byte-identical reproduction
is not expected. Review the source revision, actual schema, event contents and
hash sidecar before replacing any checked-in fixture.
