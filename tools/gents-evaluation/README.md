# Provider-free gents consumer contracts

These are AgentSwapper-authored evaluation fixtures, separate from the product
workspace and CI. They neither log in nor make model requests. Cargo downloads
dependencies and executes their build scripts; run only against the reviewed
source. No upstream implementation is vendored here. See the
[evaluation](../../docs/gents-evaluation.md) for findings and limits.

Requirements: Python 3, Git, Rust 1.98.0, and the normal native build tools for
the selected target. Keep the existing checkout clean and detached at one of:

| Source | Revision | Replay contract result |
|---|---|---|
| Reviewed main | `89f1b6760e2297b3d8a09d347c43eaf6978a8b31` | Fails: missing Responses `call_id` |
| Unmerged replay branch | `b4755abe7b737c91b386908fffeb045333d73eb1` | Passes |

For example, prepare an isolated checkout:

```sh
git clone https://github.com/gents-ai/gents.git /tmp/aswp-gents-source
git -C /tmp/aswp-gents-source checkout --detach 89f1b6760e2297b3d8a09d347c43eaf6978a8b31
python3 tools/gents-evaluation/run.py --case minimal \
  --source /tmp/aswp-gents-source --target-dir /tmp/aswp-gents-target
python3 tools/gents-evaluation/run.py --case replay \
  --source /tmp/aswp-gents-source --target-dir /tmp/aswp-gents-target
```

The replay command deliberately returns a failing exit code on the reviewed
main. It tests the public request-projection API with completed Claude-style
tool history; it does not submit that request to a provider. Change the detached
checkout to the replay branch revision and run the same command to verify the
fix. The runner rejects other revisions and tracked source modifications.

`minimal.rs` checks canonical message round trips, Codex initialization shape,
bounded read-only search, and refusal of an explicit search base outside the
workspace. `replay.rs` checks matching tool-call identities, mixed parallel calls with
reversed results, Responses/ChatGPT-Codex projection, and quota freshness.
Preserving an encrypted reasoning field in storage does **not** authorize its
replay to another account or provider.

To cross-typecheck instead of executing tests, install the Rust target and add
`--check-target x86_64-pc-windows-msvc`. This is not a Windows runtime test.

Each case uses its committed consumer lockfile and a temporary, independent
Cargo workspace. The replay consumer repeats the upstream rig patch explicitly:
Cargo patches in a dependency's workspace do not apply transitively. Nothing is
added to AgentSwapper's product dependency graph. These small tests do not build
the full gents runtime or require Lean. Full upstream conformance tests do.
