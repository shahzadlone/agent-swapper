# Agent working agreements

Use conventional commits. Preserve uncommitted work belonging to other tasks.

Work directly on `main`. Do not create feature branches or separate worktrees
unless the user explicitly requests them. Run checkpoint checks on `main` and
record the tested commit; incomplete release features stay disabled until their
required evidence is complete.

## Rust build cleanup (required)

Build artifacts are temporary. Clean up your own Rust outputs regularly, after
completed checkpoints and before finishing or handing off a task. Do not wait
for the user to notice disk growth.

- Before a substantial build, identify the actual target directory, including
  `CARGO_TARGET_DIR`, Cargo config overrides, nested workspaces and worktrees.
  Measure disk use at checkpoint boundaries. If project build caches exceed
  5 GiB, review and remove obsolete caches before adding more; this is a review
  threshold, not permission to delete active outputs.
- Keep only caches needed for current work. Remove completed experiment,
  qualification, cross-compilation and abandoned worktree build outputs. Use
  distinct target directories when concurrent checkouts require isolation;
  retire each directory when that checkout's validation is complete.
- Once builds/tests and downstream consumers are finished, prefer
  `cargo clean --manifest-path /absolute/path/Cargo.toml --target-dir /absolute/path/to/target`.
  For a verified default workspace target, `cargo clean` is sufficient.
  Confirm the resolved paths and ownership first; never run a broad cleanup
  against a shared or unknown target directory.
- Before cleaning, check for active Cargo, rustc, nextest, test and application
  processes using those outputs, including other agents. Never interrupt them
  or delete their files. Recheck later if the outputs are still in use.
- Save required test reports, audit evidence and requested release binaries
  outside the target directory before cleaning. Preserve source, uncommitted
  changes, lockfiles, installed tools and user data. Do not clear shared Cargo
  registry/git caches or Rust toolchains as routine project cleanup.
- Remove your temporary Git worktrees only when clean, no longer in use and
  their commits are retained in the intended integration branch. Never force
  removal of a dirty worktree to recover space.
- Keep an active cache when imminent work genuinely needs it, then clean it
  after its last consumer finishes. Do not clean after every compile if that
  would just force repeated rebuilds. At task completion, verify and briefly
  report recovered space and any deliberately retained build cache.
