# Native support and verification

All real-provider cells start **unsupported for verified isolation**. The
developer preview has explicit experimental native execution, not a promoted
adapter. A fixture test is not evidence about a vendor's login storage.

| Harness | Linux | WSL2 | macOS | Windows |
| --- | --- | --- | --- | --- |
| Claude Code | unverified | unverified | unverified | unverified |
| Codex | unverified | unverified | unverified | unverified |
| Kimi Code | unverified | unverified | unverified | unverified |

For every promoted cell, record exact CLI version/build, OS build, executable
packaging, authentication/storage mode, selected home variable, native login
arguments, file/credential-store traces, refresh persistence, interruption,
descendant cleanup, and native resume results. Keep dedicated account evidence
outside public source if it contains identifiers.

The preview binds Claude Code through `CLAUDE_CONFIG_DIR`, Codex through
`CODEX_HOME`, and current Kimi Code through `KIMI_CODE_HOME`. Kimi legacy layout
detection is not implemented. Native login command shapes are unverified and
must pass the same version/platform matrix before being promoted.

Manual encrypted handover packs are available as a draft schema-v0 workflow;
see [handover](handover.md). These do not promote any native support cell.

Automatic switching, quota routing, credential transfer, the full managed
capsule-v1 protocol, encrypted account backups, structured adapters, and global
activation are not implemented. See the [roadmap](roadmap.md).

The optional gents attached-client engine is **implemented, experimental and
unverified with real providers**. Its CLI contract tests do not qualify a native
CLI, subscription, engine/provider pair or platform. `aswp engines` compares
ownership and tradeoffs; [engine setup](engines.md) documents the opt-in.

| Engine contract | Linux | WSL2 | macOS | Windows |
| --- | --- | --- | --- | --- |
| gents attached CLI fixture | CI required | tested on WSL2 | CI required | CI required |
| gents runtime/provider/account pairs | unverified | unverified | unverified | unverified |

Cross-platform fixture evidence is recorded in [engine validation](engine-validation.md).
Runtime/provider qualification remains separate from the native matrix above;
see [evaluation](gents-evaluation.md) and roadmap G0.
