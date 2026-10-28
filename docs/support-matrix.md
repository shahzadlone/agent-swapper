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

### Kimi source contract

On 2026-10-28, source review of Kimi Code commit
[`0c63065`](https://github.com/MoonshotAI/kimi-code/tree/0c63065fbd7386132b3b8c914de37adfff4c8daf)
confirmed `KIMI_CODE_HOME` and the `kimi login` device-code command shape.
The current project distributes a native binary as well as npm packaging;
the older Python CLI is a separate legacy implementation. These are source
observations, not executed provider/platform qualification.
See the pinned [configuration contract](https://github.com/MoonshotAI/kimi-code/blob/0c63065fbd7386132b3b8c914de37adfff4c8daf/docs/en/configuration/config-files.md)
and [login command](https://github.com/MoonshotAI/kimi-code/blob/0c63065fbd7386132b3b8c914de37adfff4c8daf/apps/kimi-code/src/cli/sub/login.ts).

The inherited-variable conflict policy now also refuses known managed OAuth
hosts/base URL, custom headers, temporary `KIMI_MODEL_*` overrides, the web
password, legacy `KIMI_SHARE_DIR`, and Google SDK credential-file overrides.
It reports names only and never starts a child or writes a run intent on refusal.
The [pinned environment reference](https://github.com/MoonshotAI/kimi-code/blob/0c63065fbd7386132b3b8c914de37adfff4c8daf/docs/en/configuration/env-vars.md)
documents these channels. It also permits arbitrary configured `api_key_env`
names, so a finite conflict list cannot prove credential isolation.

First-launch legacy migration can inspect `~/.kimi` independently of the new
profile home, and `KIMI_SHARE_DIR` can redirect its source. AgentSwapper does not
perform migration or create suppression markers in vendor data. Legacy-layout
detection, migration/refresh traces and global credential-store behavior remain
open gates. See the [migration resolver](https://github.com/MoonshotAI/kimi-code/blob/0c63065fbd7386132b3b8c914de37adfff4c8daf/apps/kimi-code/src/migration/legacy-source.ts)
and [migration guide](https://github.com/MoonshotAI/kimi-code/blob/0c63065fbd7386132b3b8c914de37adfff4c8daf/docs/en/guides/migration.md).

### Other workflows

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
| gents attached CLI fixture | passed in CI | passed locally | passed in CI | passed in CI |
| gents runtime/provider/account pairs | unverified | unverified | unverified | unverified |

Cross-platform fixture evidence is recorded in [engine validation](engine-validation.md).
Runtime/provider qualification remains separate from the native matrix above;
see [evaluation](gents-evaluation.md) and roadmap G0.
