//! Comparisons describe ownership and current limits, not provider qualification.
use agentswapper_core::Result;
use serde::Serialize;

#[derive(Serialize)]
struct Engine {
    engine: &'static str,
    frontend: &'static str,
    status: &'static str,
    credentials_and_permissions: &'static str,
    strengths: &'static [&'static str],
    limitations: &'static [&'static str],
}

const ENGINES: [Engine; 2] = [
    Engine {
        engine: "native",
        frontend: "Claude Code, Codex CLI, Kimi Code CLI",
        status: "experimental; profile isolation unverified",
        credentials_and_permissions: "selected native CLI",
        strengths: &[
            "Familiar provider terminal, tools, hooks and permission workflow.",
            "No separate execution runtime to operate.",
        ],
        limitations: &[
            "Sessions and context formats differ across brands; manual handover is available.",
            "A direct child exit does not prove descendant cleanup.",
            "No verified quota monitoring or automatic subscription switching yet.",
        ],
    },
    Engine {
        engine: "gents",
        frontend: "gents chat attached to an explicitly configured local runtime",
        status: "experimental; CLI contract fixture-tested, live providers unverified",
        credentials_and_permissions: "gents runtime and its agent configuration",
        strengths: &[
            "Optional common agent runtime with canonical history across supported providers.",
            "Gents manages its own accounts, tools and provider routing.",
            "Explicit session UUID continues or creates a gents conversation using the bound agent.",
        ],
        limitations: &[
            "Requires separate installation, home initialization, authentication and runtime setup.",
            "Client cwd does not set the runtime workspace; configure it in gents.",
            "Client exit does not stop runtime work; AgentSwapper owns only the client lease.",
            "Listener identity is unverified; gents presents this home's authentication to the bound address.",
            "Profile removal retains engine files and macOS Keychain items; it does not stop runtimes.",
            "Native sessions, plugins and permissions do not transfer automatically.",
            "Provider-pair replay and Kimi Code subscription support remain unverified.",
            "Upstream account/model changes affect the agent; concurrent sessions may share them.",
        ],
    },
];

pub(super) fn show(json: bool) -> Result<i32> {
    let mut text = String::from(
        "Choose an engine when registering a profile. Use `aswp profile add --help`.\n",
    );
    for engine in &ENGINES {
        text.push_str(&format!(
            "\n{} — {}\n  Status: {}\n  Credentials and permissions: {}\n",
            engine.engine, engine.frontend, engine.status, engine.credentials_and_permissions
        ));
        for strength in engine.strengths {
            text.push_str(&format!("  + {strength}\n"));
        }
        for limitation in engine.limitations {
            text.push_str(&format!("  - {limitation}\n"));
        }
    }
    text.push_str("\nBoth engines: no automatic switching. Details: docs/engines.md");
    super::emit(json, &ENGINES, &text)?;
    Ok(0)
}
