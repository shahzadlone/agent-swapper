#![forbid(unsafe_code)]
#[cfg(test)]
mod tests {
    use gents_fs_runner::protocol::{GrepArgs, NativeFsRunnerRequest};
    use gents_protocol::message::{Message, UserContent};

    #[test]
    fn canonical_context_retains_tool_pair_and_provider_opaque_reasoning() {
        let source = serde_json::json!([
            {"role":"assistant", "id":null, "content":[
                {"id":"toolu_source_1", "call_id":null,
                 "function":{"name":"read_file", "arguments":{"path":"README.md"}}},
                {"id":null, "content":[{"type":"encrypted", "content":"source-provider-only"}]}
            ]},
            {"role":"user", "content":[{"type":"toolresult", "id":"toolu_source_1", "content":[{"type":"text", "text":"project notes"}]}]}
        ]);
        let history: Vec<Message> = serde_json::from_value(source).unwrap();
        let roundtrip: Vec<Message> =
            serde_json::from_slice(&serde_json::to_vec(&history).unwrap()).unwrap();
        assert_eq!(history, roundtrip);
        match &history[1] {
            Message::User { content } => match &content[0] {
                UserContent::ToolResult(result) => {
                    assert_eq!(result.id, "toolu_source_1");
                    assert!(
                        result.call_id.is_none(),
                        "canonical storage alone does not synthesize a Responses call_id"
                    );
                }
                _ => panic!("missing result"),
            },
            _ => panic!("missing user turn"),
        }
    }

    #[test]
    fn codex_initialize_uses_remote_wire_shape() {
        let request = gents_codex_protocol::InitializeParams {
            client_info: gents_codex_protocol::ClientInfo {
                name: "aswp-spike".into(),
                title: None,
                version: "0.0.0".into(),
            },
            capabilities: None,
        };
        let wire = serde_json::to_value(request).unwrap();
        assert_eq!(wire["clientInfo"]["name"], "aswp-spike");
        assert!(wire.get("capabilities").is_none());
    }

    fn grep() -> NativeFsRunnerRequest {
        NativeFsRunnerRequest::Grep(GrepArgs {
            pattern: "handover".into(),
            path: Some(".".into()),
            case_sensitive: true,
            max_matches: 10,
            raw_json: true,
            max_entries_visited: Some(100),
            max_bytes_read: Some(4096),
            max_wall_ms: Some(1000),
        })
    }

    #[test]
    fn read_only_runner_finds_context_with_explicit_budgets() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("README.md"), "one handover\n").unwrap();
        let result = gents_fs_runner::execute_request(root.path().to_path_buf(), grep()).unwrap();
        assert!(result.contains("README.md"));
        assert!(result.contains("handover"));
    }

    #[test]
    fn read_only_runner_refuses_explicit_outside_base() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let result = gents_fs_runner::execute_request_with_base(
            root.path().to_path_buf(),
            Some(outside.path().to_path_buf()),
            grep(),
        );
        assert!(result.is_err());
    }
}
