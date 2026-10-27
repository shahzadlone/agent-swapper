#![forbid(unsafe_code)]
#[cfg(test)]
mod tests {
    use gents_loop::backend_provider::BackendProviderKind;
    use gents_loop::openai_wire::OpenAiWireApi;
    use gents_loop::provider_input::ProviderInputCounter;
    use gents_protocol::message::{
        AssistantContent, Message, ToolCall, ToolFunction, ToolResultContent, UserContent,
    };

    fn tool_history() -> Vec<Message> {
        vec![
            Message::user("Inspect README"),
            Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(ToolCall::new(
                    "toolu_source_1".into(),
                    ToolFunction {
                        name: "read_file".into(),
                        arguments: serde_json::json!({"path":"README.md"}),
                    },
                ))],
            },
            Message::User {
                content: vec![UserContent::tool_result(
                    "toolu_source_1",
                    vec![ToolResultContent::text("project notes")],
                )],
            },
            Message::user("Continue"),
        ]
    }
    fn project(history: &[Message], provider: BackendProviderKind) -> serde_json::Value {
        let request = rig::completion::CompletionRequest {
            model: None,
            preamble: Some("System instructions".into()),
            chat_history: rig::OneOrMany::many(gents_loop::rig_compat::to_rig_messages(history))
                .unwrap(),
            documents: vec![],
            tools: vec![],
            temperature: None,
            max_tokens: None,
            tool_choice: None,
            additional_params: None,
            output_schema: None,
        };
        let counter = ProviderInputCounter::new(provider, OpenAiWireApi::Responses, "test-model");
        counter.project_body(&request).unwrap()
    }
    #[test]
    fn responses_projection_preserves_matched_nonempty_tool_call_ids() {
        let history = tool_history();
        let body = project(&history, BackendProviderKind::OpenAiCompatible);
        let input = body["input"].as_array().unwrap();
        let call = input
            .iter()
            .find(|item| item["type"] == "function_call")
            .unwrap();
        let result = input
            .iter()
            .find(|item| item["type"] == "function_call_output")
            .unwrap();
        // Provider-free contract: a completed pair must retain a nonempty matching call ID.
        assert_eq!(call["call_id"], "toolu_source_1");
        assert_eq!(result["call_id"], call["call_id"]);
        assert!(call.get("id").is_none(), "foreign item ID must not be sent");
        assert_eq!(
            history,
            tool_history(),
            "projection must preserve canonical source"
        );
    }
    #[test]
    fn mixed_parallel_history_preserves_distinct_ids_and_native_call_id() {
        let mut history = tool_history();
        let native = ToolCall::new(
            "fc_native_item".into(),
            ToolFunction::new("read_file".into(), serde_json::json!({"path":"Cargo.toml"})),
        )
        .with_call_id("call_native_pair".into());
        if let Message::Assistant { content, .. } = &mut history[1] {
            content.push(AssistantContent::ToolCall(native));
        }
        if let Message::User { content } = &mut history[2] {
            // Results deliberately arrive in the opposite order to their calls.
            content.insert(
                0,
                UserContent::tool_result_with_call_id(
                    "fc_native_item",
                    "call_native_pair".into(),
                    vec![ToolResultContent::text("package manifest")],
                ),
            );
        }
        let before = history.clone();
        for provider in [
            BackendProviderKind::OpenAiCompatible,
            BackendProviderKind::ChatGptCodex,
        ] {
            let body = project(&history, provider);
            let input = body["input"].as_array().unwrap();
            let calls: Vec<_> = input
                .iter()
                .filter(|item| item["type"] == "function_call")
                .collect();
            let results: Vec<_> = input
                .iter()
                .filter(|item| item["type"] == "function_call_output")
                .collect();
            assert_eq!(calls.len(), 2);
            assert_eq!(results.len(), 2);
            for expected in ["toolu_source_1", "call_native_pair"] {
                assert_eq!(
                    calls
                        .iter()
                        .filter(|item| item["call_id"] == expected)
                        .count(),
                    1
                );
                assert_eq!(
                    results
                        .iter()
                        .filter(|item| item["call_id"] == expected)
                        .count(),
                    1
                );
            }
            assert!(calls.iter().all(|item| item["id"] != "toolu_source_1"));
            assert_eq!(
                history, before,
                "projection must not mutate canonical history"
            );
        }
    }
    #[test]
    fn quota_observations_expire_and_do_not_mean_zero_usage() {
        use gents_loop::account_usage::*;
        let now = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH + chrono::Duration::days(1);
        let report = usage_from_headers(
            [
                ("x-codex-primary-used-percent", "95"),
                ("x-codex-primary-window-minutes", "300"),
            ],
            UsageSource::Header,
            now,
        );
        assert_eq!(visible_windows(&report, now)[0].1, Freshness::Fresh);
        assert_eq!(
            visible_windows(&report, now + chrono::Duration::minutes(16))[0].1,
            Freshness::Stale
        );
        assert!(visible_windows(&report, now + chrono::Duration::minutes(61)).is_empty());
    }
}
