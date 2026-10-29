//! Reviewed foreground transitions. Preparing a review never starts an agent.
use std::path::Path;

use agentswapper_core::{Error, ExecutionEngine, Profile, Result, Store, launch::LaunchPlan};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use super::{TEAL, YELLOW, wrapped_rows};

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Run,
    Login,
    Resume,
}

pub(super) struct Review {
    plan: LaunchPlan,
    accepted: bool,
    scroll: u16,
}

pub(super) enum Outcome {
    Continue,
    Cancel,
    Launch,
}

impl Review {
    pub(super) fn prepare(
        store: &Store,
        profile: Profile,
        cwd: &Path,
        executable: Option<&Path>,
        operation: Operation,
    ) -> Result<Self> {
        let mut plan = LaunchPlan::build(
            store,
            profile,
            executable,
            cwd,
            vec![],
            matches!(operation, Operation::Login),
        )?;
        if matches!(operation, Operation::Resume) {
            plan = plan.with_latest_gents_session(store)?;
        }
        plan.check_environment(|key| std::env::var_os(key))?;
        plan.check_claude_shared_auth()?;
        plan.check_kimi_legacy()?;
        if !plan.check_gents_runtime()? {
            return Err(Error::GentsRuntimeMismatch);
        }
        // This is a readiness check, not a reservation. Execution must take the
        // lease again and validate the current journal/profile under it.
        drop(store.lease(plan.profile().id)?);
        Ok(Self {
            plan,
            accepted: false,
            scroll: 0,
        })
    }

    pub(super) fn reset_acceptance(&mut self) {
        self.accepted = false;
    }

    pub(super) fn into_plan(self) -> LaunchPlan {
        self.plan
    }

    pub(super) fn key(&mut self, key: KeyEvent, area: Rect, masked: bool) -> Outcome {
        if key.code == KeyCode::Esc
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g'))
        {
            return Outcome::Cancel;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
        {
            return Outcome::Continue;
        }
        let body = Self::sections(area)[1];
        let maximum = self.max_scroll(body, masked);
        self.scroll = self.scroll.min(maximum);
        match key.code {
            KeyCode::PageDown | KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(3).min(maximum);
            }
            KeyCode::PageUp | KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(3);
            }
            KeyCode::Char(' ') if !masked => self.accepted = !self.accepted,
            KeyCode::Enter if self.accepted && !masked => return Outcome::Launch,
            _ => {}
        }
        Outcome::Continue
    }

    fn sections(area: Rect) -> [Rect; 3] {
        let inner = Block::default()
            .borders(Borders::TOP)
            .padding(Padding::horizontal(1))
            .inner(area);
        let parts = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(inner);
        [parts[0], parts[1], parts[2]]
    }

    fn content(&self, masked: bool) -> Vec<Line<'static>> {
        let preview = self.plan.preview();
        let field = |value: String| {
            if masked {
                "[hidden]".to_owned()
            } else {
                agentswapper_core::terminal_text(&value)
            }
        };
        let mut lines = vec![
            format!(
                "Destination: {} / {}",
                field(preview.profile.alias.to_string()),
                preview.profile.harness
            ),
            format!("Program: {}", field(preview.program.display().to_string())),
            format!(
                "Profile home: {}",
                field(preview.profile_home.display().to_string())
            ),
        ];
        if preview.engine == ExecutionEngine::Gents {
            if let Some(binding) = &preview.profile.gents {
                lines.push(format!(
                    "Runtime: {} / agent {}",
                    field(binding.address().to_string()),
                    field(binding.agent().to_string())
                ));
            }
            lines.push("Workspace and permissions: external gents runtime.".to_owned());
            lines.push(format!(
                "Continuity: {} gents session",
                if preview.resumed_from.is_some() {
                    "resume latest"
                } else {
                    "new"
                }
            ));
            if let Some(session) = preview.session {
                lines.push(format!("Session: {}", field(session.to_string())));
            }
            if let Some(source) = preview.resumed_from {
                lines.push(format!("Source run: {}", field(source.to_string())));
            }
            lines.push(
                "Listener identity: unverified. Runtime work may outlive this chat client."
                    .to_owned(),
            );
        } else {
            lines.push(format!(
                "Workspace: {}",
                field(preview.working_directory.display().to_string())
            ));
            lines.push(if preview.operation == "login" {
                "Action: native agent login in this profile home.".to_owned()
            } else {
                "Continuity: new conversation. Context is not transferred.".to_owned()
            });
            lines.push(
                "Permissions and tools: native agent. Descendants may outlive its exit.".to_owned(),
            );
        }
        lines.extend([
            "".to_owned(),
            "Experimental launch: profile isolation is unverified.".to_owned(),
            "Quota: unknown. Automatic switching is not enabled.".to_owned(),
            "The dashboard returns when the agent/client exits.".to_owned(),
            "Agent output has its own privacy settings.".to_owned(),
            "Check outgoing work and any background jobs before starting another agent.".to_owned(),
        ]);
        lines.into_iter().map(Line::from).collect()
    }

    fn max_scroll(&self, body: Rect, masked: bool) -> u16 {
        u16::try_from(
            wrapped_rows(self.content(masked), body.width)
                .len()
                .saturating_sub(usize::from(body.height)),
        )
        .unwrap_or(u16::MAX)
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect, masked: bool) {
        frame.render_widget(
            Block::default()
                .borders(Borders::TOP)
                .title(" Review launch ")
                .padding(Padding::horizontal(1)),
            area,
        );
        let parts = Self::sections(area);
        frame.render_widget(
            Paragraph::new(if self.plan.preview().operation == "login" {
                "Sign in with the native agent"
            } else {
                "Start the selected agent"
            })
            .style(Style::default().fg(TEAL).add_modifier(Modifier::BOLD)),
            parts[0],
        );
        frame.render_widget(
            Paragraph::new(wrapped_rows(self.content(masked), parts[1].width))
                .scroll((self.scroll.min(self.max_scroll(parts[1], masked)), 0)),
            parts[1],
        );
        let acceptance = if masked {
            "Unmask with Ctrl-P to launch. Agent output is outside dashboard privacy."
        } else if self.accepted {
            "[x] Experimental launch accepted. Enter starts the agent; Esc cancels."
        } else {
            "[ ] Space accepts this experimental launch. Enter alone never starts it."
        };
        frame.render_widget(
            Paragraph::new(acceptance)
                .style(Style::default().fg(YELLOW))
                .wrap(Wrap { trim: true }),
            parts[2],
        );
    }

    pub(super) fn footer(&self) -> &'static str {
        " Space accept  Enter start  Esc cancel\n PgUp/PgDn scroll  Ctrl-P privacy\n Ctrl-G cancel  Ctrl-C quit"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use agentswapper_core::{GentsBinding, Harness};

    fn key(review: &mut Review, code: KeyCode, masked: bool) -> Outcome {
        review.key(
            KeyEvent::new(code, KeyModifiers::NONE),
            Rect::new(0, 3, 80, 18),
            masked,
        )
    }

    fn review(store: &mut Store) -> Review {
        let profile = store
            .register(Harness::Codex, "private-canary".parse().unwrap())
            .unwrap();
        Review {
            plan: LaunchPlan::build(
                store,
                profile,
                Some(&std::env::current_exe().unwrap()),
                store.root(),
                vec![],
                false,
            )
            .unwrap(),
            accepted: false,
            scroll: 0,
        }
    }

    #[test]
    fn review_requires_separate_unmasked_acceptance_and_preserves_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let mut review = review(&mut store);
        assert!(matches!(
            key(&mut review, KeyCode::Enter, false),
            Outcome::Continue
        ));
        assert!(matches!(
            key(&mut review, KeyCode::Char(' '), true),
            Outcome::Continue
        ));
        assert!(!review.accepted);
        key(&mut review, KeyCode::Char(' '), false);
        assert!(matches!(
            key(&mut review, KeyCode::Enter, true),
            Outcome::Continue
        ));
        review.reset_acceptance();
        assert!(matches!(
            key(&mut review, KeyCode::Enter, false),
            Outcome::Continue
        ));
        review.key(
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::ALT),
            Rect::new(0, 3, 80, 18),
            false,
        );
        assert!(!review.accepted);
        key(&mut review, KeyCode::Char(' '), false);
        assert!(matches!(
            key(&mut review, KeyCode::Enter, false),
            Outcome::Launch
        ));
        assert!(matches!(
            key(&mut review, KeyCode::Esc, false),
            Outcome::Cancel
        ));
        assert!(store.runs(1).unwrap().is_empty());
    }

    #[test]
    fn review_masks_paths_and_identity_and_scroll_clamps_after_resize() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let mut review = review(&mut store);
        let text = |review: &Review, masked| {
            review
                .content(masked)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        let masked = text(&review, true);
        assert!(!masked.contains("private-canary"));
        assert!(!masked.contains(&store.root().display().to_string()));
        assert!(masked.contains("Context is not transferred"));
        assert!(text(&review, false).contains("private-canary"));
        for _ in 0..100 {
            review.key(
                KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
                Rect::new(0, 3, 40, 8),
                false,
            );
        }
        assert!(review.scroll > 0);
        review.key(
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
            Rect::new(0, 3, 160, 42),
            false,
        );
        assert_eq!(review.scroll, 0);
    }

    #[test]
    fn launch_review_renders_private_and_resized_screens_without_identity_leaks() {
        use super::super::{Dashboard, preview, tests::screenshot};
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let mut app = Dashboard {
            launch: Some(review(&mut store)),
            masked: true,
            ..Dashboard::default()
        };
        app.refresh(&store).unwrap();
        for (width, height) in [
            (0, 0),
            (20, 6),
            (40, 14),
            (44, 17),
            (80, 24),
            (100, 32),
            (160, 48),
        ] {
            let screen = screenshot(&app, width, height);
            assert!(!screen.contains("private-canary"));
            assert!(!screen.contains(&store.root().display().to_string()));
            if width >= 40 {
                assert!(screen.contains("Review launch"));
                assert!(screen.contains("Unmask with Ctrl-P"));
                preview::export(&app, &format!("launch-private-{width}"), width, height);
            }
        }
        insta::assert_snapshot!("launch_private", screenshot(&app, 80, 24));
        app.masked = false;
        for (width, height) in [(80, 24), (100, 32), (160, 48)] {
            let screen = screenshot(&app, width, height);
            assert!(screen.contains("Space accepts this experimental launch"));
            preview::export(&app, &format!("launch-review-{width}"), width, height);
        }
    }

    #[test]
    fn readiness_refuses_unsupported_native_resume_and_gents_login() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let native = review(&mut store).plan.profile().clone();
        let executable = std::env::current_exe().unwrap();
        assert!(matches!(
            Review::prepare(
                &store,
                native,
                store.root(),
                Some(&executable),
                Operation::Resume
            ),
            Err(Error::UnsupportedSession)
        ));
        let profile = store
            .register_gents(
                "relay".parse().unwrap(),
                GentsBinding::new(
                    "127.0.0.1:9191".parse().unwrap(),
                    "private_agent".parse().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            Review::prepare(
                &store,
                profile.clone(),
                store.root(),
                Some(&executable),
                Operation::Login
            ),
            Err(Error::UnsupportedGentsOperation)
        ));
        assert!(matches!(
            Review::prepare(
                &store,
                profile.clone(),
                store.root(),
                Some(&executable),
                Operation::Run
            ),
            Err(Error::GentsRuntimeMismatch)
        ));
        let home = store.profile_home(profile.id).unwrap();
        let runtime = home.join("runtime.json");
        std::fs::write(
            &runtime,
            serde_json::to_vec(
                &serde_json::json!({"home":home,"graphql":"http://127.0.0.1:9191/api/v0/graphql"}),
            )
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let lease = store.lease(profile.id).unwrap();
        assert!(matches!(
            Review::prepare(
                &store,
                profile.clone(),
                store.root(),
                Some(&executable),
                Operation::Run
            ),
            Err(Error::Busy)
        ));
        drop(lease);
        let review = Review::prepare(
            &store,
            profile.clone(),
            store.root(),
            Some(&executable),
            Operation::Run,
        )
        .unwrap();
        let masked = review
            .content(true)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for canary in [
            "private_agent",
            "127.0.0.1",
            "9191",
            &review.plan.preview().session.unwrap().to_string(),
        ] {
            assert!(!masked.contains(canary));
        }
        // An accepted, prepared plan cannot bypass a later availability change.
        store.set_enabled(profile.id, false).unwrap();
        assert!(matches!(
            review.into_plan().execute_gents(&mut store, true),
            Err(Error::Disabled)
        ));
        assert!(store.runs(1).unwrap().is_empty());
        assert!(store.verify().unwrap().consistent);
    }
}
