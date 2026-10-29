use agentswapper_core::{Alias, Error, Profile, ProfileId, Store};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::Line,
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use super::{TEAL, YELLOW, wrapped_rows};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Rename,
    Remove,
}

pub(super) struct ProfileAction {
    profile: Profile,
    kind: Kind,
    draft: String,
    accepted: bool,
    error: Option<Error>,
    changed: bool,
    scroll: u16,
}

pub(super) enum Outcome {
    Continue,
    Cancel,
    Changed { id: ProfileId, kind: Kind },
}

impl ProfileAction {
    pub(super) fn new(profile: Profile, kind: Kind) -> Self {
        Self {
            draft: profile.alias.to_string(),
            profile,
            kind,
            accepted: false,
            error: None,
            changed: false,
            scroll: 0,
        }
    }

    pub(super) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(super) fn reset_acceptance(&mut self) {
        self.accepted = false;
        self.error = None;
    }

    pub(super) fn key(
        &mut self,
        key: KeyEvent,
        store: &mut Store,
        area: Rect,
        masked: bool,
        label: &str,
    ) -> Outcome {
        if key.code == KeyCode::Esc
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g'))
        {
            return Outcome::Cancel;
        }
        if self.kind == Kind::Rename
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('u')
        {
            self.draft.clear();
            self.error = None;
            return Outcome::Continue;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
        {
            return Outcome::Continue;
        }
        let body = Self::sections(area)[0];
        self.scroll = self.scroll.min(self.max_scroll(body, masked, label));
        match key.code {
            KeyCode::PageDown => {
                self.scroll = self
                    .scroll
                    .saturating_add(3)
                    .min(self.max_scroll(body, masked, label))
            }
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(3),
            KeyCode::Char(' ') if self.kind == Kind::Remove => self.accepted = !self.accepted,
            KeyCode::Enter if self.kind == Kind::Rename || self.accepted => {
                self.error = None;
                let alias = if self.kind == Kind::Rename {
                    match self.draft.parse::<Alias>() {
                        Ok(alias) => Some(alias),
                        Err(error) => {
                            self.error = Some(error);
                            return Outcome::Continue;
                        }
                    }
                } else {
                    None
                };
                match store.find_id(self.profile.id) {
                    Ok(current)
                        if current.alias != self.profile.alias
                            || current.gents != self.profile.gents =>
                    {
                        self.profile = current;
                        self.accepted = false;
                        self.changed = true;
                        self.scroll = 0;
                        return Outcome::Continue;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        self.error = Some(error);
                        return Outcome::Continue;
                    }
                }
                let result = match alias {
                    Some(alias) => store.rename_profile(self.profile.id, alias),
                    None => store.remove_profile(self.profile.id),
                };
                match result {
                    Ok(()) => {
                        return Outcome::Changed {
                            id: self.profile.id,
                            kind: self.kind,
                        };
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            KeyCode::Backspace if self.kind == Kind::Rename => {
                self.draft.pop();
                self.error = None;
            }
            KeyCode::Char(value)
                if self.kind == Kind::Rename
                    && !value.is_control()
                    && self.draft.len() + value.len_utf8() <= 32 =>
            {
                self.draft.push(value);
                self.error = None;
            }
            _ => {}
        }
        Outcome::Continue
    }

    fn content(&self, masked: bool, label: &str) -> Vec<Line<'static>> {
        let mut lines = vec![
            format!("Selected: {label} / {}", self.profile.harness),
            String::new(),
        ];
        if self.kind == Kind::Rename {
            let draft = if masked {
                "[hidden]".to_owned()
            } else {
                agentswapper_core::terminal_text(&self.draft)
            };
            lines.extend([
                format!("New label: {draft}"),
                "".to_owned(),
                "Use 1-32 lowercase letters, digits or hyphens; start with a letter.".to_owned(),
                "Profile identity, files and directory mappings stay with this profile.".to_owned(),
            ]);
        } else {
            lines.extend([
                "Unregister this profile and its directory mappings.".to_owned(),
                "Agent files are retained. Subscription login is not revoked.".to_owned(),
                "Busy or unresolved work prevents unregistration.".to_owned(),
                "This interface cannot undo unregistration.".to_owned(),
            ]);
            if self.profile.gents.is_some() {
                lines.push("The external gents runtime is not stopped.".to_owned());
            }
        }
        if self.changed {
            lines.extend([
                "".to_owned(),
                "Another process changed this profile. Review the selected identity again."
                    .to_owned(),
            ]);
        }
        lines.into_iter().map(Line::from).collect()
    }

    fn sections(area: Rect) -> [Rect; 2] {
        let inner = Block::default()
            .borders(Borders::TOP)
            .padding(Padding::horizontal(1))
            .inner(area);
        let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(inner);
        [parts[0], parts[1]]
    }

    fn max_scroll(&self, body: Rect, masked: bool, label: &str) -> u16 {
        u16::try_from(
            wrapped_rows(self.content(masked, label), body.width)
                .len()
                .saturating_sub(usize::from(body.height)),
        )
        .unwrap_or(u16::MAX)
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect, masked: bool, label: &str) {
        frame.render_widget(
            Block::default()
                .borders(Borders::TOP)
                .title(if self.kind == Kind::Rename {
                    " Rename profile "
                } else {
                    " Unregister profile "
                })
                .padding(Padding::horizontal(1)),
            area,
        );
        let parts = Self::sections(area);
        frame.render_widget(
            Paragraph::new(wrapped_rows(self.content(masked, label), parts[0].width))
                .scroll((self.scroll.min(self.max_scroll(parts[0], masked, label)), 0)),
            parts[0],
        );
        let note = match &self.error {
            Some(error) if masked => format!("Action failed ({}).", error.code()),
            Some(error) => agentswapper_core::terminal_text(&error.to_string()),
            None if self.kind == Kind::Rename => {
                "Enter saves the new label. Ctrl-U clears input.".to_owned()
            }
            None if self.accepted => {
                "[x] Unregister accepted. Enter confirms; Esc cancels.".to_owned()
            }
            None => "[ ] Space selects unregistration. Enter alone never unregisters.".to_owned(),
        };
        frame.render_widget(
            Paragraph::new(note)
                .style(
                    Style::default().fg(if self.error.is_some() || self.kind == Kind::Remove {
                        YELLOW
                    } else {
                        TEAL
                    }),
                )
                .wrap(Wrap { trim: true }),
            parts[1],
        );
    }

    pub(super) fn footer(&self) -> &'static str {
        if self.kind == Kind::Rename {
            " Enter save  Ctrl-U clear  Esc cancel\n Ctrl-P privacy  Ctrl-G cancel\n PgUp/PgDn scroll  Ctrl-C quit"
        } else {
            " Space select  Enter unregister  Esc back\n Ctrl-P privacy  Ctrl-G cancel\n PgUp/PgDn scroll  Ctrl-C quit"
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use agentswapper_core::Harness;

    fn key(action: &mut ProfileAction, store: &mut Store, code: KeyCode) -> Outcome {
        action.key(
            KeyEvent::new(code, KeyModifiers::NONE),
            store,
            Rect::new(0, 3, 80, 18),
            false,
            "work",
        )
    }

    fn text(action: &mut ProfileAction, store: &mut Store, value: &str) {
        action.key(
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            store,
            Rect::new(0, 3, 80, 18),
            false,
            "work",
        );
        for value in value.chars() {
            key(action, store, KeyCode::Char(value));
        }
    }

    #[test]
    fn rename_preserves_input_after_invalid_duplicate_and_changed_identity_reviews() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let other = store
            .register(Harness::Codex, "taken".parse().unwrap())
            .unwrap();
        let mut action = ProfileAction::new(profile.clone(), Kind::Rename);
        text(&mut action, &mut store, "Invalid");
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        assert!(matches!(action.error, Some(Error::InvalidAlias)));
        assert_eq!(action.draft, "Invalid");
        text(&mut action, &mut store, "taken");
        key(&mut action, &mut store, KeyCode::Enter);
        assert!(matches!(action.error, Some(Error::DuplicateAlias)));
        assert_eq!(action.draft, "taken");
        text(&mut action, &mut store, "quiet-name");
        let mut peer = Store::open(store.root()).unwrap();
        peer.rename(&profile.alias, "elsewhere".parse().unwrap())
            .unwrap();
        let replacement = peer.register(Harness::Kimi, profile.alias.clone()).unwrap();
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        assert!(action.changed);
        assert_eq!(action.profile.alias.to_string(), "elsewhere");
        assert_eq!(action.draft, "quiet-name");
        assert!(
            matches!(key(&mut action, &mut store, KeyCode::Enter), Outcome::Changed { id, kind: Kind::Rename } if id == profile.id)
        );
        assert_eq!(
            store.find_id(profile.id).unwrap().alias.to_string(),
            "quiet-name"
        );
        assert_eq!(store.find(&profile.alias).unwrap().id, replacement.id);
        assert_eq!(store.find(&other.alias).unwrap().id, other.id);
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn unregister_requires_selection_and_rechecks_busy_and_peer_changed_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Codex, "work".parse().unwrap())
            .unwrap();
        let home = store.profile_home(profile.id).unwrap();
        std::fs::write(home.join("fixture-owned.txt"), "retained").unwrap();
        let mut action = ProfileAction::new(profile.clone(), Kind::Remove);
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        assert!(store.find_id(profile.id).is_ok());
        key(&mut action, &mut store, KeyCode::Char(' '));
        let lease = store.lease(profile.id).unwrap();
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        assert!(matches!(action.error, Some(Error::Busy)));
        drop(lease);
        let mut peer = Store::open(store.root()).unwrap();
        peer.rename(&profile.alias, "elsewhere".parse().unwrap())
            .unwrap();
        let replacement = peer
            .register(Harness::Claude, profile.alias.clone())
            .unwrap();
        key(&mut action, &mut store, KeyCode::Enter);
        assert!(!action.accepted);
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        key(&mut action, &mut store, KeyCode::Char(' '));
        action.reset_acceptance();
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        key(&mut action, &mut store, KeyCode::Char(' '));
        assert!(
            matches!(key(&mut action, &mut store, KeyCode::Enter), Outcome::Changed { id, kind: Kind::Remove } if id == profile.id)
        );
        assert!(matches!(store.find_id(profile.id), Err(Error::NotFound)));
        assert_eq!(store.find(&profile.alias).unwrap().id, replacement.id);
        assert_eq!(
            std::fs::read_to_string(home.join("fixture-owned.txt")).unwrap(),
            "retained"
        );
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn retired_identity_cannot_follow_its_alias_to_a_new_profile() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let mut action = ProfileAction::new(profile.clone(), Kind::Rename);
        store.remove_profile(profile.id).unwrap();
        let replacement = store
            .register(Harness::Codex, profile.alias.clone())
            .unwrap();
        text(&mut action, &mut store, "quiet-name");
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Enter),
            Outcome::Continue
        ));
        assert!(matches!(action.error, Some(Error::NotFound)));
        assert_eq!(store.find(&profile.alias).unwrap().id, replacement.id);
        assert!(matches!(
            key(&mut action, &mut store, KeyCode::Esc),
            Outcome::Cancel
        ));
    }

    #[test]
    fn profile_dialogs_hide_labels_input_and_errors_at_every_supported_size() {
        use super::super::{Dashboard, preview, tests::screenshot};
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Claude, "private-canary".parse().unwrap())
            .unwrap();
        let mut app = Dashboard::new(true);
        app.refresh(&store).unwrap();
        for (kind, name) in [(Kind::Rename, "rename"), (Kind::Remove, "unregister")] {
            let mut action = ProfileAction::new(profile.clone(), kind);
            action.draft = "draft-canary\u{202e}".to_owned();
            action.error = Some(Error::SupervisionIncomplete {
                run_id: "error-canary".to_owned(),
                source: Box::new(Error::Busy),
            });
            app.profile_action = Some(action);
            for (width, height) in [(20, 6), (40, 14), (44, 17), (80, 24), (100, 32), (160, 48)] {
                let screen = screenshot(&app, width, height);
                for canary in ["private-canary", "draft-canary", "error-canary", "\u{202e}"] {
                    assert!(!screen.contains(canary));
                }
                if width >= 40 {
                    assert!(screen.contains("Ctrl-P privacy"));
                    preview::export(&app, &format!("{name}-private-{width}"), width, height);
                }
            }
            app.masked = false;
            let action = app.profile_action.as_mut().unwrap();
            action.error = None;
            let screen = screenshot(&app, 100, 32);
            assert!(screen.contains("private-canary"));
            if kind == Kind::Rename {
                assert!(screen.contains("\\u{202e}"));
            }
            assert!(!screen.contains('\u{202e}'));
            preview::export(&app, &format!("{name}-review"), 100, 32);
            app.masked = true;
        }
    }
}
