use std::{io, time::Duration};

use agentswapper_core::{Error, Profile, ProfileId, Result, Store, launch::LaunchPlan};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table, TableState, Wrap},
};

#[cfg(test)]
mod preview;
#[cfg(unix)]
mod quit_signals;

const TEAL: Color = Color::Rgb(44, 204, 195);
const YELLOW: Color = Color::Rgb(250, 205, 61);
const INK: Color = Color::Rgb(242, 242, 242);
const BG: Color = Color::Rgb(10, 10, 10);

#[derive(Default)]
struct Dashboard {
    profiles: Vec<Profile>,
    selected: usize,
    query: String,
    searching: bool,
    masked: bool,
    help: bool,
    message: Option<String>,
    pending: usize,
    blocked_aliases: Vec<String>,
    privacy_ids: Vec<ProfileId>,
}

impl Dashboard {
    fn new(masked: bool) -> Self {
        Self {
            masked,
            ..Self::default()
        }
    }

    fn visible(&self) -> Vec<&Profile> {
        let query = self.query.to_lowercase();
        self.profiles
            .iter()
            .filter(|p| {
                p.alias.to_string().contains(&query) || p.harness.to_string().contains(&query)
            })
            .collect()
    }

    fn refresh(&mut self, store: &Store) -> Result<()> {
        let selected = self.visible().get(self.selected).map(|p| p.id);
        let profiles = store.profiles()?;
        let runs = store.unfinished()?;
        self.profiles = profiles;
        self.pending = runs.len();
        self.blocked_aliases = runs.into_iter().map(|r| r.alias.to_string()).collect();
        for profile in &self.profiles {
            if !self.privacy_ids.contains(&profile.id) {
                self.privacy_ids.push(profile.id);
            }
        }
        self.preserve_selection(selected);
        Ok(())
    }

    fn preserve_selection(&mut self, previous: Option<ProfileId>) {
        self.selected = self
            .visible()
            .iter()
            .position(|p| Some(p.id) == previous)
            .unwrap_or(0);
    }

    fn label(&self, profile: &Profile) -> String {
        if self.masked {
            match self.privacy_ids.iter().position(|id| *id == profile.id) {
                Some(index) => format!("profile-{}", index + 1),
                None => "profile".to_owned(),
            }
        } else {
            profile.alias.to_string()
        }
    }

    fn status(&self, profile: &Profile) -> &'static str {
        if self.blocked_aliases.contains(&profile.alias.to_string()) {
            "unresolved"
        } else if profile.enabled {
            "enabled"
        } else {
            "disabled"
        }
    }

    fn error_message(&self, error: &Error) -> String {
        if self.masked {
            format!(
                "Action failed ({}). Unmask and retry to inspect details.",
                error.code()
            )
        } else {
            agentswapper_core::terminal_text(&format!("Action failed: {error}"))
        }
    }

    fn toggle_enabled(&mut self, store: &mut Store) {
        let Some(profile) = self.visible().get(self.selected).cloned().cloned() else {
            return;
        };
        match store.set_enabled(profile.id, !profile.enabled) {
            Ok(_) => {
                let state = if profile.enabled {
                    "disabled"
                } else {
                    "enabled"
                };
                self.message = Some(match self.refresh(store) {
                    Ok(()) => {
                        format!("Profile {state} for future launches. Existing work is unchanged.")
                    }
                    Err(error) => format!(
                        "Profile {state}; refresh failed ({}). Press r to retry.",
                        error.code()
                    ),
                });
            }
            Err(error) => self.message = Some(self.error_message(&error)),
        }
    }
}

// Declared before the terminal so it restores raw mode even if terminal setup fails.
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}

pub(crate) fn run(store: &mut Store, masked: bool) -> Result<()> {
    let mut app = Dashboard::new(masked);
    app.refresh(store)?;
    #[cfg(unix)]
    let signals = quit_signals::QuitSignals::install()?;
    let interrupted = || {
        #[cfg(unix)]
        {
            signals.requested()
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let result = run_terminal(store, &mut app, interrupted);
    // run_terminal restores on errors as well as normal exits before re-raising.
    #[cfg(unix)]
    signals.finish()?;
    result
}

fn run_terminal(
    store: &mut Store,
    app: &mut Dashboard,
    interrupted: impl Fn() -> bool,
) -> Result<()> {
    let _restore = Restore;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        if interrupted() {
            break;
        }
        terminal.draw(|frame| draw(frame, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
            app.masked = !app.masked;
            app.message = None;
            continue;
        }
        if app.help {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Esc | KeyCode::Char('?') => app.help = false,
                _ => {}
            }
            continue;
        }
        if app.searching {
            let selected = app.visible().get(app.selected).map(|p| p.id);
            match key.code {
                KeyCode::Esc => {
                    app.searching = false;
                    app.query.clear();
                }
                KeyCode::Enter => app.searching = false,
                KeyCode::Backspace => {
                    app.query.pop();
                }
                KeyCode::Char(c) if !c.is_control() && app.query.len() + c.len_utf8() <= 128 => {
                    app.query.push(c);
                }
                _ => {}
            }
            app.preserve_selection(selected);
            continue;
        }
        match key.code {
            KeyCode::Char('q') => break,
            KeyCode::Esc => {
                let selected = app.visible().get(app.selected).map(|p| p.id);
                app.help = false;
                app.message = None;
                app.query.clear();
                app.preserve_selection(selected);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.selected = (app.selected + 1).min(app.visible().len().saturating_sub(1))
            }
            KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
            KeyCode::Char('/') => {
                app.searching = true;
                app.message = None;
            }
            KeyCode::Char('m') => {
                app.masked = !app.masked;
                app.message = None;
            }
            KeyCode::Char('?') => app.help = !app.help,
            KeyCode::Char('e') => app.toggle_enabled(store),
            KeyCode::Char('r') => {
                app.message = Some(match app.refresh(store) {
                    Ok(()) => "Profiles refreshed.".to_owned(),
                    Err(error) => app.error_message(&error),
                });
            }
            KeyCode::Enter => {
                if let Some(profile) = app.visible().get(app.selected) {
                    let result = std::env::current_dir()
                        .map_err(Error::from)
                        .and_then(|cwd| {
                            LaunchPlan::build(store, (*profile).clone(), None, &cwd, vec![], false)
                        })
                        .and_then(|plan| {
                            if !plan.check_gents_runtime()? {
                                return Err(Error::GentsRuntimeMismatch);
                            }
                            Ok(plan)
                        });
                    app.message = Some(match result {
                        Ok(_) if profile.harness == agentswapper_core::Harness::Gents =>
                            "Gents client preflight: local address matches; listener unverified. External runtime owns workspace and permissions. Inspect with aswp run PROFILE --dry-run.".to_owned(),
                        Ok(_) if app.masked => format!(
                            "Preflight: {} found. Isolation unverified. Unmask aliases to see the launch command.",
                            profile.harness
                        ),
                        Ok(_) => format!(
                            "Preflight: {} ({}) found. Isolation unverified. Leave the dashboard and inspect: aswp run {} --dry-run",
                            profile.alias, profile.harness, profile.alias
                        ),
                        Err(error) => app.error_message(&error),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn draw(frame: &mut Frame<'_>, app: &Dashboard) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(BG).fg(INK)),
        area,
    );
    if area.width < 40 || area.height < 14 {
        frame.render_widget(
            Paragraph::new("aswp\nEnlarge to 40 x 14, or use:\naswp list\nq quit")
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let wide = area.width >= 100;
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(if app.help { 8 } else { 5 }),
        Constraint::Length(3),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " aswp ",
                    Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" / AgentSwapper"),
                Span::styled("  developer preview", Style::default().fg(Color::Gray)),
            ]),
            Line::from(format!(
                " {} {} / {} unresolved / privacy {}",
                app.profiles.len(),
                if app.profiles.len() == 1 {
                    "profile"
                } else {
                    "profiles"
                },
                app.pending,
                if app.masked { "on" } else { "off" }
            )),
        ]),
        parts[0],
    );
    let body = Layout::horizontal(if wide {
        vec![Constraint::Percentage(55), Constraint::Percentage(45)]
    } else {
        vec![Constraint::Percentage(100)]
    })
    .split(parts[1]);
    let profiles = app.visible();
    if profiles.is_empty() {
        let text = if app.profiles.is_empty() {
            "No profiles yet.\nStart here: aswp profile add claude --alias work\nRegistration does not log in or change your global account."
        } else {
            "No profiles match this search. Press Esc to clear it."
        };
        frame.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .borders(Borders::TOP)
                        .title(" Profiles ")
                        .padding(Padding::horizontal(1)),
                )
                .wrap(Wrap { trim: true }),
            body[0],
        );
    } else {
        let rows = profiles.iter().map(|p| {
            let status = app.status(p);
            Row::new(vec![
                Cell::from(app.label(p)),
                Cell::from(p.harness.to_string()).style(Style::default().fg(TEAL)),
                Cell::from(status).style(Style::default().fg(match status {
                    "unresolved" => YELLOW,
                    "disabled" => Color::Gray,
                    _ => INK,
                })),
            ])
            .bottom_margin(if area.height >= 24 { 1 } else { 0 })
        });
        let table = Table::new(
            rows,
            [
                Constraint::Min(12),
                Constraint::Length(8),
                Constraint::Length(10),
            ],
        )
        .header(Row::new(["Profile", "Agent", "State"]).style(Style::default().fg(Color::Gray)))
        .column_spacing(1)
        .block(Block::default().borders(Borders::TOP).title(" Profiles "))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(18, 49, 47))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
        let mut state = TableState::default().with_selected(Some(app.selected));
        frame.render_stateful_widget(table, body[0], &mut state);
    }
    if wide {
        let details = profiles.get(app.selected).map(|p| {
            let (engine, ownership) = if p.harness == agentswapper_core::Harness::Gents {
                ("gents / attached client", "Workspace + permissions: gents\nRuntime may outlive chat")
            } else {
                ("native CLI", "Workspace + permissions: native agent\nProfile isolation: unverified")
            };
            format!(
                "{}\n{} / {}\nAvailability: {}\n\nEngine: {engine}\n{ownership}\n\nAccount: unverified\nQuota: unknown / not measured\nAutomatic switching: not enabled\n\nEnter checks launch readiness.",
                app.label(p), p.harness, app.status(p), if p.enabled { "enabled" } else { "disabled" }
            )
        }).unwrap_or_else(|| "Your selected profile's details appear here.\n\nQuota: unknown until measured.".to_owned());
        frame.render_widget(
            Paragraph::new(details)
                .block(
                    Block::default()
                        .borders(Borders::LEFT | Borders::TOP)
                        .title(" Selected profile ")
                        .padding(Padding::horizontal(1)),
                )
                .wrap(Wrap { trim: true }),
            body[1],
        );
    }
    let details = if app.help {
        "Navigation: arrows or j/k. / search.\nEnter checks preflight; it never starts an agent.\ne enables/disables future launches.\nCtrl-P toggles privacy, even during search.\nr refresh. Esc dismisses. q or Ctrl-C quits.\nQuota unknown means unmeasured.".to_owned()
    } else if app.searching {
        let query = if app.masked && !app.query.is_empty() {
            "[hidden]".to_owned()
        } else {
            agentswapper_core::terminal_text(&app.query)
        };
        format!("Search: /{query}\nEnter applies. Esc clears. Ctrl-P toggles privacy.")
    } else if let Some(message) = &app.message {
        message.clone()
    } else if let Some(profile) = profiles.get(app.selected) {
        if app.status(profile) == "unresolved" {
            format!(
                "This profile has an unresolved run.\nAvailability: {} for future launches.\nInspect aswp status before launching again.",
                if profile.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            )
        } else if wide {
            "Enter checks launch readiness. e changes availability for future launches.\nAccount identity and capacity require provider verification.".to_owned()
        } else if profile.harness == agentswapper_core::Harness::Gents {
            "Engine: gents / attached client\nWorkspace + permissions: gents\nRuntime may outlive chat\nQuota: unknown / no auto switch".to_owned()
        } else {
            format!(
                "Selected: {} | {}\nAccount and isolation: unverified\nQuota: unknown / no auto switch",
                profile.harness,
                app.status(profile)
            )
        }
    } else {
        "Register a profile to get started.\nQuota: unknown until measured.".to_owned()
    };
    frame.render_widget(
        Paragraph::new(details)
            .block(Block::default().borders(Borders::TOP).title(" Next step "))
            .wrap(Wrap { trim: true }),
        parts[2],
    );
    frame.render_widget(
        Paragraph::new(" j/k move  / search  Enter preflight\n e enable/disable  m mask  r refresh\n ? help  Esc back  q quit")
            .style(Style::default().fg(TEAL)),
        parts[3],
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use agentswapper_core::Harness;
    use ratatui::backend::TestBackend;

    fn screenshot(app: &Dashboard, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn empty_dashboard_has_an_action_and_no_capacity_claim() {
        let screen = screenshot(&Dashboard::default(), 90, 20);
        preview::export(&Dashboard::default(), "empty", 90, 20);
        assert!(screen.contains("aswp profile add claude"));
        assert!(screen.contains("Quota: unknown"));
        insta::assert_snapshot!("empty_dashboard", screen);
    }

    #[test]
    fn narrow_dashboard_preserves_unknown_quota_and_masking() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        store
            .register(Harness::Codex, "confidential-client".parse().unwrap())
            .unwrap();
        let config = agentswapper_core::config::ConfigStore::new(store.root()).unwrap();
        config
            .set(agentswapper_core::config::ConfigKey::UiMask, "true")
            .unwrap();
        let mut app = Dashboard::new(config.load().unwrap().ui_mask());
        app.refresh(&store).unwrap();
        let screen = screenshot(&app, 44, 17);
        preview::export(&app, "privacy-narrow", 44, 17);
        assert!(!screen.contains("confidential"));
        assert!(screen.contains("unknown"));
        insta::assert_snapshot!("narrow_dashboard", screen);
        for (width, height) in [(0, 0), (1, 1), (20, 6), (34, 10)] {
            let _ = screenshot(&app, width, height);
        }
    }
    #[test]
    fn gents_dashboard_discloses_external_ownership_without_leaking_masked_ids() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        store
            .register_gents(
                "private-client".parse().unwrap(),
                agentswapper_core::GentsBinding::new(
                    "127.0.0.1:9191".parse().unwrap(),
                    "private_agent".parse().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut app = Dashboard {
            masked: true,
            ..Dashboard::default()
        };
        app.refresh(&store).unwrap();
        let screen = screenshot(&app, 44, 17);
        assert!(screen.contains("Engine: gents / attached client"));
        preview::export(&app, "gents", 100, 32);
        assert!(screen.contains("Runtime may outlive chat"));
        assert!(!screen.contains("private"));
    }

    #[test]
    fn privacy_hides_search_input_and_search_is_case_insensitive() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        store
            .register(Harness::Claude, "private-canary".parse().unwrap())
            .unwrap();
        let mut app = Dashboard::new(true);
        app.refresh(&store).unwrap();
        app.searching = true;
        app.query = "PRIVATE-CANARY".into();
        assert_eq!(app.visible().len(), 1);
        let screen = screenshot(&app, 90, 20);
        assert!(!screen.to_lowercase().contains("private-canary"));
        assert!(screen.contains("[hidden]"));
        app.masked = false;
        app.query = "\u{202e}canary".into();
        let screen = screenshot(&app, 90, 20);
        assert!(!screen.contains('\u{202e}'));
        assert!(screen.contains("\\u{202e}"));
    }

    #[test]
    fn refresh_and_filter_preserve_selected_identity_and_private_label() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let selected = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let mut app = Dashboard::new(true);
        app.refresh(&store).unwrap();
        let label = app.label(&selected);
        store
            .register(Harness::Codex, "alpha".parse().unwrap())
            .unwrap();
        store
            .rename(&selected.alias, "zebra".parse().unwrap())
            .unwrap();
        app.refresh(&store).unwrap();
        assert_eq!(app.visible()[app.selected].id, selected.id);
        assert_eq!(app.label(app.visible()[app.selected]), label);
        app.query = "zebra".into();
        app.preserve_selection(Some(selected.id));
        assert_eq!(app.selected, 0);
        assert_eq!(app.label(app.visible()[0]), label);
        app.query.clear();
        app.preserve_selection(Some(selected.id));
        assert_eq!(app.selected, 1);
        store.remove(&"zebra".parse().unwrap()).unwrap();
        app.refresh(&store).unwrap();
        assert_eq!(app.selected, 0);
        assert_ne!(app.visible()[0].id, selected.id);
    }

    #[test]
    fn dashboard_action_cannot_follow_a_reused_alias_to_another_profile() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let original = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let mut app = Dashboard::new(true);
        app.refresh(&store).unwrap();
        let mut peer = Store::open(store.root()).unwrap();
        peer.rename(&original.alias, "renamed".parse().unwrap())
            .unwrap();
        peer.register(Harness::Codex, original.alias.clone())
            .unwrap();
        app.toggle_enabled(&mut store);
        assert!(!store.find(&"renamed".parse().unwrap()).unwrap().enabled);
        assert!(store.find(&original.alias).unwrap().enabled);
        assert_eq!(app.visible()[app.selected].id, original.id);
        peer.remove(&"renamed".parse().unwrap()).unwrap();
        app.toggle_enabled(&mut store);
        assert!(app.message.as_ref().unwrap().contains("profile_not_found"));
        assert!(store.find(&original.alias).unwrap().enabled);
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn masked_errors_hide_identifiers_and_unmasked_errors_escape_controls() {
        let mut app = Dashboard::new(true);
        let error = Error::SupervisionIncomplete {
            run_id: "private-canary\u{1b}[31m\u{202e}".into(),
            source: Box::new(Error::Busy),
        };
        let masked = app.error_message(&error);
        assert!(masked.contains("supervision_incomplete"));
        assert!(!masked.contains("private-canary"));
        app.masked = false;
        let unmasked = app.error_message(&error);
        assert!(unmasked.contains("private-canary"));
        assert!(!unmasked.contains('\u{1b}'));
        assert!(!unmasked.contains('\u{202e}'));
    }

    #[test]
    fn populated_dashboard_exposes_states_in_wide_and_narrow_layouts() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        for (harness, alias) in [
            (Harness::Claude, "studio"),
            (Harness::Codex, "build"),
            (Harness::Kimi, "research"),
        ] {
            store.register(harness, alias.parse().unwrap()).unwrap();
        }
        store.enable(&"research".parse().unwrap(), false).unwrap();
        let mut app = Dashboard::new(false);
        app.refresh(&store).unwrap();
        app.blocked_aliases.push("studio".into());
        app.pending = 1;
        let wide = screenshot(&app, 100, 32);
        assert!(wide.contains("Selected profile"));
        assert!(wide.contains("native CLI"));
        assert!(wide.contains("unknown / not measured"));
        insta::assert_snapshot!("populated_dashboard", wide);
        preview::export(&app, "overview", 100, 32);
        for (width, height) in [(44, 17), (80, 24), (160, 48)] {
            let screen = screenshot(&app, width, height);
            assert!(screen.contains("unresolved"));
            assert!(screen.contains("disabled"));
            assert!(screen.contains("enabled"));
            preview::export(&app, &format!("overview-{width}"), width, height);
        }
        app.selected = 2;
        preview::export(&app, "unresolved", 100, 32);
        app.masked = true;
        app.searching = true;
        app.query = "studio".into();
        app.selected = 0;
        preview::export(&app, "privacy-search", 100, 32);
    }
}
