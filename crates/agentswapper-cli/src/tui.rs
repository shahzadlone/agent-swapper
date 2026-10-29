use std::{io, time::Duration};

use agentswapper_core::{
    Error, ExecutionEngine, Profile, ProfileId, Result, Store, launch::LaunchPlan,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table, TableState, Wrap},
};

mod launch;
#[cfg(test)]
mod preview;
mod setup;
mod terminal;

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
    setup: Option<setup::Setup>,
    launch: Option<launch::Review>,
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

    fn review_launch(&mut self, store: &Store, operation: launch::Operation) {
        let Some(profile) = self.visible().get(self.selected).cloned().cloned() else {
            return;
        };
        let review = std::env::current_dir()
            .map_err(Error::from)
            .and_then(|cwd| launch::Review::prepare(store, profile, &cwd, None, operation));
        self.message = None;
        match review {
            Ok(review) => self.launch = Some(review),
            Err(error) => self.message = Some(self.error_message(&error)),
        }
    }
}

// Declared before the terminal so it restores raw mode even if terminal setup fails.
struct Restore {
    active: bool,
}
impl Restore {
    fn restore(&mut self) -> io::Result<()> {
        if self.active {
            let raw = crossterm::terminal::disable_raw_mode();
            let screen = crossterm::execute!(
                io::stdout(),
                crossterm::terminal::LeaveAlternateScreen,
                crossterm::cursor::Show
            );
            raw?;
            screen?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

enum TerminalOutcome {
    Quit,
    Launch(Box<LaunchPlan>),
}

pub(crate) fn run(store: &mut Store, masked: bool) -> Result<()> {
    let mut app = Dashboard::new(masked);
    app.refresh(store)?;
    loop {
        // Dashboard handlers are removed before a native agent owns the terminal.
        // A foreground Ctrl-C must reach that agent, then allow the dashboard to return.
        #[cfg(unix)]
        let signals = crate::terminal_signals::TerminalSignals::install()?;
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
        let TerminalOutcome::Launch(plan) = result? else {
            return Ok(());
        };
        let engine = plan.profile().harness.engine();
        crate::install_launch_interrupt_handler()?;
        // A launch error can include an uncertain wait or failed terminal
        // restoration. Return to the shell instead of entering raw mode over
        // an agent that may still own this terminal.
        let code = match engine {
            ExecutionEngine::Native => plan.execute(store, true),
            ExecutionEngine::Gents => plan.execute_gents(store, true),
        }?;
        app.message = Some(match engine {
            ExecutionEngine::Gents => format!(
                "Gents client returned with exit {code}. External runtime work may still be running."
            ),
            ExecutionEngine::Native => format!(
                "Agent returned with exit {code}. Background jobs may still be running. Enter reviews another launch; context is not transferred."
            ),
        });
        // A failed refresh must not leave a stale list available for more launches.
        app.refresh(store)?;
    }
}

fn run_terminal(
    store: &mut Store,
    app: &mut Dashboard,
    interrupted: impl Fn() -> bool,
) -> Result<TerminalOutcome> {
    let mut restore = Restore { active: true };
    crate::terminal_input::enable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = terminal::DashboardTerminal::new()?;
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
            if let Some(review) = &mut app.launch {
                review.reset_acceptance();
            }
            continue;
        }
        if let Some(review) = &mut app.launch {
            let size = terminal.size()?;
            let cancel = key.code == KeyCode::Esc
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('g'));
            if (size.width < 40 || size.height < 14) && !cancel {
                continue;
            }
            let area = ratatui::layout::Rect::new(0, 3, size.width, size.height.saturating_sub(6));
            match review.key(key, area, app.masked) {
                launch::Outcome::Continue => {}
                launch::Outcome::Cancel => {
                    app.launch = None;
                    app.message = Some("Launch cancelled. No agent was started.".to_owned());
                }
                launch::Outcome::Launch => {
                    if let Some(review) = app.launch.take() {
                        // Fail rather than hand a raw or alternate-screen terminal to an agent.
                        restore.restore()?;
                        return Ok(TerminalOutcome::Launch(Box::new(review.into_plan())));
                    }
                }
            }
            continue;
        }
        if let Some(setup) = &mut app.setup {
            let size = terminal.size()?;
            let cancel = key.code == KeyCode::Esc
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('g'));
            if (size.width < 40 || size.height < 14) && !cancel {
                continue;
            }
            let area = ratatui::layout::Rect::new(0, 3, size.width, size.height.saturating_sub(6));
            match setup.key(key, store, area, app.masked) {
                setup::Outcome::Continue => {}
                setup::Outcome::Cancel => {
                    app.setup = None;
                    app.message = Some("Setup closed.".to_owned());
                }
                setup::Outcome::Created(profile) => {
                    app.setup = None;
                    app.query.clear();
                    app.message = Some(match app.refresh(store) {
                        Ok(()) => {
                            app.preserve_selection(Some(profile.id));
                            if profile.harness == agentswapper_core::Harness::Gents {
                                "Profile registered. Start its dedicated gents runtime, then Enter reviews a launch. Login and permissions belong to that runtime.".to_owned()
                            } else {
                                "Profile registered. Press l to review native login.".to_owned()
                            }
                        }
                        Err(error) => format!(
                            "Profile registered; refresh failed ({}). Press r to retry.",
                            error.code()
                        ),
                    });
                }
            }
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
            KeyCode::Char('a') => {
                app.setup = Some(setup::Setup::default());
                app.message = None;
            }
            KeyCode::Char('e') => app.toggle_enabled(store),
            KeyCode::Char('r') => {
                app.message = Some(match app.refresh(store) {
                    Ok(()) => "Profiles refreshed.".to_owned(),
                    Err(error) => app.error_message(&error),
                });
            }
            KeyCode::Enter => app.review_launch(store, launch::Operation::Run),
            KeyCode::Char('l') => app.review_launch(store, launch::Operation::Login),
            KeyCode::Char('c') => app.review_launch(store, launch::Operation::Resume),
            _ => {}
        }
    }
    restore.restore()?;
    Ok(TerminalOutcome::Quit)
}

// Use the renderer's grapheme widths for both wrapping and scroll bounds.
fn wrapped_rows(content: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width.max(1));
    let mut rows = Vec::new();
    for line in content {
        let mut row = Line::default();
        let mut used = 0;
        let mut last_space = None;
        for grapheme in line.styled_graphemes(Style::default()) {
            let span = Span::styled(grapheme.symbol.to_owned(), grapheme.style);
            let size = span.width();
            let whitespace = grapheme.symbol.chars().all(char::is_whitespace);
            if used + size > width && used > 0 {
                let carry = if !whitespace && let Some(index) = last_space {
                    let carry = row.spans.split_off(index + 1);
                    row.spans.truncate(index);
                    carry
                } else {
                    Vec::new()
                };
                while row
                    .spans
                    .last()
                    .is_some_and(|span| span.content.chars().all(char::is_whitespace))
                {
                    row.spans.pop();
                }
                rows.push(row);
                row = Line::from(carry);
                used = row.width();
                last_space = None;
                if whitespace && row.spans.is_empty() {
                    continue;
                }
            }
            used += size;
            row.spans.push(span);
            if whitespace {
                last_space = Some(row.spans.len() - 1);
            }
        }
        rows.push(row);
    }
    rows
}

fn draw(frame: &mut Frame<'_>, app: &Dashboard) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(BG).fg(INK)),
        area,
    );
    if area.width < 40 || area.height < 14 {
        frame.render_widget(
            Paragraph::new(if app.launch.is_some() {
                "aswp\nEnlarge to 40 x 14.\nEsc cancels launch.\nCtrl-C quits."
            } else if app.setup.is_some() {
                "aswp\nEnlarge to 40 x 14.\nCtrl-G cancels setup.\nCtrl-C quits."
            } else if app.searching {
                "aswp\nEnlarge to 40 x 14.\nEsc clears search.\nCtrl-C quits."
            } else {
                "aswp\nEnlarge to 40 x 14, or use:\naswp list\nq quit"
            })
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
    if let Some(setup) = &app.setup {
        setup.draw(frame, parts[1].union(parts[2]), app.masked);
        frame.render_widget(
            Paragraph::new(setup.footer()).style(Style::default().fg(TEAL)),
            parts[3],
        );
        return;
    }
    if let Some(review) = &app.launch {
        review.draw(frame, parts[1].union(parts[2]), app.masked);
        frame.render_widget(
            Paragraph::new(review.footer()).style(Style::default().fg(TEAL)),
            parts[3],
        );
        return;
    }
    let body = Layout::horizontal(if wide {
        vec![Constraint::Percentage(55), Constraint::Percentage(45)]
    } else {
        vec![Constraint::Percentage(100)]
    })
    .split(parts[1]);
    let profiles = app.visible();
    if profiles.is_empty() {
        let text = if app.profiles.is_empty() {
            "No profiles yet.\nPress a to add your first profile.\nEach profile gets a private home; login comes next."
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
                "{}\n{} / {}\nAvailability: {}\n\nEngine: {engine}\n{ownership}\n\nAccount: unverified\nQuota: unknown / not measured\nAutomatic switching: not enabled\n\nEnter reviews a new launch.\nl reviews login. c resumes gents.",
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
        "Navigation: arrows or j/k. / search. a adds a profile.\nEnter reviews a new launch; l reviews native login.\nc reviews the latest gents session. Native resume is unavailable.\ne enables/disables future launches. Ctrl-P toggles privacy.\nr refresh. Esc dismisses. q or Ctrl-C quits.\nQuota unknown means unmeasured.".to_owned()
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
            "Enter reviews a new launch. l reviews native login. c resumes gents.\nAccount identity and capacity require provider verification.".to_owned()
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
        Paragraph::new(if app.help {
            " Esc close help  Ctrl-P privacy\n q / Ctrl-C quit"
        } else if app.searching {
            " Enter apply  Backspace edit  Esc clear\n Ctrl-P privacy  Ctrl-C quit"
        } else {
            " Enter review  l login  c gents resume\n a add  e enable/disable  / search\n j/k move  m mask  r refresh  ? help  q quit"
        })
            .style(Style::default().fg(TEAL)),
        parts[3],
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use agentswapper_core::Harness;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn wrapped_rows_keep_words_styles_and_graphemes_intact() {
        let content = "Context is not transferred. Review before starting another agent.";
        let rows = wrapped_rows(vec![Line::from(content)], 24);
        assert!(rows.iter().all(|line| line.width() <= 24));
        assert_eq!(
            rows.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            content
        );
        let identifier = "a".repeat(150);
        let rows = wrapped_rows(vec![Line::from(identifier.clone())], 24);
        assert!(rows.iter().all(|line| line.width() <= 24));
        assert_eq!(
            rows.iter().map(ToString::to_string).collect::<String>(),
            identifier
        );
        let rows = wrapped_rows(
            vec![Line::from(Span::styled(
                "界界 e\u{301} long-unbroken-field",
                Style::default().fg(TEAL),
            ))],
            8,
        );
        assert!(rows.iter().all(|line| line.width() <= 8));
        assert!(
            rows.iter()
                .map(ToString::to_string)
                .collect::<String>()
                .contains("e\u{301}")
        );
        assert!(
            rows.iter()
                .flat_map(|line| &line.spans)
                .all(|span| span.style.fg == Some(TEAL))
        );
    }

    pub(super) fn screenshot(app: &Dashboard, width: u16, height: u16) -> String {
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

    fn setup_key(app: &mut Dashboard, store: &mut Store, code: KeyCode) -> setup::Outcome {
        app.setup.as_mut().unwrap().key(
            crossterm::event::KeyEvent::new(code, KeyModifiers::NONE),
            store,
            ratatui::layout::Rect::new(0, 3, 100, 26),
            app.masked,
        )
    }

    fn setup_text(app: &mut Dashboard, store: &mut Store, text: &str) {
        for c in text.chars() {
            setup_key(app, store, KeyCode::Char(c));
        }
    }

    #[test]
    fn setup_registers_each_native_agent_only_after_review_and_keeps_cancellation_clean() {
        for (index, harness) in Harness::NATIVE.into_iter().enumerate() {
            let temp = tempfile::tempdir().unwrap();
            let mut store = Store::open(&temp.path().join("state")).unwrap();
            let mut app = Dashboard::new(false);
            app.setup = Some(setup::Setup::default());
            if index == 0 {
                preview::export(&app, "setup-agents", 100, 32);
            }
            for _ in 0..index {
                setup_key(&mut app, &mut store, KeyCode::Down);
            }
            setup_key(&mut app, &mut store, KeyCode::Enter);
            setup_text(&mut app, &mut store, "quiet-work");
            if index == 0 {
                preview::export(&app, "setup-label", 80, 24);
            }
            setup_key(&mut app, &mut store, KeyCode::Enter);
            assert!(screenshot(&app, 80, 24).contains("Review profile"));
            assert!(store.profiles().unwrap().is_empty());
            assert!(store.runs(1).unwrap().is_empty());
            // Back preserves the label, and returning to review still does not
            // mutate the registry or touch provider configuration.
            setup_key(&mut app, &mut store, KeyCode::Esc);
            assert!(screenshot(&app, 80, 24).contains("quiet-work"));
            setup_key(&mut app, &mut store, KeyCode::Enter);
            if index == 0 {
                preview::export(&app, "setup-native-review", 100, 32);
                insta::assert_snapshot!("setup_native_review", screenshot(&app, 80, 24));
            }
            let setup::Outcome::Created(profile) = setup_key(&mut app, &mut store, KeyCode::Enter)
            else {
                panic!("review did not register the profile");
            };
            assert_eq!(profile.harness, harness);
            assert_eq!(store.find(&profile.alias).unwrap().id, profile.id);
            assert_eq!(
                std::fs::read_dir(store.profile_home(profile.id).unwrap())
                    .unwrap()
                    .count(),
                0
            );
            assert!(store.runs(1).unwrap().is_empty());
            // A duplicate remains editable; cancellation never removes the
            // already registered profile or replaces its native home.
            app.setup = Some(setup::Setup::default());
            setup_key(&mut app, &mut store, KeyCode::Enter);
            setup_text(&mut app, &mut store, "quiet-work");
            setup_key(&mut app, &mut store, KeyCode::Enter);
            assert!(matches!(
                setup_key(&mut app, &mut store, KeyCode::Enter),
                setup::Outcome::Continue
            ));
            assert!(screenshot(&app, 100, 32).contains("alias already registered"));
            let cancelled = app.setup.as_mut().unwrap().key(
                crossterm::event::KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
                &mut store,
                ratatui::layout::Rect::new(0, 3, 100, 26),
                false,
            );
            assert!(matches!(cancelled, setup::Outcome::Cancel));
            assert_eq!(store.profiles().unwrap().len(), 1);
        }
    }

    #[test]
    fn gents_setup_refuses_external_routes_and_masks_every_review_field() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let mut app = Dashboard::new(false);
        app.setup = Some(setup::Setup::default());
        for _ in 0..3 {
            setup_key(&mut app, &mut store, KeyCode::Down);
        }
        setup_key(&mut app, &mut store, KeyCode::Enter);
        setup_key(&mut app, &mut store, KeyCode::Enter);
        assert!(screenshot(&app, 80, 24).contains("alias must start"));
        assert!(store.profiles().unwrap().is_empty());
        setup_text(&mut app, &mut store, "private-canary");
        setup_key(&mut app, &mut store, KeyCode::Enter);
        setup_text(&mut app, &mut store, "agent-canary");
        setup_key(&mut app, &mut store, KeyCode::Enter);
        setup_text(&mut app, &mut store, "0.0.0.0:9191");
        setup_key(&mut app, &mut store, KeyCode::Enter);
        let error = screenshot(&app, 100, 32);
        assert!(error.contains("Local runtime address"));
        assert!(store.profiles().unwrap().is_empty());
        preview::export(&app, "setup-invalid-route", 100, 32);
        for _ in 0.."0.0.0.0:9191".len() {
            setup_key(&mut app, &mut store, KeyCode::Backspace);
        }
        setup_text(&mut app, &mut store, "[::1]:9191");
        setup_key(&mut app, &mut store, KeyCode::Enter);
        assert!(screenshot(&app, 100, 32).contains("Review profile"));
        app.masked = true;
        for (width, height) in [(100, 32), (80, 24), (44, 17), (40, 14)] {
            let screen = screenshot(&app, width, height);
            for canary in ["private-canary", "agent-canary", "[::1]", "9191"] {
                assert!(!screen.contains(canary));
            }
            assert!(screen.contains("Ctrl-P privacy"));
            preview::export(&app, &format!("setup-private-{width}"), width, height);
        }
        insta::assert_snapshot!("setup_private_review", screenshot(&app, 44, 17));
        let small = ratatui::layout::Rect::new(0, 3, 40, 8);
        for _ in 0..10 {
            app.setup.as_mut().unwrap().key(
                crossterm::event::KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
                &mut store,
                small,
                true,
            );
        }
        assert!(screenshot(&app, 40, 14).contains("no agent will start"));
        // Resizing back up clamps the rendered scroll; a following PageUp must
        // work from that visible offset rather than an old oversized value.
        setup_key(&mut app, &mut store, KeyCode::PageUp);
        assert!(screenshot(&app, 100, 32).contains("Agent ID:"));
        let setup::Outcome::Created(profile) = setup_key(&mut app, &mut store, KeyCode::Enter)
        else {
            panic!("gents profile not registered");
        };
        let binding = store.find(&profile.alias).unwrap().gents.unwrap();
        assert_eq!(binding.address().to_string(), "[::1]:9191");
        assert_eq!(binding.agent().to_string(), "agent-canary");
        assert!(store.runs(1).unwrap().is_empty());
    }

    #[test]
    fn empty_dashboard_has_an_action_and_no_capacity_claim() {
        let screen = screenshot(&Dashboard::default(), 90, 20);
        preview::export(&Dashboard::default(), "empty", 90, 20);
        assert!(screen.contains("Press a to add your first profile"));
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
