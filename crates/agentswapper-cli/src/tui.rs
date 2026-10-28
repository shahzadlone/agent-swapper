use std::{io, time::Duration};

use agentswapper_core::{Error, Profile, Result, Store, launch::LaunchPlan};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

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
        self.profiles = store.profiles()?;
        let runs = store.unfinished()?;
        self.pending = runs.len();
        self.blocked_aliases = runs.into_iter().map(|r| r.alias.to_string()).collect();
        self.selected = self.selected.min(self.visible().len().saturating_sub(1));
        Ok(())
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

pub(crate) fn run(store: &Store, masked: bool) -> Result<()> {
    let mut app = Dashboard::new(masked);
    app.refresh(store)?;
    let _restore = Restore;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        terminal.draw(|frame| draw(frame, &app))?;
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
        if app.searching {
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
            app.selected = 0;
            continue;
        }
        match key.code {
            KeyCode::Char('q') => break,
            KeyCode::Esc => {
                app.help = false;
                app.message = None;
                app.query.clear();
                app.selected = 0;
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
            KeyCode::Char('r') => {
                app.refresh(store)?;
                app.message = Some("Profiles refreshed.".to_owned());
            }
            KeyCode::Enter => {
                if let Some(profile) = app.visible().get(app.selected) {
                    let result = LaunchPlan::build(
                        store,
                        (*profile).clone(),
                        None,
                        &std::env::current_dir()?,
                        vec![],
                        false,
                    )
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
                        Err(error) => format!("Preflight: {error}"),
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
    if area.width < 34 || area.height < 10 {
        frame.render_widget(
            Paragraph::new("aswp\nEnlarge to 34 x 10, or use:\naswp list\nq quit")
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(5),
        Constraint::Length(2),
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
            ]),
            Line::from(if area.width < 70 {
                " Local profiles / developer preview"
            } else {
                " Switch agents. Keep your place.  [developer preview]"
            }),
        ]),
        parts[0],
    );
    let profiles = app.visible();
    if profiles.is_empty() {
        let text = if app.profiles.is_empty() {
            "No profiles yet.\nStart here: aswp profile add claude --alias work\nRegistration does not log in or change your global account."
        } else {
            "No profiles match this search. Press Esc to clear it."
        };
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::default().borders(Borders::TOP).title(" Profiles "))
                .wrap(Wrap { trim: true }),
            parts[1],
        );
    } else {
        let narrow = area.width < 70;
        let rows = profiles.iter().enumerate().map(|(i, p)| {
            let name = if app.masked {
                format!("profile-{}", i + 1)
            } else {
                p.alias.to_string()
            };
            let status = if app.blocked_aliases.contains(&p.alias.to_string()) {
                "blocked"
            } else if p.enabled {
                "enabled"
            } else {
                "disabled"
            };
            let mut cells = vec![
                Cell::from(name),
                Cell::from(p.harness.to_string()),
                Cell::from("unknown").style(Style::default().fg(YELLOW)),
            ];
            if !narrow {
                cells.push(Cell::from(status));
                cells.push(Cell::from("unverified"));
            }
            Row::new(cells)
        });
        let widths = if narrow {
            vec![
                Constraint::Min(10),
                Constraint::Length(8),
                Constraint::Length(9),
            ]
        } else {
            vec![
                Constraint::Min(16),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(12),
            ]
        };
        let header = if narrow {
            vec!["Profile", "Harness", "Quota"]
        } else {
            vec!["Profile", "Harness", "Quota", "Status", "Account"]
        };
        let table = Table::new(rows, widths)
            .header(Row::new(header).style(Style::default().fg(TEAL)))
            .column_spacing(1)
            .block(Block::default().borders(Borders::TOP).title(" Profiles "))
            .row_highlight_style(
                Style::default()
                    .bg(Color::Rgb(35, 35, 35))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = TableState::default().with_selected(Some(app.selected));
        frame.render_stateful_widget(table, parts[1], &mut state);
    }
    let details = if app.help {
        "Navigation: arrows or j/k. / search. m masks labels.\nCtrl-P toggles privacy, including during search.\nEnter checks preflight; it never starts an agent.\nr refresh. Esc dismisses. q or Ctrl-C quits.\nQuota unknown means unmeasured, not available capacity.".to_owned()
    } else if app.searching {
        let query = if app.masked && !app.query.is_empty() {
            "[hidden]".to_owned()
        } else {
            agentswapper_core::terminal_text(&app.query)
        };
        format!("Search: /{query}\nEnter applies. Esc clears. Ctrl-P toggles privacy.")
    } else if let Some(message) = &app.message {
        message.clone()
    } else {
        let selected = profiles
            .get(app.selected)
            .map(|p| {
                format!(
                    "Selected: {} | {}",
                    p.harness,
                    if app.blocked_aliases.contains(&p.alias.to_string()) {
                        "blocked"
                    } else if p.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                )
            })
            .unwrap_or_default();
        if profiles
            .get(app.selected)
            .is_some_and(|p| p.harness == agentswapper_core::Harness::Gents)
        {
            "Engine: gents / attached client\nWorkspace + permissions: gents\nRuntime may outlive chat\nQuota: unknown / no auto switch".to_owned()
        } else if area.width < 70 {
            format!(
                "{selected}\nAccount: unverified\nQuota: unknown / no auto switch\nUnfinished runs: {}",
                app.pending
            )
        } else {
            format!(
                "{selected}\nAccount and isolation: unverified. Quota: unknown.\n{} unfinished runs. Automatic switching is not enabled.",
                app.pending
            )
        }
    };
    frame.render_widget(
        Paragraph::new(details)
            .block(Block::default().borders(Borders::TOP))
            .wrap(Wrap { trim: true }),
        parts[2],
    );
    frame.render_widget(
        Paragraph::new(" j/k move  / search  Enter preflight\n m mask  r refresh  ? help  q quit")
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
}
