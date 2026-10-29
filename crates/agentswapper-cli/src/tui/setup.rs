use agentswapper_core::{Alias, Error, GentsBinding, Harness, Profile, Result, Store};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
};

use super::{TEAL, YELLOW};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Engine,
    Alias,
    Agent,
    Address,
    Review,
}

pub(super) struct Setup {
    step: Step,
    engine: usize,
    alias: String,
    agent: String,
    address: String,
    error: Option<Error>,
    scroll: u16,
}

pub(super) enum Outcome {
    Continue,
    Cancel,
    Created(Profile),
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            step: Step::Engine,
            engine: 0,
            alias: String::new(),
            agent: String::new(),
            address: String::new(),
            error: None,
            scroll: 0,
        }
    }
}

impl Setup {
    fn harness(&self) -> Harness {
        Harness::ALL[self.engine]
    }

    fn binding(&self) -> Result<GentsBinding> {
        GentsBinding::new(
            self.address
                .parse()
                .map_err(|_| Error::InvalidEngineBinding)?,
            self.agent.parse()?,
        )
    }

    fn advance(&mut self, store: &mut Store) -> Result<Option<Profile>> {
        self.step = match self.step {
            Step::Engine => Step::Alias,
            Step::Alias => {
                self.alias.parse::<Alias>()?;
                if self.harness() == Harness::Gents {
                    Step::Agent
                } else {
                    Step::Review
                }
            }
            Step::Agent => {
                self.agent.parse::<agentswapper_core::GentsAgentId>()?;
                Step::Address
            }
            Step::Address => {
                self.binding()?;
                Step::Review
            }
            Step::Review => {
                let alias = self.alias.parse()?;
                let profile = if self.harness() == Harness::Gents {
                    store.register_gents(alias, self.binding()?)?
                } else {
                    store.register(self.harness(), alias)?
                };
                return Ok(Some(profile));
            }
        };
        Ok(None)
    }

    pub(super) fn key(
        &mut self,
        key: KeyEvent,
        store: &mut Store,
        area: Rect,
        masked: bool,
    ) -> Outcome {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('g') {
            return Outcome::Cancel;
        }
        if key.code == KeyCode::Esc {
            self.error = None;
            self.scroll = 0;
            self.step = match self.step {
                Step::Engine => return Outcome::Cancel,
                Step::Alias => Step::Engine,
                Step::Agent => Step::Alias,
                Step::Address => Step::Agent,
                Step::Review if self.harness() == Harness::Gents => Step::Address,
                Step::Review => Step::Alias,
            };
            return Outcome::Continue;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
        {
            return Outcome::Continue;
        }
        let maximum = self.max_scroll(area, masked);
        self.scroll = self.scroll.min(maximum);
        match key.code {
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(3).min(maximum);
                return Outcome::Continue;
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(3);
                return Outcome::Continue;
            }
            _ => {}
        }
        if key.code == KeyCode::Enter {
            self.error = None;
            match self.advance(store) {
                Ok(Some(profile)) => return Outcome::Created(profile),
                Ok(None) => self.scroll = 0,
                Err(error) => self.error = Some(error),
            }
        } else if self.step == Step::Engine {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.engine = (self.engine + 1).min(Harness::ALL.len() - 1)
                }
                KeyCode::Up | KeyCode::Char('k') => self.engine = self.engine.saturating_sub(1),
                _ => {}
            }
        } else {
            let input = match self.step {
                Step::Alias => Some((&mut self.alias, 32)),
                Step::Agent => Some((&mut self.agent, 128)),
                Step::Address => Some((&mut self.address, 128)),
                _ => None,
            };
            if let Some((input, limit)) = input {
                match key.code {
                    KeyCode::Backspace => {
                        input.pop();
                        self.error = None;
                    }
                    KeyCode::Char(c) if !c.is_control() && input.len() + c.len_utf8() <= limit => {
                        input.push(c);
                        self.error = None;
                    }
                    _ => {}
                }
            }
        }
        Outcome::Continue
    }

    pub(super) fn footer(&self) -> &'static str {
        if self.step == Step::Engine {
            " j/k choose  Enter continue\n Ctrl-P privacy  Esc cancel\n PgUp/PgDn scroll  Ctrl-C quit"
        } else if self.step == Step::Review {
            " Enter create profile  Esc back\n Ctrl-P privacy  Ctrl-G cancel\n PgUp/PgDn scroll  Ctrl-C quit"
        } else {
            " Enter continue  Backspace edit  Esc back\n Ctrl-P privacy  Ctrl-G cancel\n PgUp/PgDn scroll  Ctrl-C quit"
        }
    }

    fn sections(area: Rect) -> [Rect; 3] {
        let inner = Block::default()
            .borders(Borders::TOP)
            .padding(Padding::horizontal(1))
            .inner(area);
        let parts = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(inner);
        [parts[0], parts[1], parts[2]]
    }

    // Share word/grapheme wrapping with launch review so scroll bounds match
    // the actual rows without Ratatui's unstable line-count API.
    fn rows(&self, masked: bool, width: u16) -> Vec<Line<'static>> {
        super::wrapped_rows(self.content(masked), width)
    }

    fn max_scroll(&self, area: Rect, masked: bool) -> u16 {
        let body = Self::sections(area)[1];
        u16::try_from(
            self.rows(masked, body.width)
                .len()
                .saturating_sub(usize::from(body.height)),
        )
        .unwrap_or(u16::MAX)
    }

    pub(super) fn draw(&self, frame: &mut Frame<'_>, area: Rect, masked: bool) {
        let block = Block::default()
            .borders(Borders::TOP)
            .title(" Add profile ")
            .padding(Padding::horizontal(1));
        frame.render_widget(block, area);
        let parts = Self::sections(area);
        let (number, title) = match self.step {
            Step::Engine => (1, "Choose an agent or engine"),
            Step::Alias => (2, "Profile label"),
            Step::Agent => (3, "Gents agent ID"),
            Step::Address => (4, "Local runtime address"),
            Step::Review => (
                if self.harness() == Harness::Gents {
                    5
                } else {
                    3
                },
                "Review profile",
            ),
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!(
                        "{number} / {}  ",
                        if self.harness() == Harness::Gents {
                            5
                        } else {
                            3
                        }
                    ),
                    Style::default().fg(TEAL),
                ),
                Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
            ])),
            parts[0],
        );
        let rows = self.rows(masked, parts[1].width);
        let maximum = u16::try_from(rows.len().saturating_sub(usize::from(parts[1].height)))
            .unwrap_or(u16::MAX);
        frame.render_widget(
            Paragraph::new(rows).scroll((self.scroll.min(maximum), 0)),
            parts[1],
        );
        let note = match &self.error {
            Some(error) if masked => format!("Check this step ({}).", error.code()),
            Some(error) => agentswapper_core::terminal_text(&error.to_string()),
            None => "You can go back or cancel at any step.".to_owned(),
        };
        frame.render_widget(
            Paragraph::new(note)
                .style(Style::default().fg(if self.error.is_some() { YELLOW } else { TEAL }))
                .wrap(Wrap { trim: true }),
            parts[2],
        );
    }

    fn content(&self, masked: bool) -> Vec<Line<'static>> {
        let value = |text: &str| {
            if masked && !text.is_empty() {
                "[hidden]".to_owned()
            } else {
                agentswapper_core::terminal_text(text)
            }
        };
        match self.step {
            Step::Engine => {
                let choices = [
                    "Claude Code  / native CLI",
                    "Codex        / native CLI",
                    "Kimi Code    / native CLI",
                    "gents        / attached client",
                ];
                let mut lines: Vec<Line<'_>> = choices
                    .into_iter()
                    .enumerate()
                    .map(|(i, text)| {
                        Line::styled(
                            format!("{} {text}", if self.engine == i { ">" } else { " " }),
                            if self.engine == i {
                                Style::default().fg(TEAL).add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            },
                        )
                    })
                    .collect();
                lines.push(Line::raw(""));
                lines.push(Line::raw(if self.harness() == Harness::Gents {
                    "gents owns workspace and permissions."
                } else {
                    "Use this agent's own terminal UI."
                }));
                lines
            }
            Step::Alias => vec![
                Line::raw("A short label: work or personal."),
                Line::styled(
                    format!("> {}_", value(&self.alias)),
                    Style::default().fg(TEAL),
                ),
                Line::raw(""),
                Line::raw("1-32 lowercase letters, digits, hyphens."),
                Line::raw("Start with a letter."),
            ],
            Step::Agent => vec![
                Line::raw("Use the ID from your gents runtime."),
                Line::styled(
                    format!("> {}_", value(&self.agent)),
                    Style::default().fg(TEAL),
                ),
                Line::raw(""),
                Line::raw("Exact and case-sensitive; ASCII only."),
            ],
            Step::Address => vec![
                Line::raw("Loopback IP and port; no credentials."),
                Line::styled(
                    format!("> {}_", value(&self.address)),
                    Style::default().fg(TEAL),
                ),
                Line::raw(""),
                Line::raw("127.0.0.1:PORT or [::1]:PORT"),
            ],
            Step::Review => {
                let mut lines = vec![
                    Line::raw(format!("Agent:   {}", self.harness())),
                    Line::raw(format!("Profile: {}", value(&self.alias))),
                ];
                if self.harness() == Harness::Gents {
                    lines.extend([
                        Line::raw(format!("Agent ID: {}", value(&self.agent))),
                        Line::raw(format!("Runtime:  {}", value(&self.address))),
                        Line::raw(""),
                        Line::raw("Runtime and work: unverified."),
                    ]);
                } else {
                    lines.extend([
                        Line::raw(""),
                        Line::raw("A private home will be created."),
                        Line::raw("Login and isolation: unverified."),
                    ]);
                }
                lines.push(Line::raw(""));
                lines.push(Line::raw("Enter registers; no agent will start."));
                lines
            }
        }
    }
}
