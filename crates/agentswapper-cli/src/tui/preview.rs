//! Optional visual artifacts from the actual renderer and fictional test fixtures.
#![allow(clippy::unwrap_used)]
use super::{Dashboard, draw};
use ratatui::{
    Terminal,
    backend::TestBackend,
    style::{Color, Modifier},
};
use std::{fmt::Write, path::PathBuf};

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn color(color: Color, fallback: &str) -> String {
    match color {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Gray => "#c0c0c0".into(),
        _ => fallback.into(),
    }
}

pub(super) fn export(app: &Dashboard, name: &str, width: u16, height: u16) {
    let Some(directory) = std::env::var_os("ASWP_UI_PREVIEW_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, app)).unwrap();
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>AgentSwapper / {name}</title><style>body{{margin:32px;background:#181818;color:#f2f2f2;font:15px system-ui}}a{{color:#2cccc3}}pre{{width:max-content;padding:16px;background:#0a0a0a;border:1px solid #404040;border-radius:8px;font:14px/1.45 ui-monospace,'DejaVu Sans Mono','Liberation Mono',monospace;font-variant-ligatures:none}}main{{overflow:auto}}small{{color:#bbb}}</style><a href=\"index.html\">All terminal previews</a><h1>{name}</h1><p>Actual Ratatui renderer · {width} × {height} · fictional profiles</p><main><pre>"
    );
    let buffer = terminal.backend().buffer();
    for y in 0..height {
        for x in 0..width {
            let cell = &buffer[(x, y)];
            write!(
                html,
                "<span style=\"color:{};background:{};font-weight:{}\">{}</span>",
                color(cell.fg, "#f2f2f2"),
                color(cell.bg, "#0a0a0a"),
                if cell.modifier.contains(Modifier::BOLD) {
                    "700"
                } else {
                    "400"
                },
                escape(cell.symbol())
            )
            .unwrap();
        }
        html.push('\n');
    }
    html.push_str("</pre></main><small>Developer preview. Usage is unmeasured; automated switching is not implemented.</small></html>");
    std::fs::write(directory.join(format!("{name}.html")), html).unwrap();
}
