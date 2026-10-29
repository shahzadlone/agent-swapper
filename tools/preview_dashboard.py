#!/usr/bin/env python3
"""Render fictional TUI fixtures through Ratatui, then serve their HTML previews."""

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4317)
    parser.add_argument("--no-serve", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    root = repo / ".preview"
    destination = root / "terminal"
    env = {**os.environ, "ASWP_UI_PREVIEW_DIR": str(destination)}
    # Snapshot acceptance remains manual; rendering must not silently rewrite it.
    env.pop("INSTA_UPDATE", None)
    subprocess.run(["cargo", "test", "--locked", "-p", "agentswapper-cli",
                    "--lib", "tui::"], cwd=repo, env=env, check=True)
    names = ["overview", "overview-80", "overview-160", "overview-44",
             "unresolved", "gents", "privacy-search", "privacy-narrow", "empty",
             "setup-agents", "setup-label", "setup-native-review", "setup-invalid-route",
             "setup-private-100", "setup-private-80", "setup-private-44", "setup-private-40",
             "launch-review-80", "launch-review-100", "launch-review-160",
             "launch-private-40", "launch-private-44", "launch-private-80",
             "launch-private-100", "launch-private-160"]
    names.extend([f"{name}-private-{width}" for name in ["rename", "unregister"] for width in [40, 44, 80, 100, 160]])
    names.extend(["rename-review", "unregister-review"])
    links = "".join(f'<li><a href="{name}.html">{name.replace("-", " ")}</a></li>'
                    for name in names)
    destination.joinpath("index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>AgentSwapper terminal previews</title>'
        '<style>body{max-width:800px;margin:60px auto;padding:24px;background:#0a0a0a;'
        'color:#f2f2f2;font:18px/1.6 system-ui}a{color:#2cccc3}li{margin:12px 0}'
        'small{color:#bbb}</style><h1>AgentSwapper in the terminal</h1>'
        '<p>These screens come from the actual Rust renderer with fictional profiles. '
        'They show the current developer preview, not the final interface.</p>'
        f'<ul>{links}</ul><small>Usage is unmeasured. Automated switching is not implemented.'
        '</small></html>', encoding="utf-8")
    print(f"Previews: {destination}", flush=True)
    if not args.no_serve:
        handler = partial(SimpleHTTPRequestHandler, directory=str(root))
        with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
            print(f"Open http://localhost:{args.port}/terminal/", flush=True)
            server.serve_forever()


if __name__ == "__main__":
    main()
