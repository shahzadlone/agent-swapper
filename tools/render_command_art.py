"""Render the command-name artwork with local fonts and no external SVG assets.

Requires fonttools and rsvg-convert. Pass a directory containing Syne.ttf and
DMSans.ttf. The SVG output contains outlines, so viewers need no installed font.
"""

import argparse
from html import escape
from pathlib import Path
import subprocess

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont


def font(path, weight):
    source = TTFont(path)
    if "fvar" in source:
        source = instantiateVariableFont(source, {"wght": weight})
    return source


def lettering(source, words, x, y, size, colors):
    glyphs = source.getGlyphSet()
    cmap = source.getBestCmap()
    scale = size / source["head"].unitsPerEm
    parts = []
    cursor = x
    for i, char in enumerate(words):
        glyph = glyphs[cmap[ord(char)]]
        pen = SVGPathPen(glyphs)
        glyph.draw(pen)
        parts.append(
            f'<path fill="{colors[i] if isinstance(colors, list) else colors}" '
            f'transform="translate({cursor:.3f} {y}) scale({scale:.6f} {-scale:.6f})" '
            f'd="{pen.getCommands()}"/>'
        )
        cursor += glyph.width * scale
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fonts-dir", type=Path, required=True)
    args = parser.parse_args()
    output = Path(__file__).resolve().parent.parent / "assets" / "brand"
    display = font(args.fonts_dir / "Syne.ttf", 750)
    body = font(args.fonts_dir / "DMSans.ttf", 500)
    title = "aswp abbreviates AgentSwapper: A, Sw, and p. Alias: agentswapper."
    for mode in ("dark", "light"):
        dark = mode == "dark"
        bg, ink, quiet = ("#0A0A0A", "#F2F2F2", "#B2B2B2") if dark else ("#F5F5F4", "#141414", "#545454")
        teal, yellow, pink = ("#2CCCC3", "#FACD3D", "#F754A5") if dark else ("#08766F", "#8A6000", "#B40459")
        accents = [teal, yellow, yellow, pink]
        name_colors = [ink] * len("AgentSwapper")
        for index, color in zip((0, 5, 6, 8), accents):
            name_colors[index] = color
        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 340" role="img" aria-labelledby="title">',
            f'<title id="title">{escape(title)}</title>',
            f'<rect width="1440" height="340" rx="12" fill="{bg}"/>',
            lettering(body, "MEET YOUR SHORTCUT", 64, 58, 23, quiet),
            lettering(display, "aswp", 56, 211, 128, accents),
            f'<path d="M562 171h40m-12-11 12 11-12 11" fill="none" stroke="{quiet}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>',
            lettering(display, "AgentSwapper", 650, 197, 70, name_colors),
            lettering(body, "Four letters. Keep moving.", 64, 285, 28, ink),
            lettering(body, "Full-length alias: agentswapper", 650, 285, 28, quiet),
            '</svg>',
        ]
        svg = output / f"command-{mode}.svg"
        svg.write_text("".join(parts), encoding="ascii")
        subprocess.run(["rsvg-convert", "-o", str(svg.with_suffix(".png")), str(svg)], check=True)
        print(svg.relative_to(output.parent.parent))


if __name__ == "__main__":
    main()
