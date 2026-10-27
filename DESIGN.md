# AgentSwapper Design System

DESIGN_VARIANCE 6 / MOTION_INTENSITY 1 / VISUAL_DENSITY 3

Scope: the README and its assets. Selected direction: Night Shift / Distinction.

## 1. Visual theme

Confident, playful, precise. A noir canvas carries a quiet hex texture, wide
display typography, and expressive computer characters passing a folder of work.
The folder is the continuity metaphor. The characters add humor without making
the technical product hard to understand.

## 2. Color and roles

| Color | Hex | OKLCH | Role |
| :--- | :--- | :--- | :--- |
| Canvas Noir | #0A0A0A | oklch(0.1448 0 0) | Dark artwork canvas |
| Surface | #181818 | oklch(0.2090 0 0) | Supporting dark surface |
| Ink | #F2F2F2 | oklch(0.9612 0 0) | Dark-mode primary type |
| Primary Teal | #2CCCC3 | oklch(0.7660 0.1248 188.97) | Continuity, center character |
| Yellow | #FACD3D | oklch(0.8641 0.1592 90.55) | Outgoing character, paper |
| Purple | #5626C4 | oklch(0.4452 0.2214 287.31) | Folder and small details |
| Magenta | #E60576 | oklch(0.5988 0.2405 1.49) | Incoming character, route accent |
| Light Canvas | #F5F5F4 | oklch(0.9699 0.0013 106.42) | Light artwork canvas |

Light-mode primary ink is #141414. Saturated colors belong to artwork and
diagrams; body copy follows the host's accessible Markdown styling.

## 3. Typography

Syne is the display face, with wide, confident forms and tight tracking.
DM Sans supports the illustration captions and diagrams. Type is rasterized
into the PNG assets, so GitHub needs no external font requests. SVG masters
remain editable. README body type and sizing are controlled by GitHub.

## 4. Components and assets

- `assets/brand/readme-artwork-dark.png` and `readme-artwork-light.png` are the
  final header variants, each with an editable SVG master.
- `assets/brand/relay-characters.png` is the transparent original illustration.
- `assets/brand/handover-dark.png` and `handover-light.png` show the provider
  marks and the goal/progress/next-step relationship, with SVG masters.
- Earlier `readme-dark` and `readme-light` assets preserve the selected vector
  concept as an alternative.
- Provider-mark attribution is in `assets/brand/THIRD_PARTY_NOTICES.txt`.
- `command-dark` and `command-light` explain `aswp` by highlighting the A, Sw,
  and first p in AgentSwapper. The SVGs contain font outlines, with PNG fallbacks.
  The complete alias is `agentswapper`. Light-mode text uses deeper accent tones
  for contrast. Regenerate with `tools/render_command_art.py` and local fonts.

## 5. Hero

One integrated banner: AgentSwapper wordmark, a short caption, and three
characters passing one folder. Keep the tired character and coffee at the left,
the active teal runner in the center, and the eager magenta runner at the right.
Do not add floating interface cards, metrics, or installation claims.

## 6. Layout

Use standard GitHub Markdown and local image assets. Lead with the illustration,
then the product name, one-line purpose, honest development status, handover
diagram, four concise benefits, and architecture/roadmap links. The art carries
personality; the prose stays direct. No competitor comparisons in the README.

## 7. Responsive behavior

Images preserve their aspect ratio at every width. Do not set a fixed image
height in Markdown. Use a `picture` source for dark mode and an ordinary PNG
fallback. The reading order and text remain usable at a 390px viewport.

## 8. Motion

The README is static. It should load without JavaScript, animation, external
font requests, or a video. Future TUI motion must communicate state and honor
reduced-motion preferences.

## 9. NEVER DO

- Do not reopen the selected theme without a request to explore alternatives.
- Do not replace the character handover with a generic robot illustration.
- Do not use effects that obscure the faces, folder, title, or provider marks.
- Do not imply that unreleased CLI behavior is already implemented.
- Do not include invented installation commands, usage figures, or endorsements.
- Do not stretch artwork, hide text inside screenshots, or add HTML comments.
