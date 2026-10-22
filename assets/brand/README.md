# Sigil brand assets

## Official logo

Sigil's official logo is the **OG tree logo**: a thin gold tree of life (branches up, roots down)
inside a circle, over spaced `S I G I L` serif capitals, on dark green.

The files in `original/` are copied byte-for-byte from the old repo
[Dastille/dove-bloom-star-island](https://github.com/Dastille/dove-bloom-star-island). They are raster
JPEGs; there is no vector master yet.

| File | Size | Source path (old repo) | Commit(s) |
|---|---|---|---|
| `original/og-cover.jpg` | 1200×630 | `artifacts/og-cover.jpg` | `5cad593` (2026-08-24), `e86b45f` (2026-08-26), `cca33b4` (2026-08-28) |
| `original/og.jpg` | 1200×630 | `public/og.jpg` | `5cad593` (2026-08-24) |
| `original/lockup-stacked-square.jpg` | 1408×1408 | `attachments/1000008435.jpg` | `5cad593` (2026-08-24) |
| `original/lockup-horizontal.jpg` | 1168×784 | `attachments/1000008433.jpg` | `5cad593` (2026-08-24) |
| `original/emblem-stacked-black.jpg` | 1168×784 | `attachments/1000008432.jpg` | `5cad593` (2026-08-24) |
| `original/banner.jpg` | 1500×843 | `attachments/1000008438.jpg` | `5cad593` (2026-08-24) |

Dates are commit dates in US Eastern time. `og-cover.jpg` was last changed in `cca33b4`; `og.jpg` is a different file.
The root README shows `original/og.jpg`.

## Colours

`sigil-brand-tokens.css` holds the brand colours as CSS custom properties (plus a two-line `body`
background/colour rule). Copied byte-for-byte from `artifacts/sigil-brand-tokens.css` (`cca33b4`).

| Name | Hex | Token |
|---|---|---|
| Gold | `#c29965` | `--sigil-gold` |
| Gold, bright | `#d4b07a` | `--sigil-gold-bright` |
| Background (dark green) | `#07160f` | `--sigil-bg` |
| Background, elevated | `#0c2418` | `--sigil-bg-elevated` |
| Foreground / cream | `#e8dcc8` | `--sigil-fg` |
| Muted | `#8a9a88` | `--sigil-muted` |

## Future

- A professionally redrawn clean vector (SVG) of the tree logo and the wordmark. Not done yet. It should be
  redrawn by hand, not auto-traced from the JPEGs.
