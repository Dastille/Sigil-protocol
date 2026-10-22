# Sigil brand assets

Sigil has a mark and a name (wordmark), used separately or together (lockup).
Everything here comes from the old repo
[Dastille/dove-bloom-star-island](https://github.com/Dastille/dove-bloom-star-island).
Source commits: `5cad5930c3ed8f048c98fe556c81e611eb189dc7` (mark, header, mark component, fonts)
and `cca33b48db30931127c093dd24c8c5a0a11cb520` (brand tokens); all unchanged at old-repo HEAD `40e649a`.

| File | Status | Source |
|---|---|---|
| `mark.svg` | **Original**, copied byte-for-byte | `public/favicon.svg` (gold mark on dark-green rounded square, 32×32) |
| `mark-line.svg` | **Original geometry**, converted from JSX to SVG | `src/components/mark.tsx` (`SigilMark`, the in-app line mark; `currentColor`, set here to `#e8dcc8`) |
| `wordmark.svg` | **Reproduced from the CSS** | `src/components/app-header.tsx`: `font-serif text-lg tracking-tight` "Sigil" |
| `lockup.svg` | **Reproduced from the CSS** | `src/components/app-header.tsx`: `SigilMark` `size-7` + `gap-2.5` + wordmark |
| `sigil-brand-tokens.css` | **Original**, copied byte-for-byte | `artifacts/sigil-brand-tokens.css` |

No standalone wordmark/lockup file, PNG or larger logo existed in the old repo or its history; the
wordmark and lockup only existed as rendered HTML/CSS in the app header.

## Wordmark and lockup spec (from the original CSS)

- Font: Newsreader (Google Fonts), weight 400, optical size 18 (`--font-serif`: "Newsreader", "Iowan Old Style", "Palatino Linotype", Georgia, serif)
- Size: 18px (`text-lg`), line height 28px
- Letter-spacing: −0.025em (`tracking-tight`)
- Colour: `#e8dcc8` (foreground), mark uses the same colour (`currentColor`)
- Lockup: mark 28×28px, 10px gap, then wordmark, vertically centred in 28px

The wordmark text is outlined to paths (from Newsreader at opsz 18 / wght 400) so it renders without the font installed.
The wordmark, lockup and `mark-line.svg` are cream on transparent and are meant for dark backgrounds.

## Colours

| Name | Hex | Use |
|---|---|---|
| Gold | `#c29965` | `mark.svg`, `--sigil-gold`, app primary |
| Dark green | `#081710` | `mark.svg` background, app background |
| Background | `#07160f` | `--sigil-bg` |
| Background, elevated | `#0c2418` | `--sigil-bg-elevated` |
| Gold, bright | `#d4b07a` | `--sigil-gold-bright` |
| Foreground / cream | `#e8dcc8` | `--sigil-fg`, wordmark, line mark |
| Muted | `#8a9a88` | `--sigil-muted` |

## Future

A professionally redrawn vector master that holds up at large sizes is still to do. The current marks were
drawn on a 32×32 grid for favicon/header use.
