#!/usr/bin/env python3
"""Rebuild docs/WHITEPAPER.pdf from docs/WHITEPAPER.md.

Needs the Python packages `markdown` and `weasyprint` (for example in a
virtualenv: `python3 -m venv .venv && .venv/bin/pip install markdown weasyprint`).

    python3 scripts/build-whitepaper-pdf.py

The PDF carries only a title; no author, creator or source path metadata.
Rebuild it whenever WHITEPAPER.md changes: the privacy check in `cargo test`
scans the PDF text too.
"""
import pathlib

import markdown
from weasyprint import HTML

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "WHITEPAPER.md"
OUT = ROOT / "docs" / "WHITEPAPER.pdf"

CSS = """
@page { size: letter; margin: 0.8in 0.75in;
        @bottom-center { content: counter(page); font-size: 9pt; color: #555; } }
body { font-family: Carlito, Calibri, "Liberation Sans", "DejaVu Sans", sans-serif;
       font-size: 10.5pt; line-height: 1.35; color: #111; }
h1 { font-size: 20pt; margin: 0 0 6pt; }
h2 { font-size: 14pt; margin: 16pt 0 4pt; }
h3 { font-size: 11.5pt; margin: 12pt 0 3pt; }
p, li { margin: 3pt 0; }
code, pre { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; }
pre { background: #f4f4f4; padding: 5pt; white-space: pre-wrap; }
table { border-collapse: collapse; margin: 6pt 0; font-size: 8.5pt; }
th, td { border: 0.5pt solid #999; padding: 2pt 4pt; vertical-align: top; }
th { background: #eee; }
hr { border: 0; border-top: 0.5pt solid #999; }
"""


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists"])
    title = text.splitlines()[0].lstrip("# ").strip()
    html = (
        f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>"
        f"<style>{CSS}</style></head><body>{body}</body></html>"
    )
    HTML(string=html, base_url=str(SRC.parent)).write_pdf(str(OUT))
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
