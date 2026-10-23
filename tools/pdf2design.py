#!/usr/bin/env python
"""
pdf2design.py — turn UI design PDFs into something an AI agent can build from.

Why this exists
---------------
OpenCode does NOT send PDF attachments to the model (see opencode.ai/v2/docs/attachments:
"PDF ... and other binary prompt attachments are not included in the model request").
So a PDF of a UI design cannot be dropped into a prompt and "seen".

This script bridges that gap two ways:

  1. Renders every PDF page to a PNG  -> designs/_extracted/<pdf>/page-NN.png
     (visually exact; usable when the active model supports image input)

  2. Extracts a full design spec from the PDF internals -> spec.json + spec.md
     + tokens.css
     (text, fonts, sizes, colours, positions, boxes, palette, type scale and
     guessed components). This is readable by ANY model, vision or not.

Usage
-----
  python tools/pdf2design.py                       # all PDFs in designs/
  python tools/pdf2design.py path/to/design.pdf    # one file
  python tools/pdf2design.py designs/ --dpi 200    # higher resolution renders
  python tools/pdf2design.py designs/ --name login # override output folder name
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import pymupdf as fitz  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover
    try:
        import fitz  # older PyMuPDF
    except ImportError:
        sys.exit("PyMuPDF is not installed. Run:  python -m pip install pymupdf")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def hex_from_int(value: int) -> str:
    """PyMuPDF span colours are packed sRGB integers."""
    return "#{:06x}".format(value & 0xFFFFFF)


def hex_from_tuple(rgb) -> str | None:
    """Drawing fill/stroke colours are (r, g, b) floats in 0..1."""
    if not rgb:
        return None
    r, g, b = (max(0.0, min(1.0, float(c))) for c in rgb[:3])
    return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))


def is_bold(span: dict) -> bool:
    if span.get("flags", 0) & 2 ** 4:
        return True
    return bool(re.search(r"bold|black|heavy|semib|demib", span.get("font", ""), re.I))


def is_italic(span: dict) -> bool:
    if span.get("flags", 0) & 2 ** 1:
        return True
    return bool(re.search(r"italic|oblique", span.get("font", ""), re.I))


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def saturation(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    mx, mn = max(r, g, b), min(r, g, b)
    return 0 if mx == 0 else (mx - mn) / mx


def rect_to_list(r) -> list[float]:
    return [round(r.x0, 2), round(r.y0, 2), round(r.x1, 2), round(r.y1, 2)]


# --------------------------------------------------------------------------- #
# extraction
# --------------------------------------------------------------------------- #

def extract_text(page) -> list[dict]:
    out = []
    data = page.get_text("dict")
    for block in data.get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                text = span.get("text", "").strip()
                if not text:
                    continue
                out.append({
                    "text": text,
                    "font": span.get("font", ""),
                    "size": round(float(span.get("size", 0)), 2),
                    "color": hex_from_int(span.get("color", 0)),
                    "bold": is_bold(span),
                    "italic": is_italic(span),
                    "bbox": [round(v, 2) for v in span["bbox"]],
                })
    return out


def extract_drawings(page) -> tuple[list[dict], list[dict]]:
    """Split vector drawings into filled shapes and stroked shapes."""
    fills, strokes = [], []
    for d in page.get_drawings():
        rect = d.get("rect")
        if rect is None:
            continue
        width = rect.x1 - rect.x0
        height = rect.y1 - rect.y0
        if width < 3 or height < 3:
            continue  # hairlines / rules are noise for layout purposes

        if d.get("fill") is not None:
            fills.append({
                "color": hex_from_tuple(d.get("fill")),
                "bbox": rect_to_list(rect),
                "width": round(width, 2),
                "height": round(height, 2),
                "type": d.get("type"),
            })
        if d.get("color") is not None and (d.get("fill") is None or d.get("type") in ("s", "fs")):
            strokes.append({
                "color": hex_from_tuple(d.get("color")),
                "bbox": rect_to_list(rect),
                "width": round(width, 2),
                "height": round(height, 2),
                "stroke_width": round(float(d.get("width") or 0), 2),
            })
    return fills, strokes


def extract_images(page) -> list[dict]:
    out = []
    for img in page.get_images(full=True):
        xref = img[0]
        try:
            rects = page.get_image_rects(xref)
        except Exception:
            rects = []
        for r in rects:
            out.append({
                "xref": xref,
                "bbox": rect_to_list(r),
                "width": round(r.x1 - r.x0, 2),
                "height": round(r.y1 - r.y0, 2),
            })
    return out


# --------------------------------------------------------------------------- #
# component heuristics
# --------------------------------------------------------------------------- #

def guess_components(fills: list[dict], strokes: list[dict], texts: list[dict]) -> list[dict]:
    """Classify vector rectangles into buttons / inputs / cards / panels."""
    components = []

    for f in fills:
        x0, y0, x1, y1 = f["bbox"]
        w, h = f["width"], f["height"]
        color = f["color"]
        if not color:
            continue

        inside = [
            t for t in texts
            if x0 - 1 <= (t["bbox"][0] + t["bbox"][2]) / 2 <= x1 + 1
            and y0 - 1 <= (t["bbox"][1] + t["bbox"][3]) / 2 <= y1 + 1
        ]
        inside.sort(key=lambda t: t["bbox"][1])

        label = " ".join(t["text"] for t in inside)[:120]
        sat = saturation(color)
        lum = luminance(color)

        kind = None
        if h <= 56 and w <= 400 and len(inside) <= 2 and sat > 0.25:
            kind = "button"
        elif h <= 56 and w <= 480 and len(inside) <= 3 and sat <= 0.25 and lum > 0.85:
            kind = "input"
        elif h >= 60 and w >= 180:
            kind = "card" if len(inside) > 1 else "panel"

        if kind:
            components.append({
                "kind": kind,
                "label": label,
                "bbox": f["bbox"],
                "size": [w, h],
                "fill": color,
                "text_color": inside[0]["color"] if inside else None,
                "font_size": inside[0]["size"] if inside else None,
                "font": inside[0]["font"] if inside else None,
                "bold": inside[0]["bold"] if inside else None,
            })

    for s in strokes:
        x0, y0, x1, y1 = s["bbox"]
        w, h = s["width"], s["height"]
        if h > 56 or w < 90 or w > 700:
            continue
        if h <= 56 and any(f["bbox"] == s["bbox"] for f in fills):
            continue  # already handled as a fill
        components.append({
            "kind": "input",
            "label": "",
            "bbox": s["bbox"],
            "size": [w, h],
            "fill": None,
            "stroke": s["color"],
            "stroke_width": s.get("stroke_width"),
        })

    components.sort(key=lambda c: (c["bbox"][1], c["bbox"][0]))
    return components


def detect_screen_name(texts: list[dict]) -> str:
    """The largest text near the top of the page is treated as the screen title."""
    if not texts:
        return "Untitled"
    top = [t for t in texts if t["bbox"][1] < 220] or texts
    title = max(top, key=lambda t: t["size"] * (2 if t["bold"] else 1))
    return title["text"][:80]


def detect_type_scale(texts: list[dict]) -> list[dict]:
    """Group text by (size, weight) to produce a reusable type scale."""
    buckets: dict[tuple, dict] = {}
    for t in texts:
        key = (t["size"], t["bold"])
        b = buckets.setdefault(key, {"size": t["size"], "bold": t["bold"], "count": 0,
                                    "font": t["font"], "color": t["color"], "samples": []})
        b["count"] += 1
        if len(b["samples"]) < 4 and t["text"] not in b["samples"]:
            b["samples"].append(t["text"][:40])
    return sorted(buckets.values(), key=lambda b: -b["size"])


def detect_palette(fills: list[dict], strokes: list[dict], texts: list[dict]) -> dict:
    counter: Counter = Counter()
    for f in fills:
        if f["color"]:
            counter[f["color"]] += max(1, int(f["width"] * f["height"] / 1000))
    for s in strokes:
        if s["color"]:
            counter[s["color"]] += max(1, int(s["width"] * s["height"] / 1000))
    for t in texts:
        counter[t["color"]] += t["size"] * 2
    ranked = counter.most_common(40)

    primary = next((c for c, _ in ranked if saturation(c) > 0.45 and luminance(c) < 0.75), None)
    neutral_text = next((c for c, _ in ranked if saturation(c) < 0.12 and luminance(c) < 0.3), None)
    neutral_bg = next((c for c, _ in ranked if luminance(c) > 0.93), "#ffffff")

    return {
        "ranked": [{"color": c, "weight": w} for c, w in ranked],
        "suggested_primary": primary,
        "suggested_text": neutral_text,
        "suggested_background": neutral_bg,
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_page(page, out_path: Path, dpi: int) -> str:
    pix = page.get_pixmap(dpi=dpi)
    pix.save(str(out_path))
    return out_path.name


# --------------------------------------------------------------------------- #
# report writers
# --------------------------------------------------------------------------- #

def write_spec_md(spec: dict, out_path: Path) -> None:
    L = []
    a = L.append
    a("# Design spec — {}".format(spec["source"]))
    a("")
    a("Machine-extracted from the PDF. Use this to build the UI without seeing the PDF.")
    a("")

    pal = spec["palette"]
    a("## Palette")
    a("")
    if pal["suggested_primary"]:
        a("- suggested primary: `{}`".format(pal["suggested_primary"]))
    if pal["suggested_text"]:
        a("- suggested text: `{}`".format(pal["suggested_text"]))
    a("- background: `{}`".format(pal["suggested_background"]))
    a("")
    a("| Colour | Weight |")
    a("| --- | ---: |")
    for item in pal["ranked"][:24]:
        a("| `{}` | {} |".format(item["color"], item["weight"]))
    a("")

    fonts = spec["fonts"]
    if fonts:
        a("## Fonts")
        a("")
        for f in fonts:
            a("- `{}` — {} occurrence(s)".format(f["font"], f["count"]))
        a("")

    a("## Type scale")
    a("")
    a("| Size | Weight | Font | Sample |")
    a("| ---: | --- | --- | --- |")
    for t in spec["typeScale"]:
        weight = "bold" if t["bold"] else "regular"
        sample = ", ".join(t["samples"])[:70]
        a("| {}px | {} | {} | {} |".format(t["size"], weight, t["font"], sample))
    a("")

    a("## Screens")
    a("")
    for p in spec["pages"]:
        a("### Page {} — {}".format(p["index"], p["screen"]))
        a("")
        a("- render: `{}`".format(p["image"]))
        a("- page size: {} x {} pt".format(p["width"], p["height"]))
        a("")
        a("**Text content**")
        a("")
        for t in p["text"]:
            a("- [{}] {} ({}px, {})".format(
                t["color"], t["text"], t["size"], "bold" if t["bold"] else "regular"))
        a("")
        comps = p.get("components") or []
        if comps:
            a("**Components**")
            a("")
            for c in comps:
                a("- **{}** “{}” — box {}x{} at [{}, {}], fill `{}`{}".format(
                    c["kind"], c.get("label", "")[:40], c["size"][0], c["size"][1],
                    c["bbox"][0], c["bbox"][1], c.get("fill") or "none",
                    ", stroke `{}`".format(c["stroke"]) if c.get("stroke") else ""))
            a("")

    out_path.write_text("\n".join(L), encoding="utf-8")


def write_tokens_css(spec: dict, out_path: Path) -> None:
    pal = spec["palette"]
    L = []
    a = L.append
    a("/* Design tokens extracted from {} */".format(spec["source"]))
    a(":root {")
    if pal["suggested_primary"]:
        a("  --color-primary: {};".format(pal["suggested_primary"]))
    if pal["suggested_text"]:
        a("  --color-text: {};".format(pal["suggested_text"]))
    a("  --color-background: {};".format(pal["suggested_background"]))
    ranked = pal["ranked"]
    for i, item in enumerate(ranked[:12], start=1):
        a("  --color-accent-{}: {};".format(i, item["color"]))
    a("")
    for t in spec["typeScale"][:10]:
        name = "text-{}".format(str(t["size"]).replace(".", "-"))
        a("  --font-size-{}: {}px;".format(name, t["size"]))
    a("}")
    out_path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def process_pdf(pdf_path: Path, out_root: Path, dpi: int, name_override: str | None) -> dict:
    slug = name_override or re.sub(r"[^a-z0-9]+", "-", pdf_path.stem.lower()).strip("-")
    out_dir = out_root / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    doc = fitz.open(str(pdf_path))
    spec = {
        "source": pdf_path.name,
        "slug": slug,
        "pageCount": doc.page_count,
        "pages": [],
    }

    all_texts: list[dict] = []
    all_fills: list[dict] = []
    all_strokes: list[dict] = []

    for i, page in enumerate(doc, start=1):
        texts = extract_text(page)
        fills, strokes = extract_drawings(page)
        images = extract_images(page)
        png_name = render_page(page, out_dir / "page-{:02d}.png".format(i), dpi)

        page_spec = {
            "index": i,
            "screen": detect_screen_name(texts),
            "image": png_name,
            "width": round(page.rect.width, 2),
            "height": round(page.rect.height, 2),
            "text": texts,
            "fills": fills,
            "strokes": strokes,
            "images": images,
            "components": guess_components(fills, strokes, texts),
        }
        spec["pages"].append(page_spec)

        all_texts.extend(texts)
        all_fills.extend(fills)
        all_strokes.extend(strokes)

    doc.close()

    spec["palette"] = detect_palette(all_fills, all_strokes, all_texts)
    spec["typeScale"] = detect_type_scale(all_texts)
    font_counts: Counter = Counter()
    for t in all_texts:
        font_counts[t["font"]] += 1
    spec["fonts"] = [{"font": f, "count": c} for f, c in font_counts.most_common()]

    (out_dir / "spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")
    write_spec_md(spec, out_dir / "spec.md")
    write_tokens_css(spec, out_dir / "tokens.css")
    return spec


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract UI design specs from PDFs.")
    ap.add_argument("target", nargs="?", default="designs",
                    help="PDF file or directory of PDFs (default: designs/)")
    ap.add_argument("--out", default=None, help="output root (default: <target>/_extracted)")
    ap.add_argument("--dpi", type=int, default=150, help="render resolution (default 150)")
    ap.add_argument("--name", default=None, help="override output folder name")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        sys.exit("Path not found: {}".format(target))

    if target.is_dir():
        pdfs = sorted(target.glob("*.pdf"))
        out_root = Path(args.out) if args.out else target / "_extracted"
    else:
        pdfs = [target]
        out_root = Path(args.out) if args.out else target.parent / "_extracted"

    if not pdfs:
        sys.exit("No PDFs found in {}".format(target))

    out_root.mkdir(parents=True, exist_ok=True)
    print("Extracting {} PDF(s) into {}\n".format(len(pdfs), out_root))

    for pdf in pdfs:
        try:
            spec = process_pdf(pdf, out_root, args.dpi, args.name)
        except Exception as exc:  # noqa: BLE001
            print("  [FAIL] {}: {}".format(pdf.name, exc))
            continue
        print("  [OK]   {} -> {}/{}  ({} page(s))".format(
            pdf.name, out_root, spec["slug"], spec["pageCount"]))
        for page in spec["pages"]:
            print("         page {} — {} ({})".format(
                page["index"], page["screen"], page["image"]))

    print("\nDone. Read the generated spec.md / spec.json / page-NN.png next to the PDF.")


if __name__ == "__main__":
    main()
