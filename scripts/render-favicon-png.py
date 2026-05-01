#!/usr/bin/env python3
"""Render the bracket-[w] favicon to PNG at multiple sizes.

We can't shell out to rsvg-convert (not installed in the build env), so
this rasterizes the SVG geometry by hand using Pillow. The geometry is
the same as app/static/favicon.svg; coordinates are scaled from the SVG
viewBox (0..64) to the target PNG size.

Output:
    apple-touch-icon.png     180x180  for <link rel="apple-touch-icon">
    icon-192.png             192x192  for the web manifest
    icon-512.png             512x512  for the web manifest

Run:
    python3 scripts/render-favicon-png.py
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw

# Phosphor-green dark theme defaults — this is what gets baked into the
# home-screen icon. The runtime favicon-swap (refreshFavicon in
# index.html) tracks --accent for the live tab-strip icon, but home
# screen icons are brand-stable: once installed, they don't change with
# the user's panel preferences.
ACCENT = (0x8b, 0xff, 0x6a, 0xff)   # phosphor green
BG     = (0x0a, 0x0d, 0x0b, 0xff)   # near-black

OUT_DIR = Path(__file__).resolve().parent.parent / "app" / "static"


def render(size: int, path: Path) -> None:
    """Render the [w] mark at `size` x `size` and save as PNG."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Helper: scale SVG viewBox coordinate (0..64) to pixel.
    s = size / 64.0
    def sc(v): return v * s

    # Rounded backdrop. SVG uses rx=8 in a 64-unit viewBox → 12.5%.
    radius = int(sc(8))
    draw.rounded_rectangle(
        (0, 0, size - 1, size - 1),
        radius=radius,
        fill=BG,
    )

    # Stroke widths: SVG uses 3 for brackets, 3.5 for the W. Scale
    # accordingly. Pillow doesn't have a "polyline with rounded caps"
    # primitive, so we draw rectangles for the brackets (which is
    # exactly what SVG `stroke-linecap="square"` produces) and handle
    # the W as line segments with explicit end-caps via small circles.

    bracket_w = max(2, int(round(sc(3))))
    w_stroke  = max(2, int(round(sc(3.5))))

    # --- Left bracket: SVG path "M 16 16 L 11 16 L 11 48 L 16 48"
    # Three segments forming a [ shape. With square linecap, each
    # segment is rendered as a rectangle of (length × stroke_width).
    # We draw three filled rectangles to approximate. The "stroke
    # extension at endpoints" of square linecap = stroke_width/2 on
    # each end; we emulate by extending each rect by stroke_w/2.
    half = bracket_w / 2.0

    # Top horizontal: from (16,16) to (11,16)
    draw.rectangle(
        (sc(11) - half, sc(16) - half, sc(16) + half, sc(16) + half),
        fill=ACCENT,
    )
    # Vertical: from (11,16) to (11,48)
    draw.rectangle(
        (sc(11) - half, sc(16) - half, sc(11) + half, sc(48) + half),
        fill=ACCENT,
    )
    # Bottom horizontal: from (11,48) to (16,48)
    draw.rectangle(
        (sc(11) - half, sc(48) - half, sc(16) + half, sc(48) + half),
        fill=ACCENT,
    )

    # --- Right bracket: mirror of the left
    # Top: (48,16) → (53,16)
    draw.rectangle(
        (sc(48) - half, sc(16) - half, sc(53) + half, sc(16) + half),
        fill=ACCENT,
    )
    # Vertical: (53,16) → (53,48)
    draw.rectangle(
        (sc(53) - half, sc(16) - half, sc(53) + half, sc(48) + half),
        fill=ACCENT,
    )
    # Bottom: (53,48) → (48,48)
    draw.rectangle(
        (sc(48) - half, sc(48) - half, sc(53) + half, sc(48) + half),
        fill=ACCENT,
    )

    # --- The W. SVG path "M 19 24 L 25 42 L 32 30 L 39 42 L 45 24"
    # 4 segments with round caps + round joins. Pillow's draw.line
    # supports `width` but no native round join. We draw the segments
    # then overdraw filled circles at each vertex to round the joins.
    pts = [
        (sc(19), sc(24)),
        (sc(25), sc(42)),
        (sc(32), sc(30)),
        (sc(39), sc(42)),
        (sc(45), sc(24)),
    ]
    for i in range(len(pts) - 1):
        draw.line([pts[i], pts[i + 1]], fill=ACCENT, width=w_stroke)
    # Round caps + joins via dots at every vertex (including the two
    # endpoints — that's what SVG `stroke-linecap="round"` produces).
    cap_r = w_stroke / 2.0
    for x, y in pts:
        draw.ellipse(
            (x - cap_r, y - cap_r, x + cap_r, y + cap_r),
            fill=ACCENT,
        )

    img.save(path, "PNG", optimize=True)
    print(f"  wrote {path} ({path.stat().st_size} bytes)")


def main():
    print(f"rendering favicon PNGs to {OUT_DIR}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    render(180, OUT_DIR / "apple-touch-icon.png")
    render(192, OUT_DIR / "icon-192.png")
    render(512, OUT_DIR / "icon-512.png")
    print("done.")


if __name__ == "__main__":
    main()
