#!/usr/bin/env python3 -I
"""Regenerate web/logo.png (light) and web/logo-dark.png (dark) from the master artwork, at 1600 px wide.

Author / Agent: Claude Code (claude-sonnet-5-5), 2026-11-12.
The sign-in card shows the logo at 300 CSS px; browser zoom and 2x/3x displays need >= 1200 px of source, so these
are cut from the 2172 px master instead of being downscaled twice. The white matte is removed with an exact
un-premultiply against white (clean anti-aliased edges, no halo); the dark variant recolours only the dark navy
"Studio" letters to #F1F4FB and leaves the blue "UX" and the red rocket alone.
Usage: python3 -I scripts/make_logos.py "<master.png>"
"""
import sys
from pathlib import Path
from PIL import Image

SRC = Path(sys.argv[1])
OUT = Path(__file__).resolve().parent.parent / "internal/authservice/web"
WIDTH = 1600
LIGHT_TEXT = (0xF1, 0xF4, 0xFB)

src = Image.open(SRC).convert("RGB")
light_px, dark_px = [], []
for r, g, b in src.getdata():
    a = 1.0 - min(r, g, b) / 255.0                           # how far from white
    if a < 0.02:
        light_px.append((0, 0, 0, 0)); dark_px.append((0, 0, 0, 0)); continue
    c = [min(255.0, max(0.0, (v - 255.0 * (1.0 - a)) / a)) for v in (r, g, b)]   # colour behind the white matte
    al = round(a * 255)
    light_px.append((round(c[0]), round(c[1]), round(c[2]), al))
    navy = max(c) < 150 and c[2] < 150                          # dark "Studio", not the bright blue "UX"
    dark_px.append((*LIGHT_TEXT, al) if navy else light_px[-1])

def finish(px, name):
    img = Image.new("RGBA", src.size)
    img.putdata(px)
    box = img.getchannel("A").point(lambda v: 255 if v > 8 else 0).getbbox()
    pad = 6
    img = img.crop((max(box[0] - pad, 0), max(box[1] - pad, 0), min(box[2] + pad, img.width), min(box[3] + pad, img.height)))
    img = img.resize((WIDTH, round(img.height * WIDTH / img.width)), Image.LANCZOS)
    img.save(OUT / name, optimize=True)
    print(name, img.size, (OUT / name).stat().st_size // 1024, "KB")

finish(light_px, "logo.png")
finish(dark_px, "logo-dark.png")
