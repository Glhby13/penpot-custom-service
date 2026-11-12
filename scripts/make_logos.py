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
def make_icon():
    # Crop UX portion (tight bounds around U, X, and the red tip)
    ux_crop = Image.new("RGBA", src.size)
    ux_crop.putdata(light_px)
    ux_cut = ux_crop.crop((186, 177, 925, 498))
    bbox = ux_cut.getchannel("A").point(lambda v: 255 if v > 8 else 0).getbbox()
    ux_tight = ux_cut.crop(bbox)

    target_size = 512
    padding = 48
    inner_size = target_size - (padding * 2)
    scale = min(inner_size / ux_tight.width, inner_size / ux_tight.height)
    new_w = round(ux_tight.width * scale)
    new_h = round(ux_tight.height * scale)
    scaled_ux = ux_tight.resize((new_w, new_h), Image.LANCZOS)

    icon = Image.new("RGBA", (target_size, target_size), (0, 0, 0, 0))
    paste_x = (target_size - new_w) // 2
    paste_y = (target_size - new_h) // 2
    icon.paste(scaled_ux, (paste_x, paste_y), scaled_ux)
    icon.save(OUT / "icon.png", optimize=True)
    icon.resize((64, 64), Image.LANCZOS).save(OUT / "favicon.png", optimize=True)
    print("icon.png", icon.size, (OUT / "icon.png").stat().st_size // 1024, "KB")
    print("favicon.png", (64, 64), (OUT / "favicon.png").stat().st_size // 1024, "KB")

finish(light_px, "logo.png")
finish(dark_px, "logo-dark.png")
make_icon()

