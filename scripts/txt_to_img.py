#!/usr/bin/env python3
#
# txt_to_img.py: render an evidence .txt as a fixed-size dark terminal PNG.
#
# Canvas is always 1600x830 (standard terminal window screenshot size).
# If the content is taller than the canvas, the visible lines are shown
# and a "... +N more lines" footer is added at the bottom.  The source
# .txt file always contains the full untruncated evidence.
#
# Usage:
#   txt_to_img.py <file.txt> [out.png]   render one file
#   txt_to_img.py <dir>                  render every *.txt in <dir> into
#                                        <dir>/images/<name>.png
#
import os
import sys

from PIL import Image, ImageDraw, ImageFont

# Fixed canvas — matches a 1600x830 terminal window screenshot.
CANVAS_W = 1600
CANVAS_H = 830

BG     = (13, 17, 23)
FG     = (201, 209, 217)
GREEN  = (63, 185, 80)
BLUE   = (121, 192, 255)
RED    = (248, 81, 73)
GRAY   = (110, 118, 129)
ORANGE = (219, 109, 40)

FONT_SIZE = 14
LINE_PAD  = 4
MARGIN_X  = 18
MARGIN_Y  = 14


def find_font(size):
    for p in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
        "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/cour.ttf",
    ):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def line_color(line):
    upper = line.upper()
    if "CRITICAL" in upper or "VULNERABLE" in upper or "[!]" in line:
        return RED
    if "[+]" in line:
        return GREEN
    if "[*]" in line:
        return BLUE
    if line.strip().startswith("#") or line.strip() == "DONE":
        return GRAY
    if "HIGH" in upper or "MEDIUM" in upper:
        return ORANGE
    return FG


def render(txt_path, png_path):
    with open(txt_path, encoding="utf-8", errors="replace") as f:
        lines = f.read().rstrip("\n").split("\n")

    font   = find_font(FONT_SIZE)
    line_h = FONT_SIZE + LINE_PAD

    # How many lines fit before hitting the max canvas height.
    usable_h  = CANVAS_H - MARGIN_Y * 2
    max_lines = max(1, (usable_h - line_h) // line_h)  # reserve 1 row for footer

    truncated = len(lines) > max_lines
    visible   = lines[:max_lines]
    overflow  = len(lines) - max_lines

    # Height fits content exactly, capped at CANVAS_H.
    content_h = line_h * len(visible) + MARGIN_Y * 2
    if truncated:
        content_h += line_h          # extra row for the footer
    height = min(content_h, CANVAS_H)

    img  = Image.new("RGB", (CANVAS_W, height), BG)
    draw = ImageDraw.Draw(img)

    y = MARGIN_Y
    for ln in visible:
        draw.text((MARGIN_X, y), ln, font=font, fill=line_color(ln))
        y += line_h

    if truncated:
        draw.text((MARGIN_X, y), f"... +{overflow} more lines", font=font, fill=GRAY)

    img.save(png_path, optimize=True)
    return [png_path]


def main():
    if len(sys.argv) < 2:
        print("usage: txt_to_img.py <file.txt|dir> [out.png]")
        sys.exit(2)
    target = sys.argv[1]
    if os.path.isdir(target):
        out_dir = os.path.join(target, "images")
        os.makedirs(out_dir, exist_ok=True)
        n = 0
        for fn in sorted(os.listdir(target)):
            if fn.endswith(".txt"):
                try:
                    paths = render(os.path.join(target, fn),
                                   os.path.join(out_dir, fn[:-4] + ".png"))
                    n += len(paths)
                except Exception as e:
                    sys.stderr.write("skip %s: %s\n" % (fn, e))
        print("rendered %d images to %s" % (n, out_dir))
    else:
        out = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(target)[0] + ".png"
        paths = render(target, out)
        for p in paths:
            print(p)


if __name__ == "__main__":
    main()
