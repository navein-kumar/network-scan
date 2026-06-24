#!/usr/bin/env python3
#
# txt_to_img.py: render a nuclei-style evidence .txt as a dark terminal-style
# PNG so the evidence can be pasted straight into a report.
#
# Usage:
#   txt_to_img.py <file.txt> [out.png]   render one file
#   txt_to_img.py <dir>                  render every *.txt in <dir> into
#                                        <dir>/images/<name>.png
#
import os
import sys

from PIL import Image, ImageDraw, ImageFont

# Background and per-line colors (GitHub-dark-ish palette).
BG = (13, 17, 23)
FG = (201, 209, 217)
GREEN = (63, 185, 80)
BLUE = (121, 192, 255)
RED = (248, 81, 73)
GRAY = (139, 148, 158)
ORANGE = (219, 109, 40)

FONT_SIZE = 15
LINE_PAD = 6
MARGIN = 16


def find_font(size):
    for p in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def line_color(line):
    upper = line.upper()
    stripped = line.lstrip()
    if "CRITICAL" in upper or "VULNERABLE" in upper or "[!]" in line:
        return RED
    if "[+]" in line:
        return GREEN
    if "[*]" in line:
        return BLUE
    if stripped.startswith("#") or "nuclei report" in line.lower() \
            or "starting nuclei" in line.lower() or line.strip() == "DONE":
        return GRAY
    if "HIGH" in upper or "MEDIUM" in upper:
        return ORANGE
    return FG


def render(txt_path, png_path):
    with open(txt_path, encoding="utf-8", errors="replace") as f:
        lines = f.read().rstrip("\n").split("\n")
    if not lines:
        lines = [""]
    font = find_font(FONT_SIZE)
    line_h = FONT_SIZE + LINE_PAD

    measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    max_w = 1
    for ln in lines:
        try:
            w = measure.textlength(ln, font=font)
        except Exception:
            w = len(ln) * (FONT_SIZE * 0.6)
        max_w = max(max_w, w)

    width = int(max_w) + MARGIN * 2
    height = line_h * len(lines) + MARGIN * 2
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)

    y = MARGIN
    for ln in lines:
        draw.text((MARGIN, y), ln, font=font, fill=line_color(ln))
        y += line_h
    img.save(png_path)
    return png_path


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
                    render(os.path.join(target, fn),
                           os.path.join(out_dir, fn[:-4] + ".png"))
                    n += 1
                except Exception as e:
                    sys.stderr.write("skip %s: %s\n" % (fn, e))
        print("rendered %d images to %s" % (n, out_dir))
    else:
        out = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(target)[0] + ".png"
        render(target, out)
        print(out)


if __name__ == "__main__":
    main()
