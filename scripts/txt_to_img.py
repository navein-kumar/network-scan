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
import textwrap

from PIL import Image, ImageDraw, ImageFont

# Canvas dimensions — fixed width so output always looks like a terminal window.
CANVAS_WIDTH = 960
MAX_HEIGHT   = 3500   # lines per page; content exceeding this splits into _part1/_part2

# Background and per-line colours (GitHub-dark palette).
BG     = (13, 17, 23)
FG     = (201, 209, 217)
GREEN  = (63, 185, 80)
BLUE   = (121, 192, 255)
RED    = (248, 81, 73)
GRAY   = (139, 148, 158)
ORANGE = (219, 109, 40)
DIM    = (48, 54, 61)   # divider line colour

FONT_SIZE = 17
LINE_PAD  = 5
MARGIN    = 20

# Characters per line at FONT_SIZE 17 on a 960px canvas (approx 0.58 ratio).
_CHARS_PER_LINE = int((CANVAS_WIDTH - MARGIN * 2) / (FONT_SIZE * 0.58))


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


def _measure_width(draw, text, font):
    try:
        return draw.textlength(text, font=font)
    except Exception:
        return len(text) * (FONT_SIZE * 0.58)


def _expand_lines(raw_lines, font, draw):
    """Wrap any line that exceeds the canvas width."""
    out = []
    char_limit = _CHARS_PER_LINE
    for ln in raw_lines:
        if not ln.strip():
            out.append(("", FG))
            continue
        w = _measure_width(draw, ln, font)
        if w <= CANVAS_WIDTH - MARGIN * 2:
            out.append((ln, line_color(ln)))
        else:
            # Indent continuation lines by 4 spaces.
            wrapped = textwrap.wrap(ln, width=char_limit, subsequent_indent="    ")
            for i, piece in enumerate(wrapped):
                out.append((piece, line_color(ln)))
    return out


def _draw_divider(draw, y, width):
    draw.line([(MARGIN, y + 3), (width - MARGIN, y + 3)], fill=DIM, width=1)


def _render_page(lines_slice, font, line_h, width):
    """Render one page worth of (text, color) pairs to an Image."""
    height = line_h * len(lines_slice) + MARGIN * 2
    img  = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)
    y = MARGIN
    prev_blank = False
    for text, color in lines_slice:
        if text.strip() and prev_blank:
            _draw_divider(draw, y, width)
            y += 8
        if not text.strip():
            prev_blank = True
        else:
            prev_blank = False
            draw.text((MARGIN, y), text, font=font, fill=color)
        y += line_h
    return img


def render(txt_path, png_path):
    """Render txt_path to one or more PNG files.

    If the content exceeds MAX_HEIGHT pixels, the output is split into
    <basename>_part1.png, <basename>_part2.png, … and the returned list
    contains all paths written.  For single-page output the list has one
    element equal to png_path.
    """
    with open(txt_path, encoding="utf-8", errors="replace") as f:
        raw = f.read().rstrip("\n").split("\n")

    font   = find_font(FONT_SIZE)
    line_h = FONT_SIZE + LINE_PAD

    dummy = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    lines = _expand_lines(raw, font, dummy)

    width        = CANVAS_WIDTH
    lines_per_pg = (MAX_HEIGHT - MARGIN * 2) // line_h

    # Partition into pages.
    pages = [lines[i:i + lines_per_pg]
             for i in range(0, len(lines), lines_per_pg)]

    if len(pages) == 1:
        img = _render_page(pages[0], font, line_h, width)
        img.save(png_path, optimize=True)
        return [png_path]

    # Multi-page: write <stem>_part1.png, _part2.png …
    stem, ext = os.path.splitext(png_path)
    out_paths = []
    for i, page in enumerate(pages, 1):
        p = f"{stem}_part{i}{ext}"
        img = _render_page(page, font, line_h, width)
        img.save(p, optimize=True)
        out_paths.append(p)
    return out_paths


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
