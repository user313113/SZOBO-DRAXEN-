"""Small built-in block fonts. No figlet executable, font download or image API.

The large face has solid strokes and a separate outlined extrusion. Narrow
phones get full-height pixel letters, never a squashed three-row wordmark.
"""

from dataclasses import dataclass


SHADOW_FONT = {
    "S": ("███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"),
    "Z": ("███████╗", "╚══███╔╝", "  ███╔╝ ", " ███╔╝  ", "███████╗", "╚══════╝"),
    "O": (" █████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "╚█████╔╝", " ╚════╝ "),
    "B": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "),
    "D": ("██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "),
    "R": ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    "A": (" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"),
    "X": ("██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"),
    "E": ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    "N": ("███╗ ██╗", "████╗██║", "██╔████║", "██║╚███║", "██║ ╚██║", "╚═╝  ╚═╝"),
    "/": ("    ██╗", "   ██╔╝", "  ██╔╝ ", " ██╔╝  ", "██╔╝   ", "╚═╝    "),
}
PIXEL_FONT = {
    "S": ("1111", "1000", "1111", "0001", "1111"),
    "Z": ("1111", "0001", "0110", "1000", "1111"),
    "O": ("0110", "1001", "1001", "1001", "0110"),
    "B": ("1110", "1001", "1110", "1001", "1110"),
    "D": ("1110", "1001", "1001", "1001", "1110"),
    "R": ("1110", "1001", "1110", "1010", "1001"),
    "A": ("0110", "1001", "1111", "1001", "1001"),
    "X": ("1001", "1001", "0110", "1001", "1001"),
    "E": ("1111", "1000", "1110", "1000", "1111"),
    "N": ("1001", "1101", "1011", "1001", "1001"),
}
MICRO_FONT = {
    "S": ("111", "100", "111", "001", "111"),
    "Z": ("111", "001", "010", "100", "111"),
    "O": ("111", "101", "101", "101", "111"),
    "B": ("110", "101", "110", "101", "110"),
    "D": ("110", "101", "101", "101", "110"),
    "R": ("110", "101", "110", "101", "101"),
    "A": ("010", "101", "111", "101", "101"),
    "X": ("101", "101", "010", "101", "101"),
    "E": ("111", "100", "110", "100", "111"),
    "N": ("101", "111", "111", "111", "101"),
}


@dataclass(frozen=True)
class Wordmark:
    lines: tuple
    style: str

    @property
    def width(self):
        return max(map(len, self.lines), default=0)


def _shadow_word(word):
    return tuple(" ".join(SHADOW_FONT[letter][y] for letter in word) for y in range(6))


def _pixel_word(word, font):
    face = [" ".join("".join("█" if bit == "1" else " " for bit in font[letter][y])
                     for letter in word) for y in range(5)]
    # A one-cell down/right extrusion. Face always wins over its shadow.
    width = len(face[0]) + 1
    rows = [list(line.ljust(width)) for line in face] + [list(" " * width)]
    for y, line in enumerate(face):
        for x, char in enumerate(line):
            if char == "█" and rows[y + 1][x + 1] == " ":
                rows[y + 1][x + 1] = "░"
    return tuple("".join(line) for line in rows)


def _stack(first, second):
    width = max(len(first[0]), len(second[0]))
    return tuple(line.center(width) for line in first) + ("/".center(width),) + tuple(line.center(width) for line in second)


def wordmark(width, height, full=True):
    """Pick complete, legible words; never crop a letter to fit the viewport."""
    if width <= 0 or height <= 0:
        return Wordmark((), "none")
    szobo, draxen = _shadow_word("SZOBO"), _shadow_word("DRAXEN")
    combined = tuple(a + "   " + slash + "   " + b for a, slash, b in zip(szobo, SHADOW_FONT["/"], draxen))
    candidates = []
    if full:
        candidates.extend([(combined, "shadow-inline"), (_stack(szobo, draxen), "shadow-stacked")])
        for font, name in ((PIXEL_FONT, "pixel"), (MICRO_FONT, "micro")):
            candidates.append((_stack(_pixel_word("SZOBO", font), _pixel_word("DRAXEN", font)), name + "-stacked"))
    candidates.append((draxen, "shadow-compact"))
    candidates.extend((_pixel_word("DRAXEN", font), name + "-compact")
                      for font, name in ((PIXEL_FONT, "pixel"), (MICRO_FONT, "micro")))
    for lines, style in candidates:
        if len(lines) <= height and max(map(len, lines)) <= width:
            return Wordmark(tuple(lines), style)
    if width >= len("SZOBO / DRAXEN"):
        return Wordmark(("SZOBO / DRAXEN",), "text")
    return Wordmark((), "none")


def gradient(position):
    """Reference palette: ultraviolet → electric blue → cyan → mint green."""
    stops = ((151, 94, 255), (50, 128, 255), (0, 196, 239), (0, 239, 160))
    position = max(0.0, min(1.0, position)) * (len(stops) - 1)
    index = min(len(stops) - 2, int(position))
    fraction = position - index
    return tuple(round(a + (b - a) * fraction) for a, b in zip(stops[index], stops[index + 1]))
