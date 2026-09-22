"""Boot sequence and access gate for the interactive control centre.

The intro is a short, wall-clock scheduled animation: slow devices drop frames
instead of stretching the sequence, and Enter skips it. Only the visible screen
is redrawn (cursor home + erase-to-end), never scrollback, alternate screen or
cursor visibility. The password is read without echo, compared in constant
time against a PBKDF2 digest and never written anywhere. No network is used.
"""

import getpass
import hashlib
import hmac
import io
import pkgutil
import platform
import select
import sys
import time
import warnings

from . import __path__ as PACKAGE_PATH, __version__
from .terminal_app import LeaveUI
from .terminal_art import gradient
from .terminal_ui import REVEAL_EDGE, Span, row, wrap_text

# Regenerate after choosing a new password:
#   python3 -c "from draxen.gate import digest; print(digest('yeni-şifre'))"
PASSWORD_DIGEST = "32ebfb393b4540054ac00463105bc322b855658950d883d944839eae9ba61ecf"
SALT = b"szobo-draxen/gate/v1"
ITERATIONS = 60_000
MAX_ATTEMPTS = 3

FPS = 12
CHECKS_SECONDS = 1.1
REVEAL_SECONDS = 1.1
HOLD_SECONDS = 0.35
GRANTED_SECONDS = 0.7
DENIED_SECONDS = 1.0  # Multiplied by the failed attempt number.

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ASCII_SPINNER = "|/-\\"


def digest(secret):
    return hashlib.pbkdf2_hmac("sha256", str(secret).encode("utf-8"), SALT, ITERATIONS).hex()


def verify(secret):
    if not isinstance(secret, str) or not secret:
        return False
    return hmac.compare_digest(digest(secret), PASSWORD_DIGEST)


def read_secret(prompt, stream=None):
    """Hidden line input on the controlling terminal (or stdin as a fallback)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", getpass.GetPassWarning)
        return getpass.getpass(prompt, stream=stream)


def ease_out(t):
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


def system_checks(console):
    """Real local facts for the boot log; nothing is probed or invented."""
    modules = sum(1 for _ in pkgutil.iter_modules(PACKAGE_PATH))
    system = " ".join(part for part in (platform.system(), platform.machine()) if part) or "POSIX"
    if not console.color:
        depth = "renksiz"
    else:
        depth = {24: "truecolor", 256: "256 renk"}.get(console.depth, "16 renk")
    terminal = [f"{console.width}×{console.height}", depth] + (["ASCII"] if console.ascii else [])
    # Detail parts are joined with " / " as far as the row has room for them.
    return [
        ("ÇEKİRDEK", [system, "Python " + platform.python_version()], "HAZIR", "green"),
        ("TERMİNAL", terminal, "HAZIR", "green"),
        ("MODÜLLER", [f"{modules} modül", "v" + __version__], "HAZIR", "green"),
        ("AĞ", ["açılışta istek yok"], "PASİF", "amber"),
    ]


def fit_parts(parts, room, ascii_only=False):
    """Join as many " / " separated parts as fit; clip the first one if needed."""
    shown = ""
    for part in parts:
        candidate = part if not shown else shown + " / " + part
        if len(candidate) > room:
            break
        shown = candidate
    if not shown and parts and room > 0:
        marker = "." if ascii_only else "…"
        shown = parts[0][:max(0, room - len(marker))].rstrip() + marker
    return shown


class AccessGate:
    """Intro animation followed by the password prompt of the control centre."""

    def __init__(self, console, *, sleep=time.sleep, clock=time.monotonic, secret_reader=None, stdin=None):
        self.console = console
        self.sleep = sleep
        self.clock = clock
        self.secret_reader = secret_reader or read_secret
        self.stdin = sys.stdin if stdin is None else stdin
        self.checks = system_checks(console)

    # -- flow -----------------------------------------------------------------

    def run(self):
        """True when unlocked, False when locked out or the input ended."""
        console = self.console
        try:
            pending = self._intro()
            for attempt in range(1, MAX_ATTEMPTS + 1):
                if pending:
                    # A line typed during the intro counts as the first attempt.
                    secret, pending = pending, None
                else:
                    self._draw(self.frame("prompt", attempt=attempt))
                    try:
                        secret = self.secret_reader(self.prompt_text(), console.stream)
                    except EOFError:
                        console.emit()
                        console.emit([console.line(row("Oturum kapatıldı; şifre girilmedi.", "muted"))])
                        return False
                if verify(secret.strip()):
                    self._play(GRANTED_SECONDS, lambda t: self.frame("granted", t, attempt), skippable=False)
                    return True
                if attempt == MAX_ATTEMPTS:
                    self._draw(self.frame("locked", attempt=attempt))
                    console.emit()
                    return False
                self._draw(self.frame("denied", attempt=attempt))
                self.sleep(DENIED_SECONDS * attempt)
            return False
        except KeyboardInterrupt as exc:
            console.emit()
            raise LeaveUI(130) from exc

    def _intro(self):
        """Boot log, then the wordmark sweep. Returns any line typed to skip."""
        self.console.clear_view()
        typed = self._play(CHECKS_SECONDS, lambda t: self.frame("checks", t))
        if typed is None:
            typed = self._play(REVEAL_SECONDS, lambda t: self.frame("reveal", t))
        if typed is None:
            typed = self._play(HOLD_SECONDS, lambda t: self.frame("reveal", 1.0))
        return (typed or "").strip()

    def _play(self, duration, render, *, skippable=True):
        """Draw render(t), t in 0..1, on a wall-clock schedule.

        Returns None when the sequence finished, otherwise the line that
        interrupted it ("" for a bare Enter). Frames are dropped when the
        terminal is slower than FPS; the total time never stretches.
        """
        start = self.clock()
        previous = None
        while True:
            elapsed = self.clock() - start
            t = 1.0 if duration <= 0 else min(1.0, elapsed / duration)
            lines = render(t)
            if lines != previous:  # Identical frames (e.g. the hold) cost nothing on slow terminals.
                self._draw(lines)
                previous = lines
            if t >= 1.0:
                return None
            typed = self._pause(1 / FPS, skippable)
            if typed is not None:
                self._draw(render(1.0))
                return typed

    def _pause(self, seconds, skippable=True):
        """Wait one frame; a pending Enter on stdin ends the animation."""
        if not skippable:
            self.sleep(seconds)
            return None
        try:
            ready, _, _ = select.select([self.stdin], [], [], seconds)
        except (OSError, ValueError, TypeError, io.UnsupportedOperation):
            self.sleep(seconds)
            return None
        if not ready:
            return None
        line = self.stdin.readline()
        if not line:  # EOF: nothing to skip with, keep playing.
            self.sleep(seconds)
            return None
        return line.rstrip("\r\n")

    def _draw(self, lines):
        stream = self.console.stream
        stream.write("\x1b[H" + "".join(line + "\x1b[K\n" for line in lines) + "\x1b[J")
        stream.flush()

    # -- frames ---------------------------------------------------------------

    def prompt_text(self):
        return self.console.line([Span("› ", "green", True), Span("Şifre > ", "cyan")])

    def frame(self, stage, t=1.0, attempt=1):
        """One complete screen for a stage; always fits width - 1 × height - 2."""
        console = self.console
        width, height = console.width, console.height
        if width < 20 or height < 12:
            message = "SZOBO / DRAXEN / Terminali büyütün (21 kolon, 12 satır)."
            return [console.line(row(part, "cyan")) for part in wrap_text(console.text(message), width)][:max(1, height - 2)]
        panel = self._panel(stage, t, attempt)
        hint = []
        if stage in ("checks", "reveal") and t < 1.0:
            hint = [console.line(row("Enter: animasyonu atla", "muted"))]
        budget = max(1, height - 2 - len(panel) - len(hint))
        # The sweep starts with its bright edge just off the left side and ends
        # with it past the right side, so the last frame equals the static banner.
        if stage == "checks":
            reveal, shimmer = -REVEAL_EDGE, int(t * 24)
        elif stage == "reveal":
            reveal, shimmer = -REVEAL_EDGE + (1 + 2 * REVEAL_EDGE) * ease_out(t), 24 + int(t * 24)
        else:
            reveal, shimmer = None, 0
        banner = console.banner_lines(max_height=budget, status=True, reveal=reveal, shimmer=shimmer)
        return (banner + panel + hint)[:max(1, height - 2)]

    def _panel(self, stage, t, attempt):
        console = self.console
        inner = console.content_width()
        total = str(MAX_ATTEMPTS)
        if stage in ("checks", "reveal"):
            done = stage == "reveal"
            badge = "HAZIR" if done else "BAŞLATILIYOR"
            return console.panel("SİSTEM", self._check_rows(1.0 if done else t, inner), badge=badge,
                                 tone="green" if done else "cyan")
        if stage == "prompt":
            rows = console.paragraph("Bu konsol şifre korumalıdır.", inner)
            rows += console.paragraph("Şifre yazarken ekranda görünmez.", inner, "muted")
            rows.append(row())
            rows += console.paragraph("Enter: onayla / Ctrl+C: çık", inner, "muted")
            return console.panel("ERİŞİM KONTROLÜ", rows, badge=f"{attempt}/{total}", tone="cyan")
        if stage == "denied":
            remaining = MAX_ATTEMPTS - attempt
            rows = console.paragraph("Şifre hatalı.", inner, "red")
            rows += console.paragraph(f"Kalan deneme: {remaining}", inner)
            rows.append(row())
            rows += console.paragraph(f"{DENIED_SECONDS * attempt:g} sn bekleyin…", inner, "muted")
            return console.panel("ERİŞİM REDDEDİLDİ", rows, badge=f"{attempt}/{total}", tone="red")
        if stage == "locked":
            rows = console.paragraph(f"{MAX_ATTEMPTS} hatalı deneme.", inner, "red")
            rows += console.paragraph("Oturum kapatıldı.", inner)
            rows.append(row())
            rows += console.paragraph("Yeniden denemek için: sh start.sh", inner, "muted")
            return console.panel("KİLİTLENDİ", rows, badge=f"{total}/{total}", tone="red")
        rows = console.paragraph("Kimlik doğrulandı.", inner, "green")
        rows += console.paragraph("Kontrol merkezi açılıyor", inner)
        rows.append(row())
        rows.append(self._sweep(t, inner))
        return console.panel("ERİŞİM ONAYLANDI", rows, badge="OK", tone="green")

    def _check_rows(self, t, inner):
        console = self.console
        spinner = ASCII_SPINNER if console.ascii else SPINNER
        label_width = max(len(label) for label, _, _, _ in self.checks) + 2
        status_width = max(len(status) for _, _, status, _ in self.checks)
        show_status = inner >= label_width + status_width + 4
        show_detail = inner >= label_width + status_width + 16
        rows = []
        for index, (label, detail, status, tone) in enumerate(self.checks):
            start = index * 0.19
            progress = (t - start) / 0.22
            if progress < 0:
                glyph, glyph_tone, label_tone, state, state_tone = " ", "muted", "muted", "", "muted"
            elif progress < 1:
                glyph = spinner[int(t * 60) % len(spinner)]
                glyph_tone, label_tone, state, state_tone = "cyan", "text", "..." if console.ascii else "…", "muted"
            else:
                glyph, glyph_tone, label_tone, state, state_tone = "●", tone, "text", status, tone
            spans = [Span(glyph + " ", glyph_tone, True), Span(label.ljust(label_width), label_tone)]
            room = inner - 2 - label_width - (status_width + 1 if show_status else 0)
            if show_detail and progress >= 0 and room > 0:
                shown = fit_parts([console.text(part) for part in detail], room, console.ascii)
                spans.append(Span(shown.ljust(room), "muted"))
            elif show_status:
                spans.append(Span(" " * max(0, room), "muted"))
            if show_status:
                spans.append(Span(" " + state.rjust(status_width), state_tone, progress >= 1))
            rows.append(spans)
        return rows

    def _sweep(self, t, inner):
        """A decorative light pass, not a progress percentage."""
        cells = max(4, inner)
        head = int(round(t * (cells + 3))) - 2
        pieces = []
        for x in range(cells):
            distance = abs(x - head)
            char = "█" if distance == 0 else "▒" if distance == 1 else "░"
            color = gradient(x / max(1, cells - 1))
            if distance > 1:
                color = tuple(round(channel * 0.36) for channel in color)
            pieces.append(Span(char, "green" if distance <= 1 else "border", distance == 0, color))
        return pieces
