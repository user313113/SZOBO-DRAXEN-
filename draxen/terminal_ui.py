"""Responsive, dependency-free terminal presentation for Termux, iSH and desktops.

Layout is calculated in terminal cells *before* applying ANSI styles. Untrusted
report text never becomes terminal markup. No alternate screen or cursor hiding
is used, so interrupted scans leave the user's terminal usable.
"""

import os
import re
import shutil
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import __version__
from .analysis import insight_level
from .terminal_art import gradient, wordmark


# CSI, OSC (including hyperlinks/clipboard), DCS and single-character escapes.
ESCAPES = re.compile(
    r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c|$)"
    r"|(?:\x1b[P^_X]|[\x90\x98\x9e\x9f])[\s\S]*?(?:\x1b\\|\x9c|$)"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|\x1b[ -/]*[@-~]"
)
ASCII_MAP = str.maketrans({
    "ı": "i", "İ": "I", "ş": "s", "Ş": "S", "ğ": "g", "Ğ": "G",
    "─": "-", "━": "-", "│": "|", "·": "/", "→": ">", "↗": ">",
    "…": "...", "–": "-", "—": "-", "“": '"', "”": '"', "’": "'",
    "█": "#", "░": ".", "▒": ":", "▀": "#", "▄": "#",
    "╔": "+", "╗": "+", "╚": "+", "╝": "+", "═": "=", "║": "|",
    "╭": "+", "╮": "+", "╰": "+", "╯": "+", "●": "o", "›": ">",
})
PALETTE = {
    "text": (221, 230, 242),
    "muted": (144, 161, 184),
    "border": (40, 111, 101),
    "edge": (39, 205, 171),
    "blue": (50, 128, 255),
    "cyan": (67, 226, 240),
    "violet": (159, 112, 255),
    "green": (36, 232, 161),
    "amber": (242, 194, 112),
    "red": (255, 128, 146),
}
ANSI16 = {
    "text": 37, "muted": 37, "border": 90, "cyan": 96,
    "violet": 95, "blue": 94, "green": 92, "edge": 36, "amber": 93, "red": 91,
}
ENTITY_LABELS = {
    "domains_subdomains": "Alan adları",
    "network_routing": "Ağ / yönlendirme",
    "mail_communication": "Posta / iletişim",
    "cloud_infrastructure": "Bulut / altyapı",
    "security_identity": "Güvenlik / kimlik",
    "registration_other": "Kayıt / diğer",
}
FINDING_LABELS = {
    "dns_a": "DNS / A", "dns_aaaa": "DNS / AAAA", "dns_ns": "DNS / NS",
    "dns_mx": "DNS / MX", "dns_txt": "DNS / TXT", "dns_cname": "DNS / CNAME",
    "dns_soa": "DNS / SOA", "dns_caa": "DNS / CAA", "domain": "Alan adı",
    "discovered_domain": "Alt alan adı", "certificate_name": "Sertifika adı",
    "nameserver": "Ad sunucusu", "registration_ldhName": "Kayıtlı alan adı",
    "registration_event": "Kayıt tarihi", "registration_status": "Kayıt durumu",
    "asn": "ASN", "asn_holder": "ASN sahibi", "bgp_prefix": "BGP öneki",
    "network_subnet": "Alt ağ", "ip_country": "Ülke", "ip_city": "Şehir",
    "datacenter_provider": "Veri merkezi", "edge_infrastructure": "Kenar / CDN",
    "tls_protocol": "TLS protokolü", "tls_certificate": "TLS sertifikası",
    "http_security_header": "HTTP güvenliği", "server_banner": "Sunucu bilgisi",
    "open_port": "Açık port", "service_banner": "Servis bilgisi",
    "email_policy": "Posta politikası", "identified_service": "Servis sağlayıcı",
    "cloud_footprint": "Bulut izi", "cookie_insecurity": "Çerez uyarısı",
    "security_directive": "Güvenlik ilkesi", "public_email": "Açık e-posta",
}


REVEAL_EDGE = 0.07  # Width of the bright leading edge while the wordmark is revealed.


def static_glyph(x, y, frame):
    """Deterministic shimmer for unrevealed logo cells; no random module state."""
    value = (x * 0x9E3779B1 + y * 0x85EBCA77 + frame * 0xC2B2AE3D) & 0xFFFFFFFF
    value ^= value >> 15
    value = (value * 0x2C1B3C6D) & 0xFFFFFFFF
    value ^= value >> 12
    value %= 100
    return "░" if value < 46 else "▒" if value < 60 else " "


def safe_text(value, ascii_only=False):
    """Remove terminal commands and bidi controls, retaining readable Unicode."""
    text = unicodedata.normalize("NFC", ESCAPES.sub("", str(value)))
    text = "".join(
        c if c.isprintable() or c == "\u200d" else " " if c.isspace() else ""
        for c in text
    )
    if ascii_only:
        text = unicodedata.normalize("NFKD", text.translate(ASCII_MAP))
        text = "".join(c for c in text if not unicodedata.combining(c))
        text = text.encode("ascii", "replace").decode("ascii")
    return text


def _pictographic(char):
    code = ord(char)
    return 0x1F000 <= code <= 0x1FAFF or 0x2300 <= code <= 0x27FF or code in (0xA9, 0xAE, 0x3030, 0x303D, 0x3297, 0x3299)


def _clusters(text):
    """Keep combining marks, emoji modifiers, flags and emoji joins together."""
    cluster = ""
    for char in text:
        code = ord(char)
        extends = (unicodedata.category(char) in ("Mn", "Me")
                   or 0x1F3FB <= code <= 0x1F3FF or char == "\u200d")
        flag_pair = (len(cluster) == 1 and 0x1F1E6 <= ord(cluster) <= 0x1F1FF
                     and 0x1F1E6 <= code <= 0x1F1FF)
        emoji_join = cluster.endswith("\u200d") and _pictographic(char) and any(_pictographic(c) for c in cluster[:-1])
        if cluster and not (extends or emoji_join or flag_pair):
            yield cluster
            cluster = ""
        cluster += char
    if cluster:
        yield cluster


def _cluster_width(cluster):
    widths = [
        2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
        for c in cluster
        if c.isprintable() and unicodedata.category(c) not in ("Mn", "Me")
        and not 0x1F3FB <= ord(c) <= 0x1F3FF
    ]
    if not widths:
        return 0
    if ("\u200d" in cluster and len(widths) > 1) or "\u20e3" in cluster:
        return max(2, max(widths))
    if "\ufe0f" in cluster and any(_pictographic(c) for c in cluster):
        return max(2, max(widths))
    if all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in cluster):
        return 2
    return sum(widths)


def cell_width(text):
    return sum(_cluster_width(c) for c in _clusters(ESCAPES.sub("", str(text))))


def clip_text(text, width, marker=""):
    """Clip plain text without splitting a terminal cell or combining sequence."""
    width = max(0, width)
    if cell_width(text) <= width:
        return text
    if cell_width(marker) > width:
        marker = ""
    available = width - cell_width(marker)
    result = []
    for cluster in _clusters(text):
        size = _cluster_width(cluster)
        if size > available:
            break
        result.append(cluster)
        available -= size
    return "".join(result).rstrip() + marker


def wrap_text(text, width):
    """Word wrapping with safe hard breaks for URLs, hashes and CJK text."""
    width = max(1, width)
    lines, current = [], ""
    for word in str(text).split():
        if current and cell_width(current) + 1 + cell_width(word) <= width:
            current += " " + word
            continue
        if current:
            lines.append(current)
            current = ""
        chunk, used = "", 0
        for cluster in _clusters(word):
            size = _cluster_width(cluster)
            # A double-width glyph cannot fit in a one-cell viewport.
            if size > width:
                cluster, size = "?", 1
            if used + size > width:
                lines.append(chunk)
                chunk, used = "", 0
            chunk += cluster
            used += size
        current = chunk
    if current or not lines:
        lines.append(current)
    return lines


def terminal_size(stream):
    """Query the destination FD, not the unrelated controlling stdout."""
    try:
        size = os.get_terminal_size(stream.fileno())
        if size.columns > 0 and size.lines > 0:
            return size
    except (AttributeError, OSError, ValueError):
        pass

    def positive_env(name, default):
        try:
            return max(1, int(os.environ.get(name, default)))
        except ValueError:
            return default

    return os.terminal_size((positive_env("COLUMNS", 80), positive_env("LINES", 30)))


@dataclass(frozen=True)
class Span:
    text: str
    role: str = "text"
    bold: bool = False
    rgb: tuple = None  # Optional explicit colour; the role still drives 16-colour output.


def row(text="", role="text", bold=False):
    return [Span(str(text), role, bold)]


class TerminalUI:
    def __init__(self, stream=None, *, color="auto", ascii_only=False, plain=False, width=None):
        self.stream = sys.stdout if stream is None else stream
        self.requested_width = width
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        term = os.environ.get("TERM", "").lower()
        self.plain = plain or term == "dumb"
        encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            "╭─█▀ğİ".encode(encoding)
            unicode_ok = True
        except (UnicodeError, LookupError):
            unicode_ok = False
        self.ascii = ascii_only or not unicode_ok or self.plain
        self.decorated = not self.plain and (self.tty or color == "always")
        self.color = not self.plain and color != "never" and (
            color == "always" or (self.tty and "NO_COLOR" not in os.environ)
        )
        colorterm = os.environ.get("COLORTERM", "").lower()
        self.depth = (24 if colorterm in ("truecolor", "24bit") or "direct" in term
                      else 256 if "256" in term else 16)

    @property
    def width(self):
        columns = terminal_size(self.stream).columns
        # Reserve the last TTY cell; writing there can trigger automatic wrapping.
        available = max(1, columns - (1 if self.tty else 0))
        requested = self.requested_width or 120
        if self.tty:
            return max(1, min(available, requested, 160))
        return max(1, min(self.requested_width or available, 160))

    @property
    def height(self):
        return terminal_size(self.stream).lines

    def text(self, value):
        return safe_text(value, self.ascii)

    def _paint(self, text, role="text", bold=False, rgb=None):
        if not self.color or not text or text.isspace():
            return text
        if self.depth == 24:
            r, g, b = rgb or PALETTE[role]
            code = f"38;2;{r};{g};{b}"
        elif self.depth == 256:
            color = rgb or PALETTE[role]
            levels = (0, 95, 135, 175, 215, 255)
            indices = [min(range(6), key=lambda i: abs(levels[i] - channel)) for channel in color]
            cube = 16 + 36 * indices[0] + 6 * indices[1] + indices[2]
            gray = max(0, min(23, round((sum(color) / 3 - 8) / 10)))
            cube_error = sum((channel - levels[index]) ** 2 for channel, index in zip(color, indices))
            gray_error = sum((channel - (8 + gray * 10)) ** 2 for channel in color)
            code = "38;5;" + str(232 + gray if gray_error < cube_error else cube)
        else:
            code = str(ANSI16[role])
        return f"\x1b[{'1;' if bold else ''}{code}m{text}\x1b[0m"

    def line(self, spans, width=None, pad=False, center=False):
        width = self.width if width is None else max(0, width)
        size = sum(cell_width(self.text(s.text)) for s in spans)
        leading = max(0, (width - size) // 2) if center else 0
        result, remaining = [" " * leading], width - leading
        for span in spans:
            text = clip_text(self.text(span.text), remaining)
            result.append(self._paint(text, span.role, span.bold, span.rgb))
            remaining -= cell_width(text)
        if pad:
            result.append(" " * remaining)
        return "".join(result)

    def paragraph(self, value, width, role="text", prefix="", limit=None):
        prefix = clip_text(self.text(prefix), max(0, width - 1))
        lines = wrap_text(self.text(value), max(1, width - cell_width(prefix)))
        if limit and len(lines) > limit:
            lines = lines[:limit]
            marker = "..." if self.ascii else "…"
            lines[-1] = clip_text(lines[-1] + marker, width - cell_width(prefix), marker)
        return [[Span(prefix if index == 0 else " " * cell_width(prefix), "muted"), Span(line, role)]
                for index, line in enumerate(lines)]

    def fields(self, fields, width):
        label_width = min(10, max((cell_width(self.text(k)) for k, _ in fields), default=0))
        lines = []
        for key, value in fields:
            if width < 26:
                lines.extend(self.paragraph(key, width, "muted"))
                lines.extend(self.paragraph(value, width, "text"))
            else:
                label = clip_text(self.text(key), label_width)
                parts = wrap_text(self.text(value), max(1, width - label_width - 2))
                for i, part in enumerate(parts):
                    left = label if i == 0 else ""
                    lines.append([Span(left + " " * (label_width - cell_width(left) + 2), "muted"), Span(part)])
        return lines

    def panel(self, title, rows, *, width=None, badge="", tone="cyan", border="single"):
        width = self.width if width is None else width
        if not self.decorated or width < 16:
            lines = [self.line(row(line, tone, True), width) for line in wrap_text(self.text(title), width)]
            if badge:
                lines.extend(self.line(row(line, tone), width) for line in wrap_text(self.text(badge), width))
            for spans in rows:
                # Plain output is reflowed without borders or alignment padding.
                value = "".join(self.text(s.text) for s in spans).rstrip()
                lines.extend(self.line(row(line), width) for line in wrap_text(value, width))
            return lines
        edge_role = "edge" if border == "double" else "border"
        if self.ascii:
            tl, tr, bl, br, vertical, horizontal = "+", "+", "+", "+", "|", "=" if border == "double" else "-"
        elif border == "double":
            tl, tr, bl, br, vertical, horizontal = "╔", "╗", "╚", "╝", "║", "═"
        else:
            tl, tr, bl, br, vertical, horizontal = "╭", "╮", "╰", "╯", "│", "─"
        title = clip_text(self.text(title), width - 6, "..." if self.ascii else "…")
        badge = self.text(badge)
        free = width - cell_width(title) - cell_width(badge) - 8
        right = " " + badge + " " if badge and free >= 1 else ""
        head = horizontal + " " + title + " "
        fill = width - 2 - cell_width(head) - cell_width(right)
        top = (self._paint(tl + horizontal + " ", edge_role) + self._paint(title, tone, True)
               + self._paint(" " + horizontal * max(0, fill), edge_role)
               + self._paint(right, tone) + self._paint(tr, edge_role))
        edge = self._paint(vertical, edge_role)
        body = [edge + " " + self.line(spans, width - 4, pad=True) + " " + edge for spans in rows]
        return [top] + body + [self._paint(bl + horizontal * (width - 2) + br, edge_role)]

    def emit(self, lines=()):
        text = "\n".join(lines) + "\n"
        self.stream.write(text)
        self.stream.flush()

    def show_panel(self, title, rows, **kwargs):
        self.emit(self.panel(title, rows, **kwargs))

    def content_width(self, width=None):
        width = self.width if width is None else width
        return max(1, width - 4 if self.decorated and width >= 16 else width)

    def _system_line(self):
        try:
            total, used, _ = shutil.disk_usage(Path.cwd())
            disk = f"Disk {used * 100 // max(total, 1)}% / {used / 1024**3:.0f}G:{total / 1024**3:.0f}G"
        except OSError:
            disk = "Yerel terminal"
        if self.width < 48:
            disk = "OSINT / YEREL KONSOL"
        return self.line([Span("› ", "text"), Span("●", "red"), Span("●", "amber"),
                          Span("●  ", "cyan"), Span(disk, "green")])

    def banner_lines(self, *, demo=False, max_height=None, status=False, full=True, reveal=None, shimmer=0):
        """A real ANSI wordmark; height and width are both part of the layout.

        ``reveal`` (0.0 to 1 + REVEAL_EDGE) draws the wordmark partially: cells
        past the sweep show a dim shimmer of the final silhouette, cells at the
        edge glow, cells behind it are final. ``None`` renders the static banner.
        """
        budget = max(1, max_height if max_height is not None else min(20, max(1, self.height - 3)))
        inner = self.content_width()
        if not self.decorated or self.width < 20 or budget < 3:
            text = "SZOBO / DRAXEN" + (" / DEMO" if demo else " / v" + __version__)
            return [self.line(row(part, "cyan", True)) for part in wrap_text(self.text(text), self.width)][:budget]
        status = status and budget >= 10
        overhead = 2 + (2 if status else 0)
        art = wordmark(inner, max(0, budget - overhead), full=full)
        padding = 1 if len(art.lines) + overhead + 2 <= budget and art.lines else 0
        body = [row()] * (len(art.lines) + padding * 2)
        lines = self.panel("SZOBO / DRAXEN", body, badge="DEMO" if demo else "v" + __version__, tone="green", border="double")
        edge = self._paint("|" if self.ascii else "║", "edge")
        left = max(0, (inner - art.width) // 2)
        roles = ("violet", "blue", "cyan", "green")
        revealing = reveal is not None and reveal < 1 + REVEAL_EDGE
        for y, text in enumerate(art.lines):
            pieces = []
            for x, char in enumerate(text):
                position = x / max(1, art.width - 1)
                color = gradient(position)
                role = roles[min(3, int(position * 4))]
                bold = char == "█"
                if char == "░":
                    color = tuple(round(channel * 0.43) for channel in color)
                    role = "border"
                elif char not in ("█", " "):
                    color = tuple(round(channel * 0.76) for channel in color)
                if revealing and char != " " and position > reveal - REVEAL_EDGE:
                    if position > reveal:
                        char = static_glyph(x, y, shimmer)
                        color = tuple(round(channel * 0.36) for channel in color)
                        role, bold = "border", False
                    else:
                        color, role, bold = (236, 246, 255), "text", True
                pieces.append(self._paint(self.text(char), role, bold=bold, rgb=color))
            lines[1 + padding + y] = edge + " " + " " * left + "".join(pieces) + " " * (inner - left - len(text)) + " " + edge
        if status:
            clock = datetime.now().astimezone().strftime("%H:%M:%S / %d.%m.%Y")
            lines = [self._system_line()] + lines + [self.line(row(clock, "green"))]
        return lines[:budget]

    def banner(self, demo=False, **kwargs):
        self.emit(self.banner_lines(demo=demo, **kwargs))

    def home_lines(self, *, interactive=False):
        """One opening screen, not a help dump that scrolls the logo away."""
        width, height = self.width, self.height
        inner = self.content_width()
        if width < 20 or height < 12:
            message = "SZOBO / DRAXEN / Menü için terminali büyütün (21 kolon, 12 satır). --help"
            return [self.line(row(line, "cyan")) for line in wrap_text(self.text(message), width)][:max(1, height - 2)]
        compact = inner < 56
        labels = (["01 KEŞİF", "02 DERİN", "03 META", "04 DEMO", "05 ARAÇLAR", "H YARDIM", "Q ÇIKIŞ"] if compact else
                  ["01  Standart keşif", "02  Derin analiz", "03  Yerel meta veri", "04  Çevrimdışı demo", "05  Test araçları", "H   Tüm komutlar", "Q   Çıkış"])
        rows = []
        if inner >= 19:
            column = (inner - 2) // 2
            # Index pairing: an odd label count keeps its last row instead of
            # being silently dropped by zip.
            for index in range(0, len(labels), 2):
                first = self.text(labels[index])
                second = labels[index + 1] if index + 1 < len(labels) else ""
                rows.append([Span(first + " " * max(2, column + 2 - cell_width(first)), "cyan"), Span(second, "green")])
        else:
            for label in labels:
                rows.extend(self.paragraph(label, inner, "cyan"))
        menu = self.panel("KONTROL MERKEZİ", rows)
        hint = "Başlat: python -m draxen --ui"
        hint_lines = [] if interactive else [self.line(row(line, "muted")) for line in wrap_text(self.text(hint), width)]
        available = max(1, height - 2 - len(menu) - len(hint_lines))
        return (self.banner_lines(max_height=available, status=True) + menu + hint_lines)[:max(1, height - 2)]

    def home(self, *, interactive=False):
        self.emit(self.home_lines(interactive=interactive))

    def clear_view(self):
        # Clear only the visible screen, never the user's scrollback or settings.
        if self.tty and not self.plain:
            self.stream.write("\x1b[H\x1b[2J")
            self.stream.flush()

    def scan_start(self, target, settings, *, clear=False):
        if clear:
            self.clear_view()
        if not self.decorated:
            self.emit([self.line(row("SZOBO | DRAXEN / v" + __version__, "cyan", True))])
            self.show_panel("GÖREV", self.fields([("Hedef", target.value)], self.content_width()))
            return
        inner = self.content_width()
        modules = ["DNS", "RDAP", "CT"] if target.domain else ["RDAP", "PTR"]
        for key, label in (("archives", "Arşiv"), ("network", "Ağ"), ("mail", "Posta"),
                           ("security", "Güvenlik"), ("infra", "Altyapı"), ("sitemap", "Sitemap"),
                           ("brute", "Alt alan"), ("ports", "Port"), ("web", "Web"), ("verify", "DNS kontrolü")):
            if settings.get(key):
                modules.append(label)
        fields = [("HEDEF", target.value), ("MODÜLLER", " / ".join(modules)),
                  ("SINIRLAR", f"{settings['budget']} HTTP / {settings['delay']:g} sn / {settings['timeout']:g} sn zaman aşımı")]
        value_width = max(1, inner - 10) if inner >= 26 else inner
        previews = []
        for label, value in fields:
            parts = wrap_text(self.text(value), value_width)
            if len(parts) > 2:
                parts = parts[:2]
                marker = "..." if self.ascii else "…"
                parts[-1] = clip_text(parts[-1] + marker, value_width, marker)
            previews.append((label, " ".join(parts)))
        rows = self.fields(previews, inner)
        rows.extend(self.paragraph("Ctrl+C: kısmi raporu kaydet", inner, "muted"))
        task = self.panel("GÖREV", rows, badge="BAŞLIYOR")
        if len(task) > self.height - 4:
            rows = self.paragraph(target.value, inner, "cyan", limit=1)
            rows.extend(self.paragraph(f"{len(modules)} modül / {settings['budget']} HTTP", inner, limit=1))
            rows.extend(self.paragraph("Ctrl+C: kısmi kayıt", inner, "muted", limit=1))
            task = self.panel("GÖREV", rows)
        self.banner(max_height=max(1, self.height - len(task) - 2))
        self.emit(task)

    def metrics(self, data):
        entries = [("BULGU", len(data.get("findings", [])), "cyan"),
                   ("KAYNAK", len(data.get("sources", [])), "violet"),
                   ("HTTP" if self.width < 40 else "HTTP İSTEĞİ", data.get("requests", 0), "cyan"),
                   ("OLAY", len(data.get("timeline", [])), "violet")]
        if not self.decorated or self.width < 34:
            self.show_panel("SAYAÇLAR", self.fields([(label, str(value)) for label, value, _ in entries], self.content_width()))
            return
        columns = 4 if self.width >= 76 else 2
        card_width = (self.width - (columns - 1)) // columns
        for offset in range(0, len(entries), columns):
            cards = []
            for index, (label, value, tone) in enumerate(entries[offset:offset + columns]):
                width = card_width + (self.width - (card_width * columns + columns - 1) if index == columns - 1 else 0)
                cards.append(self.panel(label, self.paragraph(str(value), width - 4, tone), width=width, tone=tone))
            self.emit([" ".join(lines) for lines in zip(*cards)])

    def _source_rows(self, data, width):
        rows = []
        sources = data.get("sources", [])
        limit = 6 if self.height < 32 else 8
        for source in sources[:limit]:
            ok = source.get("state") == "ok"
            status = "OK" if ok else "EKSİK"
            tone = "green" if ok else "amber"
            name = source.get("name", "Kaynak")
            value = f"{name} / +{source.get('new_findings', 0)}"
            rows.extend(self.paragraph(value, width, tone, prefix=f"{status}  "))
            if source.get("message"):
                rows.extend(self.paragraph(source["message"], width, "muted", prefix="  ", limit=2))
        if len(sources) > limit:
            rows.extend(self.paragraph(f"+{len(sources) - limit} kaynak daha raporda.", width, "muted"))
        if not sources:
            rows.extend(self.paragraph("Henüz kaynak sonucu yok.", width, "muted"))
        return rows

    def _entity_rows(self, data, width):
        counts = data.get("analysis", {}).get("entity_counts", {})
        if not counts:
            return self.paragraph("Varlık dağılımı için veri yok.", width, "muted")
        rows = []
        maximum = max(counts.values(), default=1) or 1
        for category, count in counts.items():
            label = self.text(ENTITY_LABELS.get(category, category))
            count_text = str(count)
            if width < 22:
                rows.extend(self.paragraph(f"{label}: {count_text}", width, "muted"))
            else:
                label = clip_text(label, width - len(count_text) - 1)
                gap = " " * max(1, width - cell_width(label) - len(count_text))
                rows.append([Span(label + gap, "muted"), Span(count_text, "violet", True)])
            if self.decorated:
                length = min(width, 26)
                filled = round(length * count / maximum)
                rows.append([Span(("#" if self.ascii else "█") * filled, "cyan"),
                             Span(("." if self.ascii else "░") * (length - filled), "border")])
        return rows

    def sources_and_entities(self, data):
        if self.decorated and self.width >= 94:
            left_width = (self.width - 2) * 3 // 5
            right_width = self.width - 2 - left_width
            left = self._source_rows(data, self.content_width(left_width))
            right = self._entity_rows(data, self.content_width(right_width))
            height = max(len(left), len(right))
            left += [row()] * (height - len(left))
            right += [row()] * (height - len(right))
            a = self.panel("02 / KAYNAK DURUMU", left, width=left_width)
            b = self.panel("VARLIK DAĞILIMI", right, width=right_width, tone="violet")
            self.emit([x + "  " + y for x, y in zip(a, b)])
        else:
            inner = self.content_width()
            self.show_panel("02 / KAYNAK DURUMU", self._source_rows(data, inner))
            self.show_panel("VARLIK DAĞILIMI", self._entity_rows(data, inner), tone="violet")

    def findings(self, data):
        inner = self.content_width()
        findings = data.get("findings", [])
        limit = 6 if self.height < 32 or self.width < 60 else 10
        rows = []
        for item in findings[:limit]:
            label = FINDING_LABELS.get(item["kind"], item["kind"].replace("_", " "))
            if inner >= 58:
                label_width = 22
                keys = wrap_text(self.text(label), label_width)
                values = self.paragraph(item["value"], inner - label_width - 2, limit=3)
                for i in range(max(len(keys), len(values))):
                    key = keys[i] if i < len(keys) else ""
                    rows.append([Span(key + " " * (label_width - cell_width(key) + 2), "cyan")]
                                + (values[i] if i < len(values) else []))
            else:
                rows.extend(self.paragraph(label, inner, "cyan"))
                rows.extend(self.paragraph(item["value"], inner, prefix="  ", limit=3))
        if not findings:
            rows.extend(self.paragraph("Henüz bulgu yok; kaynak durumlarını kontrol edin.", inner, "muted"))
        else:
            rows.append(row())
            rows.extend(self.paragraph(f"İlk {min(limit, len(findings))}/{len(findings)} bulgu / Değerler önizlemedir; tam veri raporlarda.", inner, "muted"))
        self.show_panel("03 / BULGU ÖNİZLEMESİ", rows)

    def insights(self, data):
        inner = self.content_width()
        insights = data.get("analysis", {}).get("insights", [])
        priority = {"critical": 0, "warn": 1, "info": 2}
        insights = sorted(insights, key=lambda item: priority[insight_level(item["type"])])
        rows = []
        limit = 3 if self.height < 32 else 5
        for item in insights[:limit]:
            level = insight_level(item["type"])
            tone, label = {"critical": ("red", "KRİTİK"), "warn": ("amber", "UYARI"), "info": ("cyan", "BİLGİ")}[level]
            rows.extend(self.paragraph(f"{label} / {item.get('subject', '')}", inner, tone))
            rows.extend(self.paragraph(item.get("message", ""), inner, prefix="  ", limit=4))
        if not insights:
            rows.extend(self.paragraph("Ek gösterge üretilmedi; bu bir güvenlik garantisi değildir.", inner, "muted"))
        elif len(insights) > limit:
            rows.extend(self.paragraph(f"+{len(insights) - limit} gösterge daha raporda.", inner, "muted"))
        self.show_panel("04 / ANALİZ", rows, tone="violet")

    def report_paths(self, paths):
        if not paths:
            return
        inner = self.content_width()
        descriptions = {"report.html": "İnteraktif rapor", "report.json": "Tam veri / JSON",
                        "report.md": "Markdown raporu", "findings.csv": "Bulgu tablosu",
                        "graph.dot": "Graphviz ilişkileri", "graph.graphml": "Gephi grafiği",
                        "metadata_report.json": "Meta veri / JSON"}
        paths = [Path(path) for path in paths]
        common_parent = len({path.parent for path in paths}) == 1
        rows = self.fields([("KLASÖR", str(paths[0].parent))], inner) if common_parent else []
        if rows:
            rows.append(row())
        for path in sorted(paths, key=lambda p: (p.name != "report.html", p.name)):
            rows.extend(self.paragraph(path.name if common_parent else str(path), inner, "cyan"))
            rows.extend(self.paragraph(descriptions.get(path.name, "Rapor dosyası"), inner, "muted", prefix="  "))
        self.show_panel("RAPOR DOSYALARI", rows, badge="KAYDEDİLDİ", tone="green")

    def summary(self, data, *, paths=(), banner=True, interrupted=False):
        self.emit()
        if banner:
            self.banner(demo=data.get("demo", False))
        inner = self.content_width()
        partial = interrupted or data.get("interrupted", False) or any(s.get("state") != "ok" for s in data.get("sources", []))
        status = "KISMİ RAPOR" if partial else "TAMAMLANDI" if data.get("sources") else "VERİ YOK"
        if data.get("demo"):
            status = "ÇEVRİMDIŞI DEMO"
        kind = {"domain": "Alan adı", "email": "E-posta", "ip": "IP adresi"}.get(data["target"]["kind"], data["target"]["kind"])
        fields = [("HEDEF", data["target"]["value"]), ("TÜR", kind), ("DURUM", status)]
        if data.get("finished_at"):
            fields.append(("BİTİŞ", data["finished_at"]))
        self.show_panel("01 / OTURUM ÖZETİ", self.fields(fields, inner), tone="amber" if partial else "cyan")
        if data.get("demo"):
            self.emit([self.line(row(part, "amber")) for part in wrap_text(self.text("Örnek veriler / Ağ isteği yapılmadı. Gerçek tarama sonucu değildir."), self.width)])
        self.metrics(data)
        self.emit()
        self.sources_and_entities(data)
        self.emit()
        self.findings(data)
        self.insights(data)
        comparison = data.get("comparison")
        if comparison is not None:
            rows = self.fields([("YENİ", str(len(comparison["added"]))),
                                ("GÖRÜLMEDİ", str(len(comparison["not_observed"]))),
                                ("AYNI", str(comparison["unchanged_count"]))], inner)
            rows.extend(self.paragraph(comparison.get("caution", "Görülmeyen bulgular silinmiş sayılmaz."), inner, "muted"))
            self.show_panel("KARŞILAŞTIRMA", rows)
        warnings = data.get("warnings", [])
        if warnings:
            rows = []
            for warning in warnings:
                rows.extend(self.paragraph(warning, inner, "muted", prefix="! "))
            self.show_panel("05 / KAPSAM NOTLARI", rows, tone="amber")
        self.report_paths(paths)
        self.emit()

    def dashboard_lines(self, data, *, paths=(), interactive=False):
        """A screen-sized overview. Complete results stay in the paged UI/files."""
        width, height, inner = self.width, self.height, self.content_width()
        budget = max(1, height - 2)
        if width < 20 or height < 12:
            text = "SZOBO / DRAXEN / Ayrıntılar: --details"
            return [self.line(row(part, "cyan")) for part in wrap_text(self.text(text), width)][:budget]
        sources = data.get("sources", [])
        partial = data.get("interrupted", False) or any(s.get("state") != "ok" for s in sources)
        status = "KISMİ RAPOR" if partial else "TAMAMLANDI" if sources else "VERİ YOK"
        if data.get("demo"):
            status = "DEMO / AĞ İSTEĞİ YOK"
        body = self.paragraph(data["target"]["value"], inner, "cyan", limit=2 if height >= 30 else 1)
        body.append(row(status, "amber" if partial or data.get("demo") else "green"))
        stats = f"{len(data.get('findings', []))} bulgu / {sum(s.get('state') == 'ok' for s in sources)}/{len(sources)} kaynak / {data.get('requests', 0)} HTTP"
        body.extend(self.paragraph(stats, inner, "text", limit=2))
        session = self.panel("OTURUM", body)
        hints = (["1 Özet  2 Kaynak  3 Bulgu", "4 Analiz  5 Dosya  Q Geri"] if interactive else ["Tam çıktı: --details / Menü: --ui"])
        footer = []
        if paths and not interactive:
            footer.extend(self.line(spans) for spans in self.paragraph("Rapor: " + str(Path(paths[0]).parent), width, "green", limit=1))
        for hint in hints:
            footer.extend(self.line(row(part, "muted")) for part in wrap_text(self.text(hint), width))
        insights = sorted(data.get("analysis", {}).get("insights", []),
                          key=lambda item: {"critical": 0, "warn": 1, "info": 2}[insight_level(item["type"])])
        available = budget - len(session) - len(footer)
        feature = []
        if available >= 6:
            rows = []
            tone = "cyan"
            if data.get("interrupted"):
                message = "İşlem durduruldu. Toplanan veriler kısmi raporda korundu."
                tone = "amber"
            elif partial:
                failed = next(source for source in sources if source.get("state") != "ok")
                message = "Eksik kaynak: " + failed.get("name", "") + ". " + failed.get("message", "")
                tone = "amber"
            elif insights:
                item = insights[0]
                tone = {"critical": "red", "warn": "amber", "info": "cyan"}[insight_level(item["type"])]
                message = item.get("message", "")
            else:
                message = "Ek gösterge yok. Bu bir güvenlik garantisi değildir."
            rows.extend(self.paragraph(message, inner, tone, limit=min(3, max(1, available - 5))))
            feature = self.panel("ÖNE ÇIKAN", rows, tone=tone)
        logo_budget = max(1, budget - len(session) - len(feature) - len(footer))
        brand = self.banner_lines(demo=data.get("demo", False), max_height=logo_budget, full=height >= 32)
        return (brand + session + feature + footer)[:budget]

    def dashboard(self, data, *, paths=(), interactive=False):
        self.emit(self.dashboard_lines(data, paths=paths, interactive=interactive))

    def metadata(self, data, paths=()):
        self.banner()
        inner = self.content_width()
        rows = self.fields([("DOSYA", data["filename"]), ("TÜR", data["file_type"]),
                            ("BOYUT", f"{data['file_size_bytes']} bayt")], inner)
        self.show_panel("YEREL META VERİ", rows, badge="ÇEVRİMDIŞI")
        rows = []
        for key, value in sorted(data.get("metadata", {}).items()):
            rows.extend(self.paragraph(key, inner, "cyan"))
            rows.extend(self.paragraph(value, inner, prefix="  "))
        if not rows:
            rows = self.paragraph("Gömülü meta veri veya EXIF başlığı bulunamadı.", inner, "muted")
        self.show_panel("AYIKLANAN VERİLER", rows)
        self.report_paths(paths)

    def error(self, message):
        self.show_panel("HATA", self.paragraph(message, self.content_width()), tone="red")


class ScanProgress:
    """One resize-safe live line; real counts, no invented completion percentage."""
    def __init__(self, console, report, client, budget, clock=time.monotonic):
        self.console = console
        self.report = report
        self.client = client
        self.budget = budget
        self.clock = clock
        self.started = clock()
        self.name = "Hazırlanıyor"
        self.active = False
        self.live = console.tty and not console.plain
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self._drawn = False

    def __enter__(self):
        if self.live:
            self._thread = threading.Thread(target=self._refresh, name="draxen-progress", daemon=True)
            self._thread.start()
        return self

    def __call__(self, name):
        with self._lock:
            self.name = name
            self.active = True
            if self.live:
                self._draw()
            else:
                index = len(self.report.data["sources"]) + 1
                self.console.emit([self.console.line(row(part, "muted")) for part in
                                   wrap_text(self.console.text(f"[{index:02d}] {name}"), self.console.width)])

    def frame(self):
        width = self.console.width
        elapsed = max(0, self.clock() - self.started)
        frames = "|/-\\" if self.console.ascii else "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spinner = frames[int(elapsed * 8) % len(frames)]
        requests = self.client.requests
        suffix = f"  {requests}/{self.budget} HTTP" if width >= 34 else ""
        if width >= 64:
            suffix = f"  {len(self.report.data['findings'])} bulgu" + suffix + f"  {int(elapsed) // 60:02d}:{int(elapsed) % 60:02d}"
        if width >= 104:
            suffix = f"  {len(self.report.data['sources'])} kaynak" + suffix
        prefix = spinner + " "
        room = max(0, width - cell_width(prefix) - cell_width(suffix))
        label = clip_text(self.console.text(self.name), room, "..." if self.console.ascii else "…")
        return self.console.line([Span(prefix, "cyan"), Span(label + " " * max(0, room - cell_width(label))),
                                  Span(suffix, "amber" if requests >= self.budget else "muted")])

    def _draw(self):
        self.console.stream.write("\r\x1b[2K" + self.frame())
        self.console.stream.flush()
        self._drawn = True

    def _refresh(self):
        while not self._stop.wait(0.125):
            with self._lock:
                if self.active:
                    self._draw()

    def __exit__(self, exc_type, exc, traceback):
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if self._drawn:
            self.console.stream.write("\r\x1b[2K")
            self.console.stream.flush()
        return False
