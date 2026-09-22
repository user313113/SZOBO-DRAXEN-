"""Native line-input TUI: works with Termux/iSH keyboards and stock Python.

No browser, curses, raw mode, hidden cursor or alternate screen is required.
Every action waits for explicit input; opening the app never starts a scan.
"""

import math
import sys
from pathlib import Path

from . import tool_registry
from .analysis import insight_level
from .core import Target
from .terminal_ui import FINDING_LABELS, Span, row, wrap_text


class LeaveUI(Exception):
    def __init__(self, code=0):
        self.code = code


def can_interact(console):
    return (console.tty and console.decorated and not console.plain
            and console.width >= 20 and console.height >= 12
            and bool(getattr(sys.stdin, "isatty", lambda: False)()))


class TerminalApp:
    def __init__(self, console, reader=None):
        self.console = console
        self.reader = reader if reader is not None else input

    def prompt(self, label="Seçim"):
        console = self.console
        console.stream.write(console.line([Span("› ", "green", True), Span(label + " > ", "cyan")]))
        console.stream.flush()
        try:
            return self.reader().strip()
        except EOFError as exc:
            console.emit()
            raise LeaveUI() from exc
        except KeyboardInterrupt as exc:
            console.emit()
            raise LeaveUI(130) from exc

    def _form(self, title, text):
        """Keep long targets/scope visible before asking for consent or a value.

        Overflow pages require Enter/N to continue. Q cancels the action rather
        than skipping ahead to its input prompt. Ordinary forms need no extra key.
        """
        console, page = self.console, 0
        while True:
            console.clear_view()
            if console.width < 20 or console.height < 12:
                console.home()
                self.prompt("Enter: menü")
                return False
            rows = []
            for part in text.splitlines():
                rows.extend(console.paragraph(part, console.content_width()))
            full_panel = console.panel(title, rows)
            if len(full_panel) <= console.height - 4:
                console.banner(max_height=console.height - len(full_panel) - 3, full=False)
                console.emit(full_panel)
                return True
            hints = [console.line(row(part, "muted")) for part in
                     wrap_text(console.text("Enter/N: devam / P: geri / Q: menü"), console.width)]
            page_size = max(1, console.height - len(hints) - 5)
            total = max(1, math.ceil(len(rows) / page_size))
            page = min(page, total - 1)
            console.banner(max_height=1)
            console.emit(console.panel(title, rows[page * page_size:(page + 1) * page_size],
                                       badge=f"{page + 1}/{total}"))
            if page == total - 1:
                return True
            console.emit(hints)
            choice = self.prompt("Devam").casefold()
            if choice in ("q", "0", "geri"):
                return False
            if choice in ("", "n", "+"):
                page += 1
            elif choice in ("p", "-"):
                page = max(0, page - 1)

    def launch(self, runner, help_text, settings=None):
        settings = settings or {"budget": 40, "delay": 1.5, "timeout": 15, "limit": 100}
        notice = ""
        try:
            while True:
                self.console.clear_view()
                self.console.home(interactive=True)
                # The last reserved row is used for input, not an extra log line.
                choice = self.prompt(notice or "Seçim").casefold()
                notice = ""
                if choice in ("q", "0", "çıkış", "cikis"):
                    return 0
                if not choice:
                    continue  # Also provides a redraw after keyboard/rotation changes.
                if choice in ("1", "01", "2", "02"):
                    self._scan(runner, settings, deep=choice in ("2", "02"))
                elif choice in ("3", "03"):
                    if not self._form("YEREL META VERİ", "JPEG, PNG veya PDF dosya yolunu gir. Ağ isteği yapılmaz. Q: geri."):
                        continue
                    path = self.prompt("Dosya yolu")
                    if path.casefold() not in ("q", "0", ""):
                        args = ["--ui", "--meta=" + path]
                        if settings.get("output"):
                            args += ["--output", str(settings["output"])]
                        self._run(runner, args)
                elif choice in ("4", "04", "d", "demo"):
                    self._run(runner, ["--demo", "--ui"])
                elif choice in ("5", "05"):
                    self.tools_page()
                elif choice in ("h", "yardım", "yardim", "?"):
                    self.text_viewer(help_text(), "KOMUTLAR")
                else:
                    notice = "01–05, H veya Q"
        except LeaveUI as exc:
            return exc.code

    def _run(self, runner, args):
        code = runner(args)
        if code == 130:
            raise LeaveUI(130)
        if code != 0 and code != 2:
            self.prompt("Enter: menü")

    def _scan(self, runner, settings, deep=False):
        if not self._form("DERİN ANALİZ" if deep else "STANDART KEŞİF",
                          "Alan adı, genel IP veya e-posta gir. Yalnızca araştırma yetkin olan hedefleri kullan. Q: geri."):
            return
        value = self.prompt("Hedef")
        if not value or value.casefold() in ("q", "0"):
            return
        try:
            target = Target.parse(value)
        except ValueError as exc:
            self.console.error(str(exc))
            self.prompt("Enter: menü")
            return
        modules = "DNS / RDAP / CT" if target.domain else "RDAP / PTR"
        if deep:
            modules += " / derin modüller / DNS sözlüğü / TCP portları" if target.domain else " / ağ / altyapı / TCP portları"
        if not self._form("TARAMAYI ONAYLA", f"Hedef: {target.value}\nMod: {modules}\nHTTP bütçesi: {settings['budget']} / Aralık: {settings['delay']:g} sn. Başlatmak için E, geri dönmek için Enter."):
            return
        if self.prompt("Başlat? [e/H]").casefold() not in ("e", "evet"):
            return
        args = ["--ui"]
        if deep:
            args.append("--deep")
        for option in ("budget", "delay", "timeout", "limit"):
            args += ["--" + option, str(settings[option])]
        if settings.get("output"):
            args += ["--output", str(settings["output"])]
        # The target is validated above and kept separate from all CLI flags.
        args += ["--", target.value]
        self._run(runner, args)

    def _report_rows(self, data, section, paths):
        console, rows = self.console, []
        width = console.content_width()
        if section == "2":
            for source in data.get("sources", []):
                ok = source.get("state") == "ok"
                rows.extend(console.paragraph(("OK" if ok else "EKSİK") + " / " + source.get("name", ""), width, "green" if ok else "amber"))
                rows.extend(console.paragraph(f"+{source.get('new_findings', 0)} bulgu / {source.get('message', '')}", width, "muted", prefix="  "))
                rows.append(row())
        elif section == "3":
            for number, finding in enumerate(data.get("findings", []), 1):
                label = FINDING_LABELS.get(finding["kind"], finding["kind"].replace("_", " "))
                rows.extend(console.paragraph(f"{number:02d} / {label}", width, "cyan"))
                rows.extend(console.paragraph(finding["value"], width))
                if finding.get("subject"):
                    rows.extend(console.paragraph("Özne: " + finding["subject"], width, "muted"))
                rows.append(row())
        elif section == "4":
            insights = sorted(data.get("analysis", {}).get("insights", []),
                              key=lambda item: {"critical": 0, "warn": 1, "info": 2}[insight_level(item["type"])])
            for item in insights:
                label, tone = {"critical": ("KRİTİK", "red"), "warn": ("UYARI", "amber"), "info": ("BİLGİ", "cyan")}[insight_level(item["type"])]
                rows.extend(console.paragraph(label + " / " + item.get("subject", ""), width, tone))
                rows.extend(console.paragraph(item.get("message", ""), width))
                for value in item.get("values", []):
                    rows.extend(console.paragraph(value, width, "muted", prefix="  "))
                rows.append(row())
            for warning in data.get("warnings", []):
                rows.extend(console.paragraph("NOT / " + warning, width, "amber"))
            comparison = data.get("comparison")
            if comparison is not None:
                rows.extend(console.paragraph(f"Karşılaştırma: {len(comparison['added'])} yeni / {len(comparison['not_observed'])} görülmedi / {comparison['unchanged_count']} aynı.", width, "cyan"))
                rows.extend(console.paragraph(comparison.get("caution", "Görülmeyen kayıt silinmiş sayılmaz."), width, "muted"))
        elif section == "5":
            for path in paths:
                rows.extend(console.paragraph(Path(path).name, width, "green"))
                rows.extend(console.paragraph(str(path), width))
                rows.append(row())
            if not paths:
                rows.extend(console.paragraph("Dosya kaydedilmedi. Demo çevrimdışıdır; kayıt için --output KLASÖR kullan.", width, "muted"))
        return rows or console.paragraph("Bu bölümde kayıt yok.", width, "muted")

    def page_lines(self, rows, title, page, *, report=False, hints=None):
        console = self.console
        if hints is None:
            hints = (["N İleri / P Geri", "1 Özet  2 Kaynak  3 Bulgu", "4 Analiz  5 Dosya  Q Geri"] if report else ["N İleri / P Geri / Q Menü"])
        footer = []
        for hint in hints:
            footer.extend(console.line(row(part, "muted")) for part in wrap_text(console.text(hint), console.width))
        page_size = max(1, console.height - len(footer) - 5)
        total = max(1, math.ceil(len(rows) / page_size))
        page = max(0, min(page, total - 1))
        header = console.banner_lines(max_height=1)
        panel = console.panel(title, rows[page * page_size:(page + 1) * page_size], badge=f"{page + 1}/{total}")
        return (header + panel + footer)[:max(1, console.height - 2)], page, total

    def report_viewer(self, data, paths=()):
        section, page = "1", 0
        titles = {"2": "KAYNAK DURUMU", "3": "BULGULAR", "4": "ANALİZ / NOTLAR", "5": "RAPOR DOSYALARI"}
        while True:
            self.console.clear_view()
            if section == "1":
                self.console.dashboard(data, paths=paths, interactive=True)
                total = 1
            else:
                lines, page, total = self.page_lines(self._report_rows(data, section, paths), titles[section], page, report=True)
                self.console.emit(lines)
            choice = self.prompt().casefold()
            if choice in ("q", "0", "geri"):
                return 0
            if choice in ("1", "2", "3", "4", "5"):
                section, page = choice, 0
            elif choice in ("n", "+"):
                page = min(page + 1, total - 1)
            elif choice in ("p", "-"):
                page = max(0, page - 1)

    def text_viewer(self, text, title):
        page = 0
        while True:
            rows = []
            for line in text.splitlines():
                rows.extend(self.console.paragraph(line, self.console.content_width()))
            self.console.clear_view()
            lines, page, total = self.page_lines(rows, title, page)
            self.console.emit(lines)
            choice = self.prompt().casefold()
            if choice in ("q", "0", "geri"):
                return 0
            if choice in ("n", "+"):
                page = min(page + 1, total - 1)
            elif choice in ("p", "-"):
                page = max(0, page - 1)

    def tools_page(self):
        """Paged, searchable catalog of ready-made test tools (option 05).

        List display only: entries are never downloaded, installed or run.
        """
        catalog, error = tool_registry.load_catalog()
        if catalog is None:
            self.console.clear_view()
            self.console.banner(max_height=max(1, self.console.height - 8))
            self.console.error(error)
            self.console.emit(self.console.paragraph(tool_registry.DISCLAIMER,
                                                     self.console.content_width(), "amber"))
            self.prompt("Enter: menü")
            return
        state = {"page": 0, "query": ""}
        while True:
            lines, page, total = self._tools_screen(catalog, state)
            self.console.emit(lines)
            choice = self.prompt("Araç no / S: arama").strip()
            low = choice.casefold()
            if low in ("q", "0", "geri"):
                return
            if not low:
                if state["query"]:  # Enter with an active filter clears it.
                    state["query"] = ""
                    state["page"] = 0
                continue
            if low in ("n", "+"):
                state["page"] = min(page + 1, total - 1)
                continue
            if low in ("p", "-"):
                state["page"] = max(0, page - 1)
                continue
            if low in ("s", "ara", "arama", "f", "filtre"):
                state["query"] = self.prompt("Arama").strip()
                state["page"] = 0
                continue
            matches = catalog.search(state["query"])
            if choice.isdigit() and 1 <= int(choice) <= len(matches):
                self.tool_detail(matches[int(choice) - 1], catalog, state)
                continue
            # Any other text is an instant filter, same flow as typing a name.
            state["query"] = choice
            state["page"] = 0

    def _tools_screen(self, catalog, state):
        console = self.console
        matches = catalog.search(state["query"])
        width = console.content_width()
        title = "TEST ARAÇLARI" + (f" / {state['query']}" if state["query"] else "")
        rows = console.paragraph(
            f"{len(matches)}/{len(catalog)} kayıt"
            + (f" / filtre: {state['query']}" if state["query"] else "")
            + " / S: yeni arama", width, "muted")
        for index, tool in enumerate(matches, 1):
            tag = tool["categories"][0] if tool["categories"] else ""
            rows.append([Span(f"{index:04d} ", "violet", True),
                         Span(tool["name"], "cyan", True),
                         Span("  " + tag, "muted")])
        if not matches:
            rows.append(row())
            rows.extend(console.paragraph("Eşleşme yok — Enter: filtresi kaldır, Q: menü.", width, "amber"))
        hints = ["S: arama / N: ileri / P: geri / Q: menü",
                 "Sayı: araç sayfası / metin: filtre / Enter: filtre temizle"]
        return self.page_lines(rows, title, state["page"], hints=hints)

    def tool_detail(self, tool, catalog, state):
        """One tool card, paged: description, category, install hint, deps, link."""
        console = self.console
        width = console.content_width()
        rows = console.paragraph(tool["name"], width, "green")
        if tool["desc"]:
            rows.append(row())
            rows.extend(console.paragraph(tool["desc"], width))
        rows.append(row())
        fields = [
            ("KATEGORİ", ", ".join(tool["categories"])),
            ("KURULUM", catalog.install_hint(tool)),
            ("BAĞIMLILIK", ", ".join(tool["dependencies"]) or "Belirtilmedi"),
            ("BAĞLANTI", tool["url"] or "Belirtilmedi"),
        ]
        rows.extend(console.fields(fields, width))
        rows.append(row())
        rows.extend(console.paragraph(tool_registry.DISCLAIMER, width, "amber"))
        rows.extend(console.paragraph(tool_registry.ETHICS, width, "amber"))
        hints = ["Q: listeye dön / N: ileri / P: geri"]
        page = 0
        while True:
            console.clear_view()
            lines, page, total = self.page_lines(rows, "ARAÇ DETAYI", page, hints=hints)
            console.emit(lines)
            choice = self.prompt("Araç").strip().casefold()
            if choice in ("q", "0", "geri"):
                return
            if choice in ("n", "+"):
                page = min(page + 1, total - 1)
            elif choice in ("p", "-"):
                page = max(0, page - 1)

    def metadata_viewer(self, data, paths=()):
        text = f"Dosya: {data['filename']}\nTür: {data['file_type']}\nBoyut: {data['file_size_bytes']} bayt\n\n"
        text += "\n\n".join(str(key) + "\n" + str(value) for key, value in sorted(data.get("metadata", {}).items())) or "Gömülü meta veri bulunamadı."
        text += "\n\n" + "\n".join(str(path) for path in paths)
        return self.text_viewer(text, "YEREL META VERİ")
