import argparse
import json
import math
import sys
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, tool_registry
from .analysis import analyze, load_baseline
from .collectors import Collector
from .core import Client, Report, Target
from .gate import AccessGate
from .metadata import extract_metadata
from .output import print_summary, save_reports
from .terminal_ui import ScanProgress, Span, TerminalUI, row, wrap_text
from .terminal_app import LeaveUI, TerminalApp, can_interact


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"{low}–{high} aralığında olmalı")
        return number
    return parse


def bounded_float(low, high):
    def parse(value):
        number = float(value)
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError(f"{low}–{high} aralığında olmalı")
        return number
    return parse


class DraxenParser(argparse.ArgumentParser):
    def parse_known_args(self, args=None, namespace=None):
        # Keep already parsed display flags available to argparse's help/errors.
        self._ui_namespace = namespace if namespace is not None else argparse.Namespace()
        return super().parse_known_args(args, self._ui_namespace)

    def _console(self, stream=None):
        args = getattr(self, "_ui_namespace", argparse.Namespace())
        return TerminalUI(stream, color=getattr(args, "color", "auto"),
                          ascii_only=getattr(args, "ascii_only", False),
                          plain=getattr(args, "plain", False), width=getattr(args, "width", None))

    def print_help(self, file=None, console=None):
        console = console or self._console(file)
        console.banner()
        inner = console.content_width()
        examples = [("Standart keşif", "python -m draxen example.com"),
                    ("Derin analiz", "python -m draxen example.com --deep"),
                    ("Çevrimdışı demo", "python -m draxen --demo")]
        rows = []
        for label, command in examples:
            rows.extend(console.paragraph(label, inner, "muted"))
            rows.extend(console.paragraph(command, inner, "cyan"))
        console.show_panel("HIZLI BAŞLANGIÇ", rows)
        for group in self._action_groups:
            rows = []
            for action in group._group_actions:
                if action.help == argparse.SUPPRESS:
                    continue
                label = ", ".join(action.option_strings) or "HEDEF"
                if action.option_strings and action.nargs != 0:
                    label += " " + (action.metavar or ("{" + ",".join(action.choices) + "}" if action.choices else action.dest.upper()))
                rows.extend(console.paragraph(label, inner, "cyan"))
                rows.extend(console.paragraph(action.help or "", inner, "muted", prefix="  "))
            if rows:
                console.show_panel(group.title, rows)
        console.emit([console.line(row(line, "muted")) for line in wrap_text(console.text(self.epilog or ""), console.width)])

    def error(self, message):
        console = self._console(sys.stderr)
        console.error(message)
        console.emit([console.line(row(line, "muted")) for line in wrap_text(console.text("Kullanım: draxen [HEDEF] [SEÇENEKLER] / Yardım: draxen --help"), console.width)])
        self.exit(2)


def parser():
    cli = DraxenParser(prog="draxen", add_help=False, usage="%(prog)s [HEDEF] [SEÇENEKLER]",
                       description="SZOBO | DRAXEN — Düşük yoğunluklu, kaynak izlenebilir OSINT",
                       epilog="Yalnızca araştırma yetkinizin bulunduğu hedeflerde kullanın. E-posta sorgusu kimlik veya hesap doğrulaması yapmaz.")
    cli._positionals.title = "HEDEF"
    cli._optionals.title = "GENEL"
    cli.add_argument("target", nargs="?", help="Alan adı, genel IPv4/IPv6 veya e-posta")
    cli.add_argument("-h", "--help", action="help", help="Komutları ve kullanım örneklerini göster")
    cli.add_argument("--version", action="version", version="SZOBO | DRAXEN " + __version__, help="Sürüm bilgisini göster")
    local = cli.add_argument_group("ÇEVRİMDIŞI ARAÇLAR")
    offline = local.add_mutually_exclusive_group()
    offline.add_argument("--banner", action="store_true", help="Katmanlı SZOBO / DRAXEN başlığını göster; ağ isteği yapmaz")
    offline.add_argument("--demo", action="store_true", help="Arayüzü örnek verilerle göster; ağ isteği yapmaz")
    offline.add_argument("--meta", type=Path, metavar="DOSYA", help="Yerel JPEG, PNG veya PDF dosyasından meta veri (EXIF, GPS, yazar, cihaz) ayıkla")
    offline.add_argument("--tools", nargs="?", const="", default=None, metavar="FILTRE",
                         help="Hazır test araçları kataloğunu listele; FILTRE ile daralt. İndirmez, kurmaz; ağ isteği yapmaz")
    modules = cli.add_argument_group("KEŞİF MODÜLLERİ")
    modules.add_argument("--deep", action="store_true", help="Arşiv, ağ, posta, güvenlik, altyapı/TLS, sitemap, alt alan ve port modüllerini aç")
    modules.add_argument("--sitemap", action="store_true", help="robots.txt kuralları ve sitemap.xml adreslerini analiz et")
    modules.add_argument("--brute", action="store_true", help="Sözlük tabanlı alt alan adı keşfi (DNS wordlist)")
    modules.add_argument("--ports", action="store_true", help="Açık port ve servis karşılama (banner) kontrolü")
    modules.add_argument("--archives", action="store_true", help="Wayback ve mevcut urlscan kayıtlarını sorgula")
    modules.add_argument("--network", "--netintel", "--asn", action="store_true", help="IP konumu, ASN, BGP, veri merkezi ve IP blok istihbaratı")
    modules.add_argument("--mail", action="store_true", help="MTA-STS, TLS-RPT, BIMI, DS/DNSKEY, DKIM ve SPF analizi")
    modules.add_argument("--security", action="store_true", help="security.txt, HTTP başlıkları ve e-posta profil kontrolleri")
    modules.add_argument("--infra", action="store_true", help="CDN/WAF, SOA mimarisi, RIR kaydı ve TLS kriptografik profili")
    modules.add_argument("--web", action="store_true", help="robots.txt izin verirse hedefin ana sayfasını oku (doğrudan bağlantı)")
    scan = cli.add_argument_group("TARAMA SINIRLARI")
    scan.add_argument("--verify", type=bounded_int(0, 20), default=0, metavar="N", help="En fazla N kaynak adayını DNS ile kontrol et (0–20, varsayılan 0)")
    scan.add_argument("--limit", type=bounded_int(1, 1000), default=100, metavar="N", help="CT ve sayfa bulgusu sınırı (1–1000, varsayılan 100)")
    scan.add_argument("--budget", type=bounded_int(1, 100), default=40, metavar="N", help="HTTP istek sınırı (1–100, varsayılan 40)")
    scan.add_argument("--delay", type=bounded_float(1, 60), default=1.5, metavar="SANİYE", help="İstekler arası en az süre (1–60, varsayılan 1.5)")
    scan.add_argument("--timeout", type=bounded_float(2, 60), default=15, metavar="SANİYE", help="Ağ soketi zaman aşımı (2–60, varsayılan 15)")
    output = cli.add_argument_group("RAPOR VE GÖRÜNÜM")
    output.add_argument("--compare", type=Path, metavar="DOSYA", help="Aynı hedefin önceki report.json dosyasıyla karşılaştır")
    output.add_argument("--output", type=Path, metavar="KLASÖR", help="Çıktı klasörü; mevcut aynı adlı raporlar yenilenir")
    output.add_argument("--ui", action="store_true", help="Doğrudan terminalde etkileşimli menü ve sayfalı rapor arayüzü")
    output.add_argument("--details", action="store_true", help="Tek ekranlık özet yerine uzun, ayrıntılı terminal çıktısı")
    output.add_argument("--quiet", action="store_true", help="İlerleme ve bulgu özetini yazdırma; raporlar kaydedilir")
    output.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="ANSI renkleri (varsayılan auto; NO_COLOR desteklenir)")
    output.add_argument("--ascii", action="store_true", dest="ascii_only", help="Blok ve Unicode yerine uyumlu ASCII karakterler kullan")
    output.add_argument("--plain", action="store_true", help="Logo, panel, renk ve animasyon olmadan sade ASCII çıktı")
    output.add_argument("--width", type=bounded_int(20, 160), metavar="N", help="Düzen genişliği (20–160); gerçek terminal genişliği aşılmaz")
    return cli


def run_meta(path, output, quiet, console=None, error_console=None, ui=False):
    console = console or TerminalUI()
    error_console = error_console or TerminalUI(sys.stderr)
    try:
        res = extract_metadata(path)
    except Exception as exc:
        error_console.error("Meta veri okuma hatası: " + str(exc))
        return 1
    paths = []
    if output:
        try:
            out_dir = Path(output)
            out_dir.mkdir(parents=True, exist_ok=True)
            report_file = out_dir / "metadata_report.json"
            report_file.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            paths.append(report_file)
        except OSError as exc:
            error_console.error("Rapor yazılamadı: " + str(exc))
            return 1
    if not quiet:
        if ui:
            return TerminalApp(console).metadata_viewer(res, paths)
        console.metadata(res, paths)
    return 0


def show_tools(args, console, error_console):
    """Offline catalog browser for ready-made test tools (display only)."""
    catalog, error = tool_registry.load_catalog()
    if catalog is None:
        error_console.error(error)
        return 1
    matches = catalog.search(args.tools)
    inner = console.content_width()
    console.banner(max_height=max(1, console.height - 4))
    rows = console.paragraph(
        f"{len(matches)}/{len(catalog)} kayıt / çevrimdışı katalog"
        + (f" / filtre: {args.tools}" if args.tools else ""), inner, "muted")
    rows.extend(console.paragraph(tool_registry.DISCLAIMER, inner, "amber"))
    rows.append(row())
    for index, tool in enumerate(matches, 1):
        tag = tool["categories"][0] if tool["categories"] else ""
        rows.append([Span(f"{index:04d} ", "violet", True),
                     Span(tool["name"], "cyan", True),
                     Span("  " + tag, "muted")])
        if tool["url"]:
            rows.extend(console.paragraph(tool["url"], inner, "muted", prefix="  "))
    if not matches:
        rows.append(row())
        rows.extend(console.paragraph("Eşleşme yok — farklı bir filtre deneyin.", inner, "amber"))
    title = "TEST ARAÇLARI" + (f" / {args.tools.upper()}" if args.tools else "")
    console.show_panel(title, rows, badge=str(len(matches)))
    return 0


def show_report(args, console, data, paths, banner=True):
    if args.ui:
        return TerminalApp(console).report_viewer(data, paths)
    if console.decorated and not args.details:
        console.dashboard(data, paths=paths)
    else:
        print_summary(data, console=console, paths=paths, banner=banner,
                      interrupted=data.get("interrupted", False))
    return 0


def main(argv=None):
    # EOF / Ctrl+C leave the entire nested UI, not just its current report.
    # Keep the process boundary here; the launcher calls _main internally.
    try:
        return _main(argv)
    except LeaveUI as exc:
        return exc.code


def _main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    display = {"color": args.color, "ascii_only": args.ascii_only, "plain": args.plain, "width": args.width}
    console = TerminalUI(sys.stdout, **display)
    error_console = TerminalUI(sys.stderr, **display)
    scan_flags = (args.deep, args.web, args.archives, args.network, args.mail, args.security,
                  args.infra, args.sitemap, args.brute, args.ports, args.verify)
    if args.ui:
        if args.quiet or args.plain or args.details or args.banner:
            cli.error("--ui; --quiet, --plain, --details veya --banner ile birlikte kullanılamaz")
        if not can_interact(console):
            cli.error("--ui için en az 21 kolon / 12 satır ve gerçek terminal girişi/çıkışı gerekli. Termux/iSH içinde doğrudan çalıştırın; pipe veya TERM=dumb kullanmayın.")
    if args.banner:
        if args.target or args.compare or any(scan_flags):
            cli.error("--banner yalnızca başlığı gösterir; hedef veya keşif modülü kullanmayın")
        if not args.quiet:
            console.banner(max_height=max(1, console.height - 1), status=True)
        return 0
    if args.demo:
        if args.target or args.compare or any(scan_flags):
            cli.error("--demo bir tarama değildir; hedef, --compare veya keşif modülleriyle birlikte kullanılamaz")
        from .demo import sample_report
        data = sample_report()
        paths = []
        if args.output:
            try:
                paths = save_reports(data, args.output)
            except OSError as exc:
                error_console.error("Rapor yazılamadı: " + str(exc))
                return 1
        if not args.quiet:
            return show_report(args, console, data, paths)
        return 0
    if args.meta:
        return run_meta(args.meta, args.output, args.quiet, console, error_console, ui=args.ui)
    if args.tools is not None:
        if args.target or args.compare or any(scan_flags):
            cli.error("--tools bir tarama değildir; hedef, --compare veya keşif modülleriyle birlikte kullanılamaz")
        return show_tools(args, console, error_console)
    if not args.target:
        if args.compare or any(scan_flags):
            cli.error("Keşif seçenekleri için hedef gerekli: draxen example.com --deep")
        if args.quiet:
            return 0
        if args.details:
            cli.print_help(console=console)
        elif can_interact(console):
            display_args = ["--color", args.color]
            if args.width:
                display_args += ["--width", str(args.width)]
            if args.ascii_only:
                display_args.append("--ascii")
            settings = {key: getattr(args, key) for key in ("budget", "delay", "timeout", "limit", "output")}
            # Opening the control centre plays the intro and asks for the access
            # password; command-line scans and offline tools stay scriptable.
            if not AccessGate(console).run():
                return 1
            return TerminalApp(console).launch(lambda action: _main(display_args + action), cli.format_help, settings)
        else:
            console.home()
        return 0
    try:
        target = Target.parse(args.target)
    except ValueError as exc:
        cli.error(str(exc))
    if target.kind == "ip" and (args.web or args.verify):
        cli.error("--web ve --verify yalnızca alan adı veya e-posta hedefleriyle kullanılabilir")
    if target.kind == "ip" and (args.archives or args.mail or args.security or args.sitemap or args.brute):
        cli.error("--archives, --mail, --security, --sitemap ve --brute alan adı veya e-posta gerektirir")
    baseline = None
    if args.compare:
        try:
            baseline = load_baseline(args.compare, target)
        except (OSError, ValueError, RecursionError) as exc:
            cli.error("Karşılaştırma raporu okunamadı: " + str(exc))
    args.archives = args.archives or (args.deep and bool(target.domain))
    args.mail = args.mail or (args.deep and bool(target.domain))
    args.security = args.security or args.deep
    args.infra = args.infra or args.deep
    args.sitemap = args.sitemap or (args.deep and bool(target.domain))
    args.brute = args.brute or (args.deep and bool(target.domain))
    args.ports = args.ports or args.deep
    args.network = args.network or args.deep
    client = Client(delay=args.delay, timeout=args.timeout, budget=args.budget)
    report = Report(target)
    report.data["settings"] = {
        "web": args.web, "verify": args.verify, "limit": args.limit, "budget": args.budget,
        "delay": args.delay, "timeout": args.timeout, "archives": args.archives,
        "network": args.network, "mail": args.mail, "security": args.security,
        "infra": args.infra, "sitemap": args.sitemap, "brute": args.brute, "ports": args.ports,
    }
    output = args.output or Path("reports") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    progress_console = console if args.ui else error_console
    progress = ScanProgress(progress_console, report, client, args.budget) if not args.quiet else None
    if not args.quiet:
        progress_console.scan_start(target, report.data["settings"], clear=args.ui)
    collector = Collector(
        client, report, target, limit=args.limit, verify=args.verify, web=args.web,
        progress=progress, archives=args.archives, network=args.network, mail=args.mail,
        security=args.security, infra=args.infra, sitemap=args.sitemap, brute=args.brute, ports=args.ports,
    )
    interrupted = False
    with progress if progress is not None else nullcontext():
        try:
            data = collector.run()
        except KeyboardInterrupt:
            interrupted = True
            report.data["interrupted"] = True
            report.warn("İşlem kullanıcı tarafından durduruldu; bu rapor kısmidir.")
            data = report.finish(client.requests)
    analyze(data, baseline)
    try:
        paths = save_reports(data, output)
    except OSError as exc:
        error_console.error("Rapor yazılamadı: " + str(exc))
        return 1
    if not args.quiet:
        result = show_report(args, console, data, paths,
                             banner=not (console.tty and error_console.tty and error_console.decorated))
        if result == 130:
            return 130
    if interrupted:
        return 130
    return 2 if any(source["state"] != "ok" for source in data["sources"]) else 0
