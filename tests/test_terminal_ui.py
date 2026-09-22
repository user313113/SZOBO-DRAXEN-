import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.analysis import insight_level
from draxen.cli import main, parser, run_meta
from draxen.core import Report, Target
from draxen.demo import sample_report
from draxen.output import insight_severity, print_summary, terminal
from draxen.terminal_ui import (
    ESCAPES, ScanProgress, TerminalUI, cell_width, clip_text, row,
    safe_text, terminal_size, wrap_text,
)
from test_draxen import FakeClient


ENV = {"TERM": "xterm-256color", "COLORTERM": "truecolor", "COLUMNS": "80", "LINES": "40"}


class TtyStream(io.StringIO):
    def __init__(self, encoding="utf-8"):
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding

    def isatty(self):
        return True


class CellLayoutTests(unittest.TestCase):
    def test_visible_width_not_codepoint_or_ansi_length(self):
        for text, expected in (("Türkçe / İğışçöü", 16), ("e\u0301", 1), ("界面", 4),
                               ("👩\u200d💻", 2), ("👍🏽", 2), ("🇹🇷", 2), ("❤️", 2), ("a\u200db\u200dc", 3),
                               ("\x1b[38;2;1;2;3mDNS\x1b[0m", 3)):
            with self.subTest(text=text):
                self.assertEqual(cell_width(text), expected)

    def test_wrap_long_tokens_and_combining_characters(self):
        for text in ("https://example.com/" + "a" * 400, "界面" * 20,
                     "e\u0301" * 50, "👩\u200d💻" * 20, "çalışma " * 30):
            for width in (2, 3, 20, 38, 80):
                lines = wrap_text(text, width)
                self.assertTrue(all(cell_width(line) <= width for line in lines))
                self.assertEqual("".join(lines).replace(" ", ""), text.replace(" ", ""))
                self.assertTrue(all(not line.startswith("\u0301") for line in lines))

    def test_one_cell_viewport(self):
        self.assertEqual(wrap_text("界", 1), ["?"])
        self.assertEqual(clip_text("界", 1), "")
        self.assertEqual(clip_text("long", 0), "")

    def test_clip_preserves_clusters_and_reserves_marker(self):
        self.assertEqual(clip_text("e\u0301abcd", 3, "…"), "e\u0301a…")
        self.assertEqual(clip_text("界面test", 4, "…"), "界…")
        self.assertEqual(clip_text("short", 30, "…"), "short")

    def test_terminal_commands_and_bidi_are_removed(self):
        attacks = (
            "\x1b[2J", "\x1b[31m", "\x1b]0;replace-title\x07",
            "\x1b]52;c;clipboard\x1b\\", "\x1bPpayload\x1b\\",
            "\x9b2J", "\x9d0;title\x9c", "\u202e", "\u2066",
        )
        for attack in attacks:
            self.assertEqual(safe_text("before" + attack + "after"), "beforeafter")
        self.assertEqual(safe_text("a\n\r\tb"), "a   b")
        self.assertEqual(safe_text("e\u0301"), "é")
        self.assertEqual(terminal("\x1b[31mred\x1b[0m"), "red")
        self.assertEqual(safe_text("[bold red]literal[/]"), "[bold red]literal[/]")

    def test_ascii_transliteration(self):
        self.assertEqual(safe_text("İğdır / Türkçe / ŞÖÜ → …", True), "Igdir / Turkce / SOU > ...")

    def test_fd_size_takes_priority_over_stale_columns(self):
        stream = Mock()
        stream.fileno.return_value = 19
        with patch.dict(os.environ, ENV, clear=True), patch("os.get_terminal_size", return_value=os.terminal_size((38, 24))) as get_size:
            self.assertEqual(terminal_size(stream), (38, 24))
            get_size.assert_called_once_with(19)

    def test_size_fallback_handles_invalid_environment(self):
        with patch.dict(os.environ, {"COLUMNS": "invalid", "LINES": "0"}, clear=True):
            self.assertEqual(terminal_size(io.StringIO()), (80, 1))

    def test_width_tracks_resize_and_reserves_last_tty_cell(self):
        console = TerminalUI(TtyStream(), width=120)
        with patch("draxen.terminal_ui.terminal_size", side_effect=[os.terminal_size((100, 30)), os.terminal_size((38, 24))]):
            self.assertEqual(console.width, 99)
            self.assertEqual(console.width, 37)


class PresentationTests(unittest.TestCase):
    def render(self, data=None, width=80, height=40, tty=False, **kwargs):
        stream = TtyStream() if tty else io.StringIO()
        with patch.dict(os.environ, dict(ENV, COLUMNS=str(width + int(tty)), LINES=str(height)), clear=True):
            console = TerminalUI(stream, width=width, **kwargs)
            console.summary(sample_report() if data is None else data)
        return stream.getvalue()

    def assert_fits(self, text, width):
        for number, line in enumerate(text.splitlines()):
            self.assertLessEqual(cell_width(line), width, f"row {number}: {line!r}")

    def test_responsive_layout_every_breakpoint(self):
        data = sample_report()
        data["target"]["value"] = "長い例." + "a" * 180 + ".example.com"
        data["findings"][0]["value"] = "界👩\u200d💻e\u0301" * 80
        data["sources"][0]["message"] = "https://example.com/" + "b" * 200
        data["warnings"].append("Uzun uyarı " * 40)
        data["comparison"] = {"added": [], "not_observed": [], "unchanged_count": 4, "caution": "Görülmedi " * 40}
        for width in (1, 2, 8, 15, 16, 20, 24, 28, 32, 34, 38, 40, 59, 60, 63, 64, 73, 74, 75, 76, 80, 93, 94, 95, 108, 120, 160):
            with self.subTest(width=width):
                output = self.render(data, width=width, color="always")
                self.assert_fits(output, width)
                for line in ESCAPES.sub("", output).splitlines():
                    if line.startswith("│"):
                        self.assertEqual(cell_width(line), width)

    def test_raw_color_codes_do_not_shift_panel_edges(self):
        for width in (38, 80, 120):
            colored = ESCAPES.sub("", self.render(width=width, tty=True, color="always"))
            plain_colors = self.render(width=width, tty=True, color="never")
            self.assertEqual(colored, plain_colors)
            self.assert_fits(colored, width)

    def test_small_screens_use_compact_pixel_logo(self):
        large = self.render(width=108, height=40, tty=True)
        small = self.render(width=38, height=24, tty=True)
        short = self.render(width=108, height=24, tty=True)
        self.assertIn("░", small)
        self.assertIn("╚═", ESCAPES.sub("", short))
        self.assertIn("╚═", ESCAPES.sub("", large))
        self.assertNotIn("▀", small)
        self.assert_fits(small, 38)

    def test_color_capability_fallbacks(self):
        for term, colorterm, expected, absent in (
            ("xterm-256color", "truecolor", "38;2;", None),
            ("xterm-256color", "", "38;5;", "38;2;"),
            ("ansi", "", "\x1b[1;96m", "38;"),
        ):
            with self.subTest(term=term), patch.dict(os.environ, dict(ENV, TERM=term, COLORTERM=colorterm), clear=True):
                stream = TtyStream()
                TerminalUI(stream).banner()
                text = stream.getvalue()
                self.assertIn(expected, text)
                if absent:
                    self.assertNotIn(absent, text)

    def test_no_color_and_never_still_have_panels(self):
        for config, kwargs in ((dict(ENV, NO_COLOR=""), {}), (ENV, {"color": "never"})):
            with patch.dict(os.environ, config, clear=True):
                stream = TtyStream()
                TerminalUI(stream, **kwargs).banner()
                self.assertNotIn("\x1b", stream.getvalue())
                self.assertIn("╔", stream.getvalue())

    def test_explicit_always_overrides_no_color(self):
        with patch.dict(os.environ, dict(ENV, NO_COLOR="1"), clear=True):
            stream = io.StringIO()
            TerminalUI(stream, color="always").banner()
            self.assertIn("38;2;", stream.getvalue())

    def test_redirection_is_plain_and_escape_free(self):
        output = self.render()
        self.assertNotIn("\x1b", output)
        self.assertNotIn("╭", output)
        self.assertNotIn("█", output)
        self.assertIn("ÇEVRİMDIŞI DEMO", output)

    def test_dumb_plain_and_legacy_encoding_are_safe(self):
        for term, encoding, options in (("dumb", "utf-8", {"color": "always"}),
                                         ("xterm", "ascii", {"color": "never"}),
                                         ("xterm", "latin-1", {"color": "never"}),
                                         ("xterm", "utf-8", {"plain": True, "color": "always"})):
            with self.subTest(term=term, encoding=encoding, options=options), patch.dict(os.environ, dict(ENV, TERM=term), clear=True):
                stream = TtyStream(encoding)
                TerminalUI(stream, **options).summary(sample_report())
                text = stream.getvalue()
                text.encode("ascii")
                self.assertNotIn("\x1b", text)
                self.assert_fits(text, 79)

    def test_ascii_mode_preserves_structure(self):
        output = self.render(width=38, tty=True, ascii_only=True, color="never")
        self.assertIn("+= SZOBO", output)
        self.assertIn("#", output)
        output.encode("ascii")
        self.assert_fits(output, 38)

    def test_wrapped_status_prefix_is_not_repeated(self):
        console = TerminalUI(io.StringIO(), color="never")
        rows = console.paragraph("long source name is wrapping", 14, prefix="OK  ")
        lines = [console.line(spans, 14) for spans in rows]
        self.assertTrue(lines[0].startswith("OK"))
        self.assertTrue(all(line.startswith("    ") for line in lines[1:]))

    def test_summary_does_not_modify_report(self):
        data = sample_report()
        original = copy.deepcopy(data)
        self.render(data, color="always", width=38)
        self.assertEqual(data, original)

    def test_empty_report_does_not_claim_success_or_security(self):
        data = Report(Target.parse("example.com")).finish(0)
        output = self.render(data)
        self.assertIn("VERİ YOK", output)
        self.assertIn("güvenlik garantisi değildir", output)
        self.assertNotIn("TAMAMLANDI", output)

    def test_partial_sources_and_insight_priority(self):
        data = sample_report()
        data.pop("demo")
        data["sources"][0].update(state="incomplete", message="Örnek zaman aşımı")
        data["analysis"]["insights"].append({"type": "tls_cert_expired", "subject": "expired.example.com", "message": "Sertifika süresi dolmuş."})
        output = self.render(data, width=38, color="always")
        stripped = ESCAPES.sub("", output)
        self.assertIn("KISMİ RAPOR", stripped)
        self.assertIn("EKSİK", stripped)
        self.assertLess(stripped.index("KRİTİK"), stripped.index("UYARI"))
        self.assert_fits(output, 38)

    def test_severity_matches_existing_html_and_markdown(self):
        for name in ("tls_cert_expired", "cookie_security_weak", "bgp_routing_identified", "unknown"):
            self.assertEqual(insight_level(name), insight_severity(name)[0])

    def test_untrusted_markup_and_control_sequences_are_inert(self):
        data = sample_report()
        data["target"]["value"] = "[bold]example.com[/]\x1b]52;c;secrets\x07\x1b[2J"
        data["warnings"] = ["\x1b[31mred\x1b[0m\u202e warning"]
        text = self.render(data, width=38, color="never")
        self.assertNotIn("\x1b", text)
        self.assertNotIn("secrets", text)
        self.assertNotIn("[2J", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("[bold]example.com[/]", text)

    def test_long_report_folder_and_metadata_values_wrap(self):
        with patch.dict(os.environ, ENV, clear=True):
            stream = io.StringIO()
            console = TerminalUI(stream, width=38, color="always")
            console.metadata({"filename": "çekim_" + "a" * 120 + ".jpg", "file_type": "JPEG", "file_size_bytes": 1024,
                              "metadata": {"GPS": "İstanbul / 41.0082, 28.9784", "Long": "x" * 300}},
                             [Path("reports") / ("long" * 30) / "metadata_report.json"])
            self.assert_fits(stream.getvalue(), 38)
            stripped = ESCAPES.sub("", stream.getvalue())
            self.assertIn("metadata_report.json", stripped)
            self.assertIn("İstanbul", stripped)

    def test_existing_print_summary_api_remains_available(self):
        with redirect_stdout(io.StringIO()) as output:
            print_summary(sample_report())
        self.assertIn("example.com", output.getvalue())


class ProgressTests(unittest.TestCase):
    def make_progress(self, stream, width=80, plain=False):
        report = Report(Target.parse("example.com"))
        client = Mock(requests=12)
        console = TerminalUI(stream, width=width, color="never", plain=plain)
        progress = ScanProgress(console, report, client, 40, clock=lambda: 72)
        progress.started = 0
        return progress

    def test_live_frames_track_real_counters_and_width(self):
        with patch.dict(os.environ, ENV, clear=True):
            for width in (20, 38, 64, 79, 120):
                progress = self.make_progress(TtyStream(), width)
                progress.name = "Sertifika şeffaflığı / " + "界" * 100
                frame = progress.frame()
                self.assertLessEqual(cell_width(frame), min(79, width))
                if width >= 38:
                    self.assertIn("12/40 HTTP", frame)
                self.assertNotIn("%", frame)

    def test_redirected_progress_has_no_animation_controls(self):
        stream = io.StringIO()
        with patch.dict(os.environ, ENV, clear=True):
            with self.make_progress(stream, 38) as progress:
                progress("DNS / " + "a" * 100)
        text = stream.getvalue()
        self.assertNotIn("\r", text)
        self.assertNotIn("\x1b", text)
        self.assertTrue(all(cell_width(line) <= 38 for line in text.splitlines()))
        self.assertIsNone(progress._thread)

    def test_cleanup_on_interrupt_and_unexpected_error(self):
        for exception in (KeyboardInterrupt, RuntimeError):
            with self.subTest(exception=exception), patch.dict(os.environ, ENV, clear=True):
                stream = TtyStream()
                with self.assertRaises(exception):
                    with self.make_progress(stream) as progress:
                        progress("DNS")
                        raise exception()
                self.assertFalse(progress._thread.is_alive())
                self.assertTrue(stream.getvalue().endswith("\r\x1b[2K"))
                self.assertNotIn("?25l", stream.getvalue())
                self.assertNotIn("?1049h", stream.getvalue())

    def test_plain_mode_never_starts_a_thread(self):
        stream = TtyStream()
        with patch.dict(os.environ, ENV, clear=True):
            with self.make_progress(stream, plain=True) as progress:
                progress("DNS")
        self.assertIsNone(progress._thread)
        self.assertNotIn("\x1b", stream.getvalue())


class TerminalCliTests(unittest.TestCase):
    def test_demo_makes_no_network_or_implicit_file_writes(self):
        with patch("draxen.cli.Client") as client, patch("draxen.cli.Collector") as collector, patch("draxen.cli.save_reports") as save, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--demo"]), 0)
        client.assert_not_called()
        collector.assert_not_called()
        save.assert_not_called()
        self.assertIn("DEMO", output.getvalue())
        self.assertEqual(sample_report()["requests"], 0)

    def test_quiet_demo_is_completely_silent(self):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["--demo", "--quiet", "--color", "always"]), 0)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "")

    def test_demo_export_is_explicit_and_marked(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--demo", "--output", folder, "--quiet"]), 0)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertTrue(data["demo"])
            self.assertEqual(data["requests"], 0)
            self.assertEqual(len(list(Path(folder).iterdir())), 6)
            self.assertIn("DEMO", (Path(folder) / "report.md").read_text())
            html_report = (Path(folder) / "report.html").read_text()
            self.assertIn("ÇEVRİMDIŞI DEMO", html_report[:html_report.index("<h1>")])

    def test_demo_is_deterministic(self):
        self.assertEqual(sample_report(), sample_report())

    def test_demo_rejects_target_or_live_modules(self):
        for flags in (("example.com",), ("--deep",), ("--network",), ("--verify", "2"), ("--meta", "x.jpg")):
            with self.subTest(flags=flags), redirect_stderr(io.StringIO()), patch("draxen.cli.Client") as client, self.assertRaises(SystemExit):
                main(["--demo", *flags])
            client.assert_not_called()

    def test_display_options_and_width_validation(self):
        args = parser().parse_args(["--color", "never", "--ascii", "--plain", "--width", "38"])
        self.assertTrue(args.ascii_only)
        self.assertTrue(args.plain)
        self.assertEqual(args.width, 38)
        self.assertEqual(args.color, "never")
        for value in ("0", "19", "161", "x"):
            with self.subTest(value=value), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args(["--width", value])

    def test_help_and_errors_fit_a_phone(self):
        with patch.dict(os.environ, dict(ENV, COLUMNS="39"), clear=True):
            for flags in (["--color", "never", "--help"], [], ["--plain", "--help"]):
                out = TtyStream()
                with redirect_stdout(out):
                    if "--help" in flags:
                        with self.assertRaises(SystemExit) as stopped:
                            main(flags)
                        self.assertEqual(stopped.exception.code, 0)
                    else:
                        self.assertEqual(main(flags), 0)
                self.assertTrue(all(cell_width(line) <= 38 for line in out.getvalue().splitlines()))
                if "--help" in flags:
                    self.assertIn("--demo", out.getvalue())
                    self.assertIn("--compare", out.getvalue())
                else:
                    self.assertIn("KONTROL MERKEZİ", out.getvalue())
                    self.assertIn("--ui", out.getvalue())
                    self.assertNotIn("--compare", out.getvalue())
            err = TtyStream()
            with redirect_stderr(err), self.assertRaises(SystemExit):
                main(["not-a-domain"])
            self.assertTrue(all(cell_width(line) <= 38 for line in err.getvalue().splitlines()))

    def test_normal_scan_retains_reports_and_exit_status(self):
        fixture = {"crt.sh": [{"name_value": "api.example.com"}], "rdap.org": {"objectClassName": "domain"}}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, dict(ENV, COLUMNS="38"), clear=True), patch("draxen.cli.Client", return_value=FakeClient(fixture)), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["example.com", "--output", folder]), 0)
            self.assertEqual(len(list(Path(folder).iterdir())), 6)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertEqual(data["findings"][0]["value"], "api.example.com")
        for text in (out.getvalue(), err.getvalue()):
            self.assertNotIn("\x1b", text)
            self.assertTrue(all(cell_width(line) <= 38 for line in text.splitlines()))

    def test_failed_source_exit_code_remains_two(self):
        data = sample_report()
        data.pop("demo")
        data["sources"][0]["state"] = "incomplete"
        with tempfile.TemporaryDirectory() as folder, patch("draxen.cli.Collector.run", return_value=data), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["example.com", "--output", folder]), 2)
        self.assertIn("KISMİ RAPOR", out.getvalue())

    def test_visible_interrupted_scan_saves_partial_report(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, dict(ENV, COLUMNS="39"), clear=True), patch("draxen.cli.Collector.run", side_effect=KeyboardInterrupt), redirect_stdout(TtyStream()) as out, redirect_stderr(TtyStream()) as err:
            self.assertEqual(main(["example.com", "--output", folder]), 130)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertTrue(data["interrupted"])
            self.assertTrue(any("kısmidir" in warning for warning in data["warnings"]))
            self.assertIn("KISMİ RAPOR", ESCAPES.sub("", out.getvalue()))
        self.assertNotIn("?25l", err.getvalue())

    def test_metadata_errors_are_safe_and_wrapped(self):
        with patch.dict(os.environ, dict(ENV, COLUMNS="38"), clear=True), patch("draxen.cli.extract_metadata", side_effect=OSError("\x1b[2J" + "uzun " * 70)), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(run_meta(Path("missing.jpg"), None, False), 1)
        self.assertNotIn("\x1b", err.getvalue())
        self.assertNotIn("[2J", err.getvalue())
        self.assertTrue(all(cell_width(line) <= 38 for line in err.getvalue().splitlines()))

    def test_report_write_error_is_still_failure(self):
        with patch("draxen.cli.save_reports", side_effect=OSError("not writable")), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["--demo", "--output", "reports", "--quiet"]), 1)
        self.assertIn("Rapor yazılamadı", err.getvalue())


class PreviewAndPtyTests(unittest.TestCase):
    def test_browser_preview_escapes_literal_markup(self):
        from tools.preview_terminal import ansi_html
        result = ansi_html("\x1b[1;38;2;1;2;3m<script>literal</script>\x1b[0m")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;literal&lt;/script&gt;", result)
        self.assertIn("color:rgb(1,2,3)", result)

    def test_browser_preview_is_self_contained(self):
        from tools.preview_terminal import build_preview
        with tempfile.TemporaryDirectory() as folder:
            path = build_preview(Path(folder) / "index.html")
            page = path.read_text(encoding="utf-8")
        self.assertEqual(page.count('<template id="view-'), 9)
        self.assertIn('view-38-ascii', page)
        self.assertIn('view-108-color', page)
        self.assertIn('view-80-plain', page)
        self.assertNotIn('<script src=', page)
        self.assertNotIn('fonts.googleapis', page)

    def test_validation_errors_respect_parsed_display_options(self):
        with patch.dict(os.environ, ENV, clear=True):
            for flags in (["--plain", "bad"], ["--color", "never", "--width", "19"]):
                with redirect_stderr(TtyStream()) as out, self.assertRaises(SystemExit):
                    main(flags)
                self.assertNotIn("\x1b", out.getvalue())
                if "--plain" in flags:
                    out.getvalue().encode("ascii")

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX pseudo-terminal test")
    def test_actual_terminal_sizes_override_environment(self):
        import fcntl
        import pty
        import select
        import struct
        import subprocess
        import termios

        for columns in (24, 38, 80, 120):
            with self.subTest(columns=columns):
                master, slave = pty.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, columns, 0, 0))
                env = dict(os.environ, **dict(ENV, COLUMNS="500"))
                env.pop("NO_COLOR", None)
                process = subprocess.Popen([sys.executable, "-m", "draxen", "--demo"],
                                           stdout=slave, stderr=slave, env=env,
                                           cwd=Path(__file__).resolve().parents[1])
                os.close(slave)
                chunks = []
                try:
                    while True:
                        ready, _, _ = select.select([master], [], [], 5)
                        self.assertTrue(ready, "Demo did not finish within the PTY deadline")
                        try:
                            part = os.read(master, 65536)
                        except OSError:
                            break  # Linux PTYs signal EOF with EIO.
                        if not part:
                            break
                        chunks.append(part)
                    self.assertEqual(process.wait(timeout=5), 0)
                finally:
                    os.close(master)
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                output = b"".join(chunks).decode("utf-8")
                self.assertIn("38;2;", output)
                self.assertLessEqual(max(map(cell_width, output.splitlines())), columns - 1)


if __name__ == "__main__":
    unittest.main()
