import copy
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.cli import main
from draxen.demo import sample_report
from draxen.core import Target
from draxen.gate import AccessGate
from draxen.terminal_app import LeaveUI, TerminalApp, can_interact
from draxen.terminal_art import gradient, wordmark
from draxen.terminal_ui import ESCAPES, TerminalUI, cell_width, row
from test_draxen import FakeClient
from test_terminal_ui import ENV, TtyStream


class NativeLayoutTests(unittest.TestCase):
    def console(self, width, height, **kwargs):
        stream = TtyStream()
        console = TerminalUI(stream, **kwargs)
        size = patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, height)))
        self.addCleanup(size.stop)
        size.start()
        return console

    def assert_screen_fits(self, lines, width, height):
        self.assertLessEqual(len(lines), max(1, height - 2))
        for line in lines:
            self.assertLessEqual(cell_width(line), max(1, width - 1), repr(line))

    def test_complete_wordmarks_without_cropping(self):
        for width, height, style in ((112, 6, "shadow-inline"), (75, 13, "shadow-stacked"),
                                      (33, 13, "pixel-stacked"), (25, 13, "micro-stacked"),
                                      (75, 6, "shadow-compact"), (16, 1, "text")):
            result = wordmark(width, height)
            self.assertEqual(result.style, style)
            self.assertLessEqual(result.width, width)
            self.assertLessEqual(len(result.lines), height)
        self.assertEqual(wordmark(1, 1).lines, ())

    def test_reference_gradient_has_four_hues(self):
        self.assertEqual(gradient(0), (151, 94, 255))
        self.assertEqual(gradient(1), (0, 239, 160))
        self.assertEqual(gradient(1 / 3), (50, 128, 255))
        self.assertEqual(gradient(2 / 3), (0, 196, 239))

    def test_home_and_dashboard_fit_width_and_height(self):
        data = sample_report()
        data["target"]["value"] = "very-long-" * 20 + ".example.com"
        data["analysis"]["insights"][0]["message"] = "界 Türkçe " * 100
        with patch.dict(os.environ, ENV, clear=True):
            for width in (20, 24, 28, 32, 38, 40, 60, 64, 80, 114, 120, 160):
                for height in (12, 16, 20, 24, 28, 40):
                    with self.subTest(width=width, height=height), patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, height))):
                        console = TerminalUI(TtyStream())
                        for interactive in (False, True):
                            self.assert_screen_fits(console.home_lines(interactive=interactive), width, height)
                            self.assert_screen_fits(console.dashboard_lines(data, interactive=interactive), width, height)

    def test_small_and_wide_home_have_both_brand_words_and_every_action(self):
        with patch.dict(os.environ, ENV, clear=True):
            for width in (38, 64, 80, 120):
                with self.subTest(width=width), patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, 24))):
                    lines = TerminalUI(TtyStream()).home_lines(interactive=True)
                    text = ESCAPES.sub("", "\n".join(lines))
                    self.assertIn("SZOBO / DRAXEN", text)
                    for token in ("01", "02", "03", "04", "05", "H", "Q"):
                        self.assertIn(token, text)
                    self.assertGreaterEqual(text.count("█"), 60)
                    self.assertNotIn("--archives", text)
                    self.assert_screen_fits(lines, width, 24)

    def test_monochrome_and_ascii_home_still_fit(self):
        with patch.dict(os.environ, ENV, clear=True):
            console = self.console(38, 24, color="never", ascii_only=True)
            lines = console.home_lines(interactive=True)
            text = "\n".join(lines)
            text.encode("ascii")
            self.assertNotIn("\x1b", text)
            self.assertIn("#", text)
            self.assert_screen_fits(lines, 38, 24)

    def test_scan_start_fits_even_with_long_target_and_all_modules(self):
        target = Target.parse(("a" * 63 + ".") * 3 + "example.com")
        settings = dict(sample_report()["settings"], archives=True, network=True, mail=True,
                        security=True, infra=True, sitemap=True, brute=True, ports=True, web=True, verify=5)
        with patch.dict(os.environ, ENV, clear=True):
            for width in (20, 24, 32, 38, 64, 80, 120):
                for height in (12, 16, 20, 24, 28):
                    with self.subTest(width=width, height=height), patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, height))):
                        output = TtyStream()
                        TerminalUI(output).scan_start(target, settings)
                        self.assert_screen_fits(output.getvalue().splitlines(), width, height)

    def test_interaction_requires_usable_geometry_and_both_ttys(self):
        with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()):
            for columns, lines, expected in ((38, 24, True), (21, 12, True), (20, 12, False), (38, 11, False)):
                with patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((columns, lines))):
                    self.assertEqual(can_interact(TerminalUI(TtyStream())), expected)
            self.assertFalse(can_interact(TerminalUI(io.StringIO(), color="always")))
            with redirect_stdin(io.StringIO()):
                self.assertFalse(can_interact(TerminalUI(TtyStream())))

    def test_preview_does_not_mutate_data(self):
        data = sample_report()
        original = copy.deepcopy(data)
        with patch.dict(os.environ, ENV, clear=True):
            console = self.console(38, 24)
            console.dashboard_lines(data)
            app = TerminalApp(console)
            for section in ("2", "3", "4", "5"):
                app._report_rows(data, section, [])
        self.assertEqual(data, original)

    def test_summary_is_not_a_fake_security_pass(self):
        data = sample_report()
        data.pop("demo")
        data["sources"][0].update(state="incomplete", message="Kaynak zaman aşımı")
        with patch.dict(os.environ, ENV, clear=True):
            console = self.console(38, 24, color="never")
            text = "\n".join(console.dashboard_lines(data))
        self.assertIn("KISMİ RAPOR", text)
        self.assertIn("Eksik kaynak", text)


class NativeInteractionTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, dict(ENV, COLUMNS="39", LINES="24"), clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.output = TtyStream()
        self.console = TerminalUI(self.output)

    def app(self, inputs):
        return TerminalApp(self.console, reader=Mock(side_effect=inputs))

    def test_opening_and_quitting_never_runs_any_action(self):
        runner = Mock()
        self.assertEqual(self.app(["q"]).launch(runner, lambda: "help"), 0)
        runner.assert_not_called()
        self.assertIn("KONTROL MERKEZİ", self.output.getvalue())
        self.assertNotIn("?25l", self.output.getvalue())
        self.assertNotIn("?1049h", self.output.getvalue())

    def test_invalid_choice_and_enter_redraw_without_scanning(self):
        runner = Mock()
        self.assertEqual(self.app(["not-an-action", "", "q"]).launch(runner, lambda: "help"), 0)
        runner.assert_not_called()
        self.assertIn("01–05", self.output.getvalue())

    def test_quick_scan_requires_explicit_confirmation(self):
        for response in ("", "h", "hayır", "q"):
            runner = Mock()
            result = self.app(["1", "example.com", response, "q"]).launch(runner, lambda: "help")
            self.assertEqual(result, 0)
            runner.assert_not_called()

    def test_invalid_targets_do_not_reach_runner(self):
        runner = Mock()
        self.app(["1", "127.0.0.1", "", "q"]).launch(runner, lambda: "help")
        runner.assert_not_called()
        self.assertIn("HATA", self.output.getvalue())

    def test_confirmed_deep_scan_preserves_budget_and_target(self):
        runner = Mock(return_value=0)
        settings = {"budget": 12, "delay": 2.5, "timeout": 8, "limit": 20, "output": "reports/native"}
        result = self.app(["2", "example.com", "e", "q"]).launch(runner, lambda: "help", settings)
        self.assertEqual(result, 0)
        args = runner.call_args.args[0]
        self.assertIn("--deep", args)
        self.assertEqual(args[args.index("--budget") + 1], "12")
        self.assertEqual(args[args.index("--output") + 1], "reports/native")
        self.assertEqual(args[-2:], ["--", "example.com"])

    def test_metadata_file_is_not_interpreted_as_a_flag(self):
        runner = Mock(return_value=0)
        self.app(["3", "--my image.jpg", "q"]).launch(runner, lambda: "help")
        self.assertIn("--meta=--my image.jpg", runner.call_args.args[0])

    def test_demo_dispatch_is_offline_and_interrupt_propagates(self):
        runner = Mock(return_value=130)
        self.assertEqual(self.app(["4"]).launch(runner, lambda: "help"), 130)
        runner.assert_called_once_with(["--demo", "--ui"])

    def test_help_can_be_paged_and_returns_to_the_menu(self):
        runner = Mock()
        text = "\n".join(f"command-{i:03d}" for i in range(80))
        self.assertEqual(self.app(["h", "n", "p", "q", "q"]).launch(runner, lambda: text), 0)
        runner.assert_not_called()
        self.assertIn("command-000", ESCAPES.sub("", self.output.getvalue()))
        self.assertIn("KOMUTLAR", self.output.getvalue())

    def test_long_forms_page_without_hiding_or_discarding_rows(self):
        text = "\n".join(f"line-{i:03d}" for i in range(60))
        for width, height in ((21, 12), (32, 16), (38, 24), (80, 24)):
            with self.subTest(width=width, height=height), patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, height))):
                output = TtyStream()
                app = TerminalApp(TerminalUI(output), reader=Mock(return_value="n"))
                self.assertTrue(app._form("ONAY", text))
                rendered = ESCAPES.sub("", output.getvalue())
                for number in range(60):
                    self.assertEqual(rendered.count(f"line-{number:03d}"), 1)
                for frame in output.getvalue().split("\x1b[H\x1b[2J"):
                    if frame:
                        self.assertLessEqual(len(frame.splitlines()), height - 1)
                        self.assertTrue(all(cell_width(line) <= width - 1 for line in frame.splitlines()))

    def test_cancelling_long_confirmation_never_starts_scan(self):
        target = ("a" * 63 + ".") * 3 + "example.com"
        runner = Mock()
        settings = {"budget": 40, "delay": 1.5, "timeout": 15, "limit": 100}
        with patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((38, 16))):
            self.app([target, "q"])._scan(runner, settings, deep=True)
        runner.assert_not_called()
        self.assertIn("Devam", self.output.getvalue())
        self.assertNotIn("Başlat?", self.output.getvalue())

    def test_eof_and_interrupt_leave_a_usable_terminal(self):
        for exception, code in ((EOFError, 0), (KeyboardInterrupt, 130)):
            with self.subTest(exception=exception):
                self.assertEqual(self.app([exception()]).launch(Mock(), lambda: ""), code)
                self.assertNotIn("?25l", self.output.getvalue())
                self.assertNotIn("?1049h", self.output.getvalue())

    def test_report_navigation_shows_all_sections(self):
        app = self.app(["2", "n", "3", "n", "4", "5", "1", "q"])
        self.assertEqual(app.report_viewer(sample_report(), [Path("reports/example/report.json")]), 0)
        text = ESCAPES.sub("", self.output.getvalue())
        for title in ("KAYNAK DURUMU", "BULGULAR", "ANALİZ / NOTLAR", "RAPOR DOSYALARI"):
            self.assertIn(title, text)
        self.assertIn("report.json", text)

    def test_pagination_does_not_discard_final_rows(self):
        app = self.app([])
        rows = [row(f"record-{number:03d}") for number in range(100)]
        _, _, total = app.page_lines(rows, "KAYITLAR", 0, report=True)
        output = []
        for page in range(total):
            lines, actual, count = app.page_lines(rows, "KAYITLAR", page, report=True)
            self.assertEqual(actual, page)
            self.assertEqual(count, total)
            self.assertLessEqual(len(lines), 22)
            self.assertTrue(all(cell_width(line) <= 38 for line in lines))
            output += lines
        text = ESCAPES.sub("", "\n".join(output))
        for number in range(100):
            self.assertEqual(text.count(f"record-{number:03d}"), 1)

    def test_more_than_ten_findings_are_available_without_truncation(self):
        data = sample_report()
        data["findings"] = [{"kind": "dns_a", "value": f"full-value-{i:03d}", "subject": "example.com"} for i in range(60)]
        rows = self.app([])._report_rows(data, "3", [])
        text = "\n".join(self.console.line(parts) for parts in rows)
        self.assertIn("full-value-059", ESCAPES.sub("", text))
        self.assertIn("Özne", ESCAPES.sub("", text))


PASSWORD = "szobodraxen1881"  # Default access password; only its PBKDF2 digest ships in the package.


class FakeClock:
    """Monotonic stand-in that advances on every read, so animations finish instantly."""
    def __init__(self, step=0.1):
        self.now = 0.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


def unlocked(*secrets):
    """Patch the CLI's access gate: no real delays, password answers supplied."""
    answers = list(secrets) or [PASSWORD]

    def factory(console):
        return AccessGate(console, sleep=lambda seconds: None, clock=FakeClock(),
                          secret_reader=Mock(side_effect=answers))
    return patch("draxen.cli.AccessGate", side_effect=factory)


class NativeCliTests(unittest.TestCase):
    def test_explicit_ui_rejects_pipes_without_starting_a_client(self):
        with redirect_stdin(io.StringIO()), redirect_stderr(io.StringIO()), patch("draxen.cli.Client") as client, self.assertRaises(SystemExit) as stopped:
            main(["--ui"])
        self.assertEqual(stopped.exception.code, 2)
        client.assert_not_called()

    def test_tiny_terminal_exits_with_resize_hint_instead_of_waiting(self):
        with patch.dict(os.environ, ENV, clear=True), patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((38, 8))), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, patch("builtins.input") as read:
            self.assertEqual(main([]), 0)
        read.assert_not_called()
        self.assertIn("terminali büyütün", " ".join(ESCAPES.sub("", output.getvalue()).split()))

    @unittest.skipUnless(shutil.which("sh"), "POSIX launcher")
    def test_packaged_checkout_is_clean_and_runs_without_installation(self):
        from tools.package_terminal import build_package, PREFIX
        from zipfile import ZipFile
        with tempfile.TemporaryDirectory() as folder:
            archive_path = build_package(Path(folder) / "native.zip")
            with ZipFile(archive_path) as archive:
                names = archive.namelist()
                self.assertIn(PREFIX + "/start.sh", names)
                self.assertIn(PREFIX + "/draxen/terminal_app.py", names)
                self.assertFalse(any(part in name for name in names for part in (".git/", "reports/", "__pycache__/")))
                archive.extractall(Path(folder) / "unpacked")
            script = Path(folder) / "unpacked" / PREFIX / "start.sh"
            result = subprocess.run(["sh", str(script), "--banner", "--plain"], cwd=folder,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SZOBO / DRAXEN", result.stdout)

    def test_full_menu_demo_flow_uses_no_client_or_file_writes(self):
        with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, unlocked(), patch("builtins.input", side_effect=["4", "3", "n", "4", "5", "q", "q"]), patch("draxen.cli.Client") as client, patch("draxen.cli.save_reports") as save:
            self.assertEqual(main([]), 0)
        client.assert_not_called()
        save.assert_not_called()
        text = ESCAPES.sub("", output.getvalue())
        self.assertIn("ERİŞİM ONAYLANDI", text)
        self.assertIn("KONTROL MERKEZİ", output.getvalue())
        self.assertIn("DEMO / AĞ İSTEĞİ YOK", text)
        self.assertLess(text.index("ERİŞİM KONTROLÜ"), text.index("KONTROL MERKEZİ"))

    def test_menu_opens_only_after_the_access_password(self):
        with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, unlocked("yanlış", "yine yanlış", "üçüncü"), patch("builtins.input") as read, patch("draxen.cli.Client") as client:
            self.assertEqual(main([]), 1)
        read.assert_not_called()
        client.assert_not_called()
        text = ESCAPES.sub("", output.getvalue())
        self.assertNotIn("KONTROL MERKEZİ", text)
        self.assertIn("ERİŞİM REDDEDİLDİ", text)
        self.assertIn("KİLİTLENDİ", text)

    def test_interrupt_and_eof_at_the_password_prompt_exit_cleanly(self):
        for interrupt, code in ((KeyboardInterrupt(), 130), (EOFError(), 1)):
            with self.subTest(code=code), patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, unlocked(interrupt), patch("builtins.input") as read, patch("draxen.cli.Client") as client:
                self.assertEqual(main([]), code)
            read.assert_not_called()
            client.assert_not_called()
            self.assertNotIn("KONTROL MERKEZİ", output.getvalue())
            self.assertNotIn("?25l", output.getvalue())
            self.assertNotIn("?1049h", output.getvalue())

    def test_eof_and_interrupt_exit_nested_demo_instead_of_reopening_menu(self):
        for interrupt, code in ((EOFError(), 0), (KeyboardInterrupt(), 130)):
            with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, unlocked(), patch("builtins.input", side_effect=["4", interrupt]) as read, patch("draxen.cli.Client") as client:
                self.assertEqual(main([]), code)
            self.assertEqual(read.call_count, 2)
            self.assertEqual(output.getvalue().count("KONTROL MERKEZİ"), 1)
            client.assert_not_called()

    def test_eof_exits_nested_metadata_instead_of_reopening_menu(self):
        data = {"filename": "local.png", "file_type": "PNG", "file_size_bytes": 24, "metadata": {"Title": "Yerel"}}
        with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as output, unlocked(), patch("builtins.input", side_effect=["3", "local.png", EOFError()]), patch("draxen.cli.extract_metadata", return_value=data):
            self.assertEqual(main([]), 0)
        self.assertEqual(output.getvalue().count("KONTROL MERKEZİ"), 1)

    def test_quiet_does_not_open_an_input_loop(self):
        with patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as out, redirect_stderr(TtyStream()) as err, patch("builtins.input") as read:
            self.assertEqual(main(["--quiet"]), 0)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "")
        read.assert_not_called()

    def test_explicit_ui_scan_still_saves_six_reports(self):
        fixture = {"crt.sh": [{"name_value": "api.example.com"}], "rdap.org": {"objectClassName": "domain"}}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, ENV, clear=True), redirect_stdin(TtyStream()), redirect_stdout(TtyStream()) as out, redirect_stderr(TtyStream()), patch("builtins.input", return_value="q"), patch("draxen.cli.Client", return_value=FakeClient(fixture)):
            self.assertEqual(main(["example.com", "--ui", "--output", folder]), 0)
            self.assertEqual(len(list(Path(folder).iterdir())), 6)
        self.assertIn("example.com", out.getvalue())

    def test_default_terminal_demo_fits_one_screen_and_details_is_opt_in(self):
        with patch.dict(os.environ, dict(ENV, COLUMNS="39", LINES="24"), clear=True):
            with redirect_stdout(TtyStream()) as compact:
                self.assertEqual(main(["--demo"]), 0)
            with redirect_stdout(TtyStream()) as detailed:
                self.assertEqual(main(["--demo", "--details"]), 0)
        self.assertLessEqual(len(compact.getvalue().splitlines()), 22)
        self.assertGreater(len(detailed.getvalue().splitlines()), 24)
        self.assertIn("BULGU ÖNİZLEMESİ", ESCAPES.sub("", detailed.getvalue()))

    def test_banner_mode_is_not_a_scan(self):
        with patch("draxen.cli.Client") as client, patch("draxen.cli.save_reports") as save, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--banner"]), 0)
        self.assertIn("SZOBO / DRAXEN", out.getvalue())
        client.assert_not_called()
        save.assert_not_called()

    @unittest.skipUnless(shutil.which("sh"), "POSIX launcher")
    def test_launcher_uses_its_checkout_from_another_directory(self):
        script = Path(__file__).resolve().parents[1] / "start.sh"
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run(["sh", str(script), "--banner", "--plain"], cwd=cwd,
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SZOBO / DRAXEN", result.stdout)

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX pseudo-terminal")
    def test_actual_native_entry_demo_navigation_and_resize(self):
        import fcntl
        import pty
        import select
        import struct
        import termios
        import time

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 38, 0, 0))
        env = dict(os.environ, TERM="xterm-256color", COLORTERM="")
        env.pop("NO_COLOR", None)
        # A new session detaches the child from the developer's terminal, so the
        # hidden password read uses the pseudo-terminal like Termux/iSH would.
        process = subprocess.Popen([sys.executable, "-m", "draxen"], stdin=slave, stdout=slave, stderr=slave,
                                   cwd=Path(__file__).resolve().parents[1], env=env, start_new_session=True)
        os.close(slave)

        def read_prompt(marker="Seçim > ", timeout=15):
            received = b""
            deadline = time.monotonic() + timeout
            while marker not in ESCAPES.sub("", received.decode("utf-8", "replace")):
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, "Native UI did not show " + repr(marker))
                ready, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(ready)
                received += os.read(master, 65536)
            return received.decode("utf-8")

        try:
            intro = read_prompt("Şifre > ")
            self.assertIn("38;5;", intro)  # iSH-style 256-color capability, not forced RGB.
            plain_intro = ESCAPES.sub("", intro)
            self.assertIn("SİSTEM", plain_intro)
            self.assertIn("ERİŞİM KONTROLÜ", plain_intro)
            self.assertNotIn("KONTROL MERKEZİ", plain_intro)
            self.assertNotIn("?25l", intro)
            self.assertNotIn("?1049h", intro)
            os.write(master, b"yanlis-sifre\n")
            denied = read_prompt("Şifre > ")
            self.assertIn("ERİŞİM REDDEDİLDİ", ESCAPES.sub("", denied))
            self.assertNotIn("yanlis-sifre", ESCAPES.sub("", denied))  # Never echoed.
            os.write(master, b"szobodraxen1881\n")
            first = read_prompt()
            self.assertIn("ERİŞİM ONAYLANDI", ESCAPES.sub("", first))
            self.assertNotIn("szobodraxen1881", ESCAPES.sub("", first))
            self.assertIn("KONTROL MERKEZİ", first)
            home = first.split("\x1b[2J")[-1]
            self.assertLessEqual(len(ESCAPES.sub("", home).splitlines()), 23)
            self.assertLessEqual(max(map(cell_width, home.splitlines())), 37)
            os.write(master, b"4\n")
            self.assertIn("DEMO / AĞ İSTEĞİ YOK", ESCAPES.sub("", read_prompt()))
            os.write(master, b"3\n")
            self.assertIn("BULGULAR", ESCAPES.sub("", read_prompt()))
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 20, 32, 0, 0))
            os.write(master, b"\n")  # Enter redraws against the new viewport.
            resized = read_prompt()
            last_frame = resized.split("\x1b[2J")[-1]
            self.assertLessEqual(max(map(cell_width, last_frame.splitlines())), 31)
            self.assertLessEqual(len(last_frame.splitlines()), 19)
            os.write(master, b"q\n")
            self.assertIn("KONTROL MERKEZİ", read_prompt())
            os.write(master, b"q\n")
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX pseudo-terminal")
    def test_actual_native_entry_enter_skips_intro_and_three_failures_lock(self):
        import fcntl
        import pty
        import select
        import struct
        import termios
        import time

        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 38, 0, 0))
        env = dict(os.environ, TERM="xterm-256color", COLORTERM="")
        env.pop("NO_COLOR", None)
        process = subprocess.Popen([sys.executable, "-m", "draxen"], stdin=slave, stdout=slave, stderr=slave,
                                   cwd=Path(__file__).resolve().parents[1], env=env, start_new_session=True)
        os.close(slave)

        def read_until(marker, timeout=15):
            received = b""
            deadline = time.monotonic() + timeout
            while marker not in ESCAPES.sub("", received.decode("utf-8", "replace")):
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, "Native UI did not show " + repr(marker))
                ready, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(ready)
                chunk = os.read(master, 65536)
                if not chunk:
                    break
                received += chunk
            return received.decode("utf-8", "replace")

        try:
            started = time.monotonic()
            os.write(master, b"\n")  # Enter during the intro skips straight to the prompt.
            read_until("Şifre > ")
            self.assertLess(time.monotonic() - started, 2.0)
            for attempt in (b"a\n", b"b\n"):
                os.write(master, attempt)
                self.assertIn("ERİŞİM REDDEDİLDİ", ESCAPES.sub("", read_until("Şifre > ")))
            os.write(master, b"c\n")
            self.assertIn("KİLİTLENDİ", ESCAPES.sub("", read_until("KİLİTLENDİ")))
            self.assertEqual(process.wait(timeout=10), 1)
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


class redirect_stdin:
    """contextlib has no redirect_stdin on the supported Python versions."""
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        self.original, sys.stdin = sys.stdin, self.stream
        return self.stream

    def __exit__(self, *exc):
        sys.stdin = self.original


if __name__ == "__main__":
    unittest.main()
