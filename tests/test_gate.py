import io
import os
import platform
import sys
import unittest
from unittest.mock import Mock, patch

from draxen import __version__
from draxen.gate import (
    ITERATIONS, MAX_ATTEMPTS, PASSWORD_DIGEST, AccessGate, digest, ease_out, fit_parts,
    system_checks, verify,
)
from draxen.terminal_app import LeaveUI
from draxen.terminal_ui import ESCAPES, REVEAL_EDGE, TerminalUI, cell_width, static_glyph
from test_terminal_app import PASSWORD, FakeClock
from test_terminal_ui import ENV, TtyStream


STAGES = ("checks", "reveal", "prompt", "denied", "locked", "granted")


class DigestTests(unittest.TestCase):
    def test_default_password_matches_shipped_digest_only(self):
        self.assertTrue(verify(PASSWORD))
        for wrong in ("", " ", PASSWORD.upper(), PASSWORD + " ", PASSWORD[:-1], "szobo draxen 1881", None, 1881):
            with self.subTest(wrong=wrong):
                self.assertFalse(verify(wrong))

    def test_digest_is_pbkdf2_hex_and_source_holds_no_clear_text(self):
        self.assertEqual(digest(PASSWORD), PASSWORD_DIGEST)
        self.assertEqual(len(PASSWORD_DIGEST), 64)
        int(PASSWORD_DIGEST, 16)
        self.assertGreaterEqual(ITERATIONS, 10_000)
        self.assertNotEqual(digest("başka"), PASSWORD_DIGEST)
        with open(os.path.join(os.path.dirname(__file__), "..", "draxen", "gate.py"), encoding="utf-8") as handle:
            self.assertNotIn(PASSWORD, handle.read())


class FrameLayoutTests(unittest.TestCase):
    def gate(self, width, height, **kwargs):
        size = patch("draxen.terminal_ui.terminal_size", return_value=os.terminal_size((width, height)))
        size.start()
        self.addCleanup(size.stop)
        self.output = TtyStream()
        console = TerminalUI(self.output, **kwargs)
        return AccessGate(console, sleep=lambda seconds: None, clock=FakeClock(), secret_reader=Mock())

    def assert_screen_fits(self, lines, width, height):
        self.assertLessEqual(len(lines), max(1, height - 2))
        for line in lines:
            self.assertLessEqual(cell_width(line), max(1, width - 1), repr(line))

    def test_every_stage_fits_width_and_height(self):
        animated = [("checks", t, 1) for t in (0.0, 0.3, 0.6, 1.0)] + [("reveal", t, 1) for t in (0.0, 0.5, 1.0)]
        animated += [("granted", t, 1) for t in (0.0, 0.5, 1.0)]
        static = [(stage, 1.0, attempt) for stage in ("prompt", "denied", "locked") for attempt in (1, MAX_ATTEMPTS)]
        with patch.dict(os.environ, ENV, clear=True):
            for width in (20, 21, 24, 28, 32, 38, 40, 64, 80, 108, 120, 160):
                for height in (12, 14, 16, 20, 24, 28, 40):
                    with self.subTest(width=width, height=height):
                        gate = self.gate(width, height)
                        for stage, t, attempt in animated + static:
                            self.assert_screen_fits(gate.frame(stage, t, attempt), width, height)

    def test_prompt_screen_shares_the_home_layout_so_the_logo_does_not_jump(self):
        with patch.dict(os.environ, ENV, clear=True):
            for width, height in ((38, 24), (80, 24), (80, 40), (108, 40)):
                with self.subTest(width=width, height=height):
                    gate = self.gate(width, height)
                    frame = [ESCAPES.sub("", line) for line in gate.frame("prompt")]
                    home = [ESCAPES.sub("", line) for line in gate.console.home_lines(interactive=True)]
                    logo = lambda lines: [line for line in lines if "█" in line]
                    self.assertEqual(logo(frame), logo(home))
                    self.assertEqual(frame.index(logo(frame)[0]), home.index(logo(home)[0]))

    def test_reveal_ends_exactly_on_the_static_banner(self):
        with patch.dict(os.environ, ENV, clear=True):
            for width, height in ((38, 24), (80, 40), (112, 30)):
                with self.subTest(width=width):
                    gate = self.gate(width, height)
                    console = gate.console
                    final = console.banner_lines(max_height=16, reveal=1 + REVEAL_EDGE, shimmer=7)
                    self.assertEqual(final, console.banner_lines(max_height=16))
                    hidden = ESCAPES.sub("", "\n".join(console.banner_lines(max_height=16, reveal=-REVEAL_EDGE)))
                    shown = ESCAPES.sub("", "\n".join(final))
                    self.assertNotIn("███", hidden)
                    self.assertIn("███", shown)
                    self.assertEqual(hidden.count("\n"), shown.count("\n"))
                    halfway = ESCAPES.sub("", "\n".join(console.banner_lines(max_height=16, reveal=0.5)))
                    self.assertIn("█", halfway)
                    self.assertTrue(set("░▒") & set(halfway))

    def test_shimmer_is_deterministic_and_moves_between_frames(self):
        cells = [(x, y) for x in range(40) for y in range(6)]
        first = [static_glyph(x, y, 1) for x, y in cells]
        self.assertEqual(first, [static_glyph(x, y, 1) for x, y in cells])
        self.assertNotEqual(first, [static_glyph(x, y, 2) for x, y in cells])
        self.assertTrue(set(first) <= {"░", "▒", " "})
        self.assertGreater(first.count("░") + first.count("▒"), len(first) // 3)

    def test_checks_resolve_in_order_and_use_real_local_facts(self):
        with patch.dict(os.environ, ENV, clear=True):
            gate = self.gate(80, 24)
            for label, detail, status, tone in gate.checks:
                self.assertTrue(label and detail and status and tone)
            details = " / ".join(" ".join(detail) for _, detail, _, _ in gate.checks)
            self.assertIn(platform.python_version(), details)
            self.assertIn("v" + __version__, details)
            self.assertIn(f"{gate.console.width}×24", details)  # The TTY reserves its last column.
            self.assertIn("istek yok", details)
            start = ESCAPES.sub("", "\n".join(gate.frame("checks", 0.0)))
            end = ESCAPES.sub("", "\n".join(gate.frame("checks", 1.0)))
            self.assertLess(start.count("HAZIR"), 2)
            self.assertEqual(end.count("HAZIR"), 3)
            self.assertIn("BAŞLATILIYOR", end)
            self.assertIn("PASİF", end)
            ready = ESCAPES.sub("", "\n".join(gate.frame("reveal", 1.0)))
            self.assertEqual(ready.count("HAZIR"), 3 + 1)  # Three rows plus the panel badge.
            self.assertIn("Enter: animasyonu atla", start)
            self.assertNotIn("Enter: animasyonu atla", end)

    def test_ascii_monochrome_frames_are_pure_ascii(self):
        with patch.dict(os.environ, ENV, clear=True):
            gate = self.gate(38, 24, color="never", ascii_only=True)
            for stage in STAGES:
                for t in (0.0, 0.4, 1.0):
                    text = "\n".join(gate.frame(stage, t, 2))
                    text.encode("ascii")
                    self.assertNotIn("\x1b", text)
            self.assertIn("ERISIM KONTROLU", "\n".join(gate.frame("prompt")))

    def test_tiny_viewport_gets_a_resize_hint_instead_of_a_broken_frame(self):
        with patch.dict(os.environ, ENV, clear=True):
            gate = self.gate(18, 10)
            lines = gate.frame("reveal", 0.5)
            self.assertIn("büyütün", ESCAPES.sub("", " ".join(lines)))
            self.assert_screen_fits(lines, 18, 10)

    def test_fit_parts_prefers_whole_parts_over_clipped_text(self):
        self.assertEqual(fit_parts(["Linux aarch64", "Python 3.12.1"], 40), "Linux aarch64 / Python 3.12.1")
        self.assertEqual(fit_parts(["Linux aarch64", "Python 3.12.1"], 20), "Linux aarch64")
        self.assertEqual(fit_parts(["açılışta istek yok"], 10), "açılışta…")
        self.assertEqual(fit_parts(["acilista istek yok"], 10, ascii_only=True), "acilista.")
        self.assertEqual(fit_parts([], 10), "")
        self.assertEqual(fit_parts(["uzun"], 0), "")
        self.assertEqual(ease_out(0), 0)
        self.assertEqual(ease_out(1), 1)
        self.assertGreater(ease_out(0.5), 0.5)


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, dict(ENV, COLUMNS="39", LINES="24"), clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.output = TtyStream()
        self.console = TerminalUI(self.output)
        self.sleeps = []

    def gate(self, *answers, stdin=None, clock=None):
        return AccessGate(self.console, sleep=self.sleeps.append, clock=clock or FakeClock(),
                          secret_reader=Mock(side_effect=list(answers)), stdin=stdin or TtyStream())

    def rendered(self):
        return ESCAPES.sub("", self.output.getvalue())

    def test_wrong_then_right_password_unlocks_with_a_growing_delay(self):
        gate = self.gate("yanlış", "  " + PASSWORD + "\n")
        self.assertTrue(gate.run())
        text = self.rendered()
        self.assertEqual(gate.secret_reader.call_count, 2)
        self.assertIn("ERİŞİM REDDEDİLDİ", text)
        self.assertIn("Kalan deneme: 2", text)
        self.assertIn("ERİŞİM ONAYLANDI", text)
        self.assertIn("2/3", text)
        self.assertIn(1.0, self.sleeps)
        self.assertNotIn(PASSWORD, text)
        prompt = ESCAPES.sub("", gate.secret_reader.call_args[0][0])
        self.assertIn("Şifre", prompt)

    def test_three_failures_lock_and_never_ask_a_fourth_time(self):
        gate = self.gate("a", "b", "c", "d")
        self.assertFalse(gate.run())
        self.assertEqual(gate.secret_reader.call_count, MAX_ATTEMPTS)
        text = self.rendered()
        self.assertIn("KİLİTLENDİ", text)
        self.assertEqual(text.count("ERİŞİM REDDEDİLDİ"), MAX_ATTEMPTS - 1)
        self.assertEqual(self.sleeps.count(1.0), 1)
        self.assertEqual(self.sleeps.count(2.0), 1)
        self.assertNotIn("ERİŞİM ONAYLANDI", text)

    def test_eof_denies_and_interrupt_leaves_with_130(self):
        self.assertFalse(self.gate(EOFError()).run())
        self.assertIn("Oturum kapatıldı", self.rendered())
        with self.assertRaises(LeaveUI) as stopped:
            self.gate(KeyboardInterrupt()).run()
        self.assertEqual(stopped.exception.code, 130)
        with self.assertRaises(LeaveUI) as stopped:
            self.gate("a", KeyboardInterrupt()).run()
        self.assertEqual(stopped.exception.code, 130)

    def test_intro_only_redraws_the_visible_screen(self):
        self.assertTrue(self.gate(PASSWORD).run())
        output = self.output.getvalue()
        self.assertNotIn("?25l", output)
        self.assertNotIn("?1049h", output)
        self.assertGreaterEqual(output.count("\x1b[H"), 10)
        self.assertLessEqual(output.count("\x1b[2J"), 1)
        for frame in output.split("\x1b[H")[2:]:
            body = frame.split("\x1b[J")[0]
            self.assertLessEqual(len(body.splitlines()), 22)
            self.assertTrue(all(cell_width(line.replace("\x1b[K", "")) <= 38 for line in body.splitlines()))

    def test_slow_terminals_drop_frames_instead_of_stretching_time(self):
        clock = FakeClock(step=0.6)
        gate = self.gate(PASSWORD, clock=clock)
        self.assertTrue(gate.run())
        # checks 1.1 s, reveal 1.1 s, hold 0.35 s, granted 0.7 s: never more than a few frames each.
        self.assertLessEqual(self.output.getvalue().count("\x1b[H"), 16)
        self.assertLess(clock.now, 12)

    def test_enter_during_the_intro_skips_to_the_prompt(self):
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        os.write(writer, b"\n")
        os.close(writer)
        stdin = os.fdopen(reader, "r", closefd=False)
        gate = self.gate(PASSWORD, stdin=stdin)
        self.assertTrue(gate.run())
        self.assertEqual(gate.secret_reader.call_count, 1)
        before_prompt = self.output.getvalue().split("ERİŞİM KONTROLÜ")[0]
        # Clear, first boot frame, final boot frame, prompt frame: nothing in between.
        self.assertLessEqual(before_prompt.count("\x1b[H"), 4)
        self.assertIn("ERİŞİM KONTROLÜ", self.rendered())

    def test_password_typed_during_the_intro_counts_as_the_first_attempt(self):
        for typed, unlocked in ((PASSWORD, True), ("yanlış", False)):
            with self.subTest(typed=typed):
                self.setUp()
                reader, writer = os.pipe()
                self.addCleanup(os.close, reader)
                os.write(writer, (typed + "\n").encode("utf-8"))
                os.close(writer)
                stdin = os.fdopen(reader, "r", closefd=False)
                gate = self.gate("b", "c", stdin=stdin)
                self.assertEqual(gate.run(), unlocked)
                self.assertEqual(gate.secret_reader.call_count, 0 if unlocked else MAX_ATTEMPTS - 1)
                self.assertEqual("ERİŞİM ONAYLANDI" in self.rendered(), unlocked)

    def test_unreadable_stdin_falls_back_to_plain_sleep(self):
        gate = self.gate(PASSWORD, stdin=io.StringIO())
        self.assertTrue(gate.run())
        self.assertTrue(self.sleeps)
        self.assertTrue(all(0 < seconds <= 1 for seconds in self.sleeps))


if __name__ == "__main__":
    unittest.main()
