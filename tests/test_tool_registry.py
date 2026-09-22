import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from draxen import tool_registry
from draxen.cli import main
from draxen.terminal_app import TerminalApp
from draxen.terminal_ui import ESCAPES, TerminalUI
from test_terminal_ui import ENV, TtyStream

FIXTURE = {
    "Tool-X": {
        "name": "Tool-X",
        "desc": "is in the bug fixing stage",
        "url": "https://github.com/ekadanuarta/Tool-X.git",
        "category": ["uncategorized"],
        "dependency": ["git", "bash"],
        "package_manager": "git",
    },
    "arch-linux": {
        "name": "arch-linux",
        "desc": "Arch Linux kurulum betiği",
        "url": "https://example.com/arch.sh",
        "category": ["Linux & Desktop Installation"],
        "dependency": ["bash", "curl"],
        "package_manager": "curl",
    },
    "sqlmap": {
        "name": "sqlmap",
        "desc": "Automatic SQL injection and database takeover tool",
        "url": "https://github.com/sqlmaphack/sqlmap",
        "category": ["web_hacking", "exploitation_tools"],
        "dependency": ["python", "git"],
        "package_manager": "git",
    },
}


def write_fixture():
    handle, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(handle, "w", encoding="utf-8") as file:
        json.dump(FIXTURE, file, ensure_ascii=False, indent=4)
    return Path(path)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = write_fixture()
        self.addCleanup(os.unlink, self.fixture)

    def catalog(self):
        catalog, error = tool_registry.load_catalog(self.fixture)
        self.assertIsNone(error)
        return catalog

    def test_load_catalog_returns_tools_in_file_order(self):
        self.assertEqual([tool["slug"] for tool in self.catalog().tools],
                         ["Tool-X", "arch-linux", "sqlmap"])

    def test_search_is_case_insensitive_and_scopes_to_fields(self):
        catalog = self.catalog()
        self.assertEqual([tool["slug"] for tool in catalog.search("SQLMAP")], ["sqlmap"])
        self.assertEqual([tool["slug"] for tool in catalog.search("ekadanuarta")], ["Tool-X"])
        self.assertEqual([tool["slug"] for tool in catalog.search("web_hacking")], ["sqlmap"])
        self.assertEqual(catalog.search("   "), catalog.tools)
        self.assertEqual(catalog.search("no-such-thing"), [])

    def test_categories_keep_file_order_with_counts(self):
        self.assertEqual(self.catalog().categories(), [
            ("uncategorized", 1),
            ("Linux & Desktop Installation", 1),
            ("web_hacking", 1),
            ("exploitation_tools", 1),
        ])

    def test_install_hint_is_display_only(self):
        catalog = self.catalog()
        self.assertEqual(catalog.install_hint(catalog.by_slug["Tool-X"]),
                         "git clone https://github.com/ekadanuarta/Tool-X.git")
        self.assertEqual(catalog.install_hint(catalog.by_slug["arch-linux"]),
                         "curl -L https://example.com/arch.sh")
        self.assertEqual(catalog.install_hint({"url": "", "package_manager": "git"}),
                         "Kayıtta bağlantı yok.")

    def test_missing_corrupt_and_empty_catalogs_report_instead_of_raising(self):
        catalog, error = tool_registry.load_catalog(Path(tempfile.gettempdir()) / "yok.json")
        self.assertIsNone(catalog)
        self.assertIn("Katalog bulunamadı", error)
        self.fixture.write_text("{ bozuk", encoding="utf-8")
        catalog, error = tool_registry.load_catalog(self.fixture)
        self.assertIsNone(catalog)
        self.assertIn("bozuk", error)
        self.fixture.write_text("{}", encoding="utf-8")
        catalog, error = tool_registry.load_catalog(self.fixture)
        self.assertIsNone(catalog)
        self.assertIn("boş", error)

    def test_normalization_fills_missing_fields(self):
        tool = tool_registry.normalize_tool("raw", {"category": "single", "dependency": "git"})
        self.assertEqual(tool["name"], "raw")
        self.assertEqual(tool["categories"], ["single"])
        self.assertEqual(tool["dependencies"], ["git"])
        self.assertEqual(tool["package_manager"], "git")
        self.assertEqual(tool_registry.normalize_tool("x", None)["categories"], ["uncategorized"])


class ShippedCatalogTests(unittest.TestCase):
    """The catalog shipped in the repository must be valid and non-trivial."""

    def test_shipped_catalog_loads_and_has_core_tools(self):
        catalog, error = tool_registry.load_catalog()
        self.assertIsNone(error)
        self.assertGreaterEqual(len(catalog), 500)
        self.assertIn("Tool-X", catalog.by_slug)
        self.assertTrue(all(not tool["url"] or tool["url"].startswith("http")
                            for tool in catalog.tools))


class ToolsCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = write_fixture()
        self.addCleanup(os.unlink, self.fixture)
        self.patcher = patch("draxen.tool_registry.DEFAULT_CATALOG", self.fixture)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def run_tools(self, *argv):
        with patch.dict(os.environ, ENV, clear=True), \
                redirect_stdout(TtyStream()) as out, redirect_stderr(TtyStream()) as err, \
                patch("draxen.cli.Client") as client, patch("draxen.cli.save_reports") as save:
            code = main(list(argv))
        self.assertEqual(client.called, False)
        self.assertEqual(save.called, False)
        return code, ESCAPES.sub("", out.getvalue()), ESCAPES.sub("", err.getvalue())

    def test_tools_lists_catalog_without_network(self):
        code, out, err = self.run_tools("--tools")
        self.assertEqual(code, 0)
        self.assertIn("TEST ARAÇLARI", out)
        for token in ("Tool-X", "arch-linux", "sqlmap"):
            self.assertIn(token, out)
        self.assertIn("yalnızca listeleme yapar", out)
        self.assertIn("3/3 kayıt", out)
        self.assertEqual(err, "")

    def test_tools_filter_narrows_the_list(self):
        code, out, _ = self.run_tools("--tools", "sqlmap")
        self.assertEqual(code, 0)
        self.assertIn("filtre: sqlmap", out)
        self.assertIn("sqlmap", out)
        self.assertIn("1/3 kayıt", out)
        self.assertNotIn("0002  arch-linux", out)

    def test_tools_no_match_still_exits_clean(self):
        code, out, _ = self.run_tools("--tools", "olmayan")
        self.assertEqual(code, 0)
        self.assertIn("Eşleşme yok", out)

    def test_tools_conflicts_with_target(self):
        with patch.dict(os.environ, ENV, clear=True), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stopped:
            main(["example.com", "--tools"])
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("--tools bir tarama değildir", ESCAPES.sub("", err.getvalue()))


class ToolsPageTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, dict(ENV, COLUMNS="39", LINES="24"), clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.output = TtyStream()
        self.console = TerminalUI(self.output)
        self.fixture = write_fixture()
        self.addCleanup(os.unlink, self.fixture)
        patcher = patch("draxen.tool_registry.DEFAULT_CATALOG", self.fixture)
        patcher.start()
        self.addCleanup(patcher.stop)

    def app(self, inputs):
        return TerminalApp(self.console, reader=Mock(side_effect=inputs))

    def rendered(self):
        return ESCAPES.sub("", self.output.getvalue())

    def test_option_five_opens_tools_page_and_returns_to_menu(self):
        runner = Mock()
        self.assertEqual(self.app(["5", "q", "q"]).launch(runner, lambda: "help"), 0)
        runner.assert_not_called()
        text = self.rendered()
        self.assertIn("TEST ARAÇLARI", text)
        self.assertIn("Tool-X", text)
        self.assertIn("sqlmap", text)
        self.assertIn("KONTROL MERKEZİ", text)

    def test_tool_detail_shows_fields_and_disclaimer(self):
        runner = Mock()
        self.assertEqual(self.app(["5", "1", "q", "q", "q"]).launch(runner, lambda: "help"), 0)
        runner.assert_not_called()
        text = self.rendered()
        self.assertIn("ARAÇ DETAYI", text)
        self.assertIn("git clone", text)
        self.assertIn("danuarta/Tool-X.git", text)  # URL wraps on narrow terminals.
        self.assertIn("KATEGORİ", text)
        self.assertIn("BAĞLANTI", text)
        self.assertIn("yalnızca listeleme yapar", text)

    def test_tools_search_filters_and_list_keeps_working(self):
        runner = Mock()
        self.assertEqual(self.app(["5", "s", "sql", "q", "q"]).launch(runner, lambda: "help"), 0)
        runner.assert_not_called()
        text = self.rendered()
        self.assertIn("1/3 kayıt", text)
        self.assertIn("filtre: sql", text)
        self.assertIn("sqlmap", text)

    def test_typed_text_filters_instead_of_erroring(self):
        runner = Mock()
        self.assertEqual(self.app(["5", "sql", "q", "q"]).launch(runner, lambda: "help"), 0)
        self.assertIn("filtre: sql", self.rendered())


if __name__ == "__main__":
    unittest.main()
