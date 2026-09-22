import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.analysis import analyze
from draxen.cli import main, parser
from draxen.core import Report, Target
from draxen.crawlers import CrawlerAnalyzer
from draxen.metadata import (
    extract_metadata,
    parse_jpeg_exif,
    parse_pdf_metadata,
    parse_png_metadata,
)
try:
    from test_draxen import FakeClient
except ImportError:
    from tests.test_draxen import FakeClient


def create_sample_jpeg():
    tiff_header = b"II*\x00\x08\x00\x00\x00"
    num_entries = struct.pack("<H", 2)
    entry_make = struct.pack("<HHI", 0x010F, 2, 6) + struct.pack("<I", 38)
    entry_model = struct.pack("<HHI", 0x0110, 2, 7) + struct.pack("<I", 44)
    ifd0 = num_entries + entry_make + entry_model + b"\x00\x00\x00\x00"
    data_make = b"Apple\x00"
    data_model = b"iPhone\x00"
    tiff_payload = tiff_header + ifd0 + data_make + data_model
    exif_marker = b"Exif\x00\x00" + tiff_payload
    app1_len = struct.pack(">H", len(exif_marker) + 2)
    app1 = b"\xff\xe1" + app1_len + exif_marker
    return b"\xff\xd8" + app1 + b"\xff\xd9"


def create_sample_png():
    sig = b"\x89PNG\r\n\x1a\n"
    text_data = b"Author\x00Security Analyst"
    chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + b"\x00\x00\x00\x00"
    return sig + chunk


def create_sample_pdf():
    return b"%PDF-1.4\n1 0 obj\n<< /Title (Confidential Assessment) /Author (SecTeam) /CreationDate (D:20260920120000) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"


class MetadataV15Tests(unittest.TestCase):
    def test_parse_jpeg(self):
        jpeg_data = create_sample_jpeg()
        meta = parse_jpeg_exif(jpeg_data)
        self.assertEqual(meta.get("Make"), "Apple")
        self.assertEqual(meta.get("Model"), "iPhone")

    def test_parse_png(self):
        png_data = create_sample_png()
        meta = parse_png_metadata(png_data)
        self.assertEqual(meta.get("Author"), "Security Analyst")

    def test_parse_pdf(self):
        pdf_data = create_sample_pdf()
        meta = parse_pdf_metadata(pdf_data)
        self.assertEqual(meta.get("Title"), "Confidential Assessment")
        self.assertEqual(meta.get("Author"), "SecTeam")
        self.assertEqual(meta.get("CreationDate"), "20260920120000")

    def test_extract_metadata_file(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "doc.pdf"
            p.write_bytes(create_sample_pdf())
            res = extract_metadata(p)
            self.assertEqual(res["file_type"], "PDF Document")
            self.assertEqual(res["metadata"]["Author"], "SecTeam")


class CrawlersV15Tests(unittest.TestCase):
    def test_crawler_analyzer(self):
        target = Target.parse("example.com")
        robots_content = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nAllow: /public\nSitemap: https://example.com/sitemap.xml"
        sitemap_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/about</loc><lastmod>2026-05-01</lastmod></url>
  <url><loc>https://api.example.com/report.pdf</loc></url>
</urlset>"""
        client = FakeClient({
            "robots.txt": robots_content,
            "sitemap.xml": sitemap_content,
        })
        report = Report(target)
        candidates = set()
        crawler = CrawlerAnalyzer(client, report, "example.com", limit=10, candidates=candidates)
        crawler.run()

        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertIn("crawler_disallowed_path", kinds)
        self.assertIn("crawler_allowed_path", kinds)
        self.assertIn("sitemap_url", kinds)
        self.assertIn("media_reference", kinds)
        self.assertIn("api.example.com", candidates)

        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("robots_disallowed_paths", types)
        self.assertIn("media_documents_exposed", types)


class CliV15Tests(unittest.TestCase):
    def test_cli_meta_option(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "photo.jpg"
            p.write_bytes(create_sample_jpeg())
            code = main(["--meta", str(p), "--output", folder, "--quiet"])
            self.assertEqual(code, 0)
            report_path = Path(folder) / "metadata_report.json"
            self.assertTrue(report_path.exists())

    def test_cli_sitemap_rejected_for_ip(self):
        with self.assertRaises(SystemExit):
            main(["8.8.8.8", "--sitemap"])


if __name__ == "__main__":
    unittest.main()
