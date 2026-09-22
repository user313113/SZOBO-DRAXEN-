import re
import struct
import zlib
from pathlib import Path

TAG_NAMES = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8825: "GPSInfo",
}


def parse_jpeg_exif(data):
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return {}
    idx = 2
    while idx < len(data) - 4:
        if data[idx] != 0xFF:
            break
        marker = data[idx + 1]
        length = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
        if length < 2:
            break
        if marker == 0xE1 and data[idx + 4 : idx + 10] == b"Exif\x00\x00":
            return parse_tiff(data[idx + 10 : idx + 2 + length])
        idx += 2 + length
    return {}


def parse_tiff(tiff):
    if len(tiff) < 8:
        return {}
    endian = "<" if tiff[:2] == b"II" else ">"
    if tiff[2:4] not in (b"*\x00", b"\x00*"):
        return {}
    ifd0_offset = struct.unpack(endian + "I", tiff[4:8])[0]
    results = {}
    parse_ifd(tiff, ifd0_offset, endian, results)
    return results


def parse_ifd(tiff, offset, endian, results):
    if offset + 2 > len(tiff):
        return
    count = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
    idx = offset + 2
    for _ in range(count):
        if idx + 12 > len(tiff):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", tiff[idx : idx + 8])
        val_bytes = tiff[idx + 8 : idx + 12]
        val = None
        if typ == 2:
            if cnt <= 4:
                val = val_bytes[:cnt].decode("latin-1", "replace").rstrip("\x00")
            else:
                str_offset = struct.unpack(endian + "I", val_bytes)[0]
                if str_offset + cnt <= len(tiff):
                    val = tiff[str_offset : str_offset + cnt].decode("latin-1", "replace").rstrip("\x00")
        elif typ in (3, 4) and cnt == 1:
            val = struct.unpack(endian + ("H" if typ == 3 else "I"), val_bytes[: 2 if typ == 3 else 4])[0]
        if tag in TAG_NAMES and val is not None:
            results[TAG_NAMES[tag]] = str(val).strip()
        if tag == 0x8825:
            gps_offset = struct.unpack(endian + "I", val_bytes)[0]
            parse_gps(tiff, gps_offset, endian, results)
        idx += 12


def parse_gps(tiff, offset, endian, results):
    if offset + 2 > len(tiff):
        return
    count = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
    idx = offset + 2
    gps = {}
    for _ in range(count):
        if idx + 12 > len(tiff):
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", tiff[idx : idx + 8])
        val_bytes = tiff[idx + 8 : idx + 12]
        if tag in (1, 3):
            gps["LatRef" if tag == 1 else "LonRef"] = val_bytes[:1].decode("latin-1", "replace")
        elif tag in (2, 4):
            rat_offset = struct.unpack(endian + "I", val_bytes)[0]
            if rat_offset + 24 <= len(tiff):
                deg_n, deg_d = struct.unpack(endian + "II", tiff[rat_offset : rat_offset + 8])
                min_n, min_d = struct.unpack(endian + "II", tiff[rat_offset + 8 : rat_offset + 16])
                sec_n, sec_d = struct.unpack(endian + "II", tiff[rat_offset + 16 : rat_offset + 24])
                deg = (deg_n / deg_d) if deg_d else 0
                minute = (min_n / min_d) if min_d else 0
                sec = (sec_n / sec_d) if sec_d else 0
                gps["Lat" if tag == 2 else "Lon"] = deg + (minute / 60.0) + (sec / 3600.0)
        idx += 12
    if "Lat" in gps and "Lon" in gps:
        lat = gps["Lat"] * (-1 if gps.get("LatRef") == "S" else 1)
        lon = gps["Lon"] * (-1 if gps.get("LonRef") == "W" else 1)
        results["GPSCoordinates"] = f"{lat:.6f}, {lon:.6f}"
        results["GoogleMaps"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"


def parse_png_metadata(data):
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return {}
    results = {}
    idx = 8
    while idx + 8 < len(data):
        length = struct.unpack(">I", data[idx : idx + 4])[0]
        ctype = data[idx + 4 : idx + 8]
        cdata = data[idx + 8 : idx + 8 + length]
        if ctype == b"tEXt" and b"\x00" in cdata:
            k, v = cdata.split(b"\x00", 1)
            results[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace").strip()
        elif ctype == b"zTXt" and b"\x00" in cdata and len(cdata) > 2:
            k, rest = cdata.split(b"\x00", 1)
            if len(rest) > 1 and rest[0] == 0:
                try:
                    text = zlib.decompress(rest[1:]).decode("latin-1", "replace")
                    results[k.decode("latin-1", "replace")] = text.strip()
                except Exception:
                    pass
        elif ctype == b"iTXt" and b"\x00" in cdata:
            parts = cdata.split(b"\x00", 3)
            if len(parts) >= 4:
                k = parts[0].decode("utf-8", "replace")
                results[k] = parts[3].decode("utf-8", "replace").strip()
        idx += 12 + length
    return results


def parse_pdf_metadata(data):
    if not data.startswith(b"%PDF-"):
        return {}
    results = {}
    head = data[:500000].decode("latin-1", "replace")
    tail = data[-50000:].decode("latin-1", "replace")
    text = head + tail
    for field in ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate"):
        m = re.search(r"/" + field + r"\s*\(([^)]+)\)", text)
        if m:
            val = m.group(1).strip()
            if field in ("CreationDate", "ModDate") and val.startswith("D:"):
                val = val[2:16]
            results[field] = val

    xmp_m = re.search(r"<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>", text, re.DOTALL)
    if xmp_m:
        xmp = xmp_m.group(1)
        for tag, name in [
            (r"<dc:creator>\s*<rdf:Seq>\s*<rdf:li>([^<]+)</rdf:li>", "XMP_Author"),
            (r"<dc:title>\s*<rdf:Alt>\s*<rdf:li[^>]*>([^<]+)</rdf:li>", "XMP_Title"),
            (r"<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>", "XMP_CreatorTool"),
            (r"<xmp:CreateDate>([^<]+)</xmp:CreateDate>", "XMP_CreateDate"),
            (r"<pdf:Producer>([^<]+)</pdf:Producer>", "XMP_Producer"),
        ]:
            tm = re.search(tag, xmp)
            if tm:
                results[name] = tm.group(1).strip()
    return results


def extract_metadata(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")
    data = path.read_bytes()
    filename = path.name

    if data.startswith(b"\xff\xd8"):
        meta = parse_jpeg_exif(data)
        ftype = "JPEG Image"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        meta = parse_png_metadata(data)
        ftype = "PNG Image"
    elif data.startswith(b"%PDF-"):
        meta = parse_pdf_metadata(data)
        ftype = "PDF Document"
    else:
        return {"filename": filename, "file_type": "Bilinmeyen Dosya Türü", "metadata": {}}

    return {
        "filename": filename,
        "file_type": ftype,
        "file_size_bytes": len(data),
        "metadata": meta,
    }
