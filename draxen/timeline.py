import re
from datetime import datetime, timezone


def parse_iso(value):
    text = str(value).strip()
    if not text:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(text[:19] if "T" in text and len(text) > 19 and not text.endswith("Z") else text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
        except (ValueError, TypeError):
            continue
    if re.fullmatch(r"\d{14}", text):
        try:
            dt = datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            return dt.isoformat(timespec="seconds")
        except ValueError:
            pass
    return None


def build_timeline(findings):
    events = []
    seen = set()
    for item in findings:
        kind = item["kind"]
        val = item["value"]
        subj = item["subject"]
        rel = item["relation"]
        for ev in item["evidence"]:
            details = ev.get("details", {})
            if kind == "registration_event":
                iso = parse_iso(val)
                if iso and (iso, rel, subj) not in seen:
                    seen.add((iso, rel, subj))
                    events.append({"timestamp": iso, "category": "Kayıt / Domain", "event": f"{subj} {rel}", "source": ev["source"]})
            if kind == "certificate_name":
                nb = parse_iso(details.get("not_before"))
                if nb and (nb, "Sertifika Başlangıcı", val) not in seen:
                    seen.add((nb, "Sertifika Başlangıcı", val))
                    events.append({"timestamp": nb, "category": "Sertifika", "event": f"{val} sertifikası yayınlandı", "source": ev["source"]})
                na = parse_iso(details.get("not_after"))
                if na and (na, "Sertifika Bitişi", val) not in seen:
                    seen.add((na, "Sertifika Bitişi", val))
                    events.append({"timestamp": na, "category": "Sertifika", "event": f"{val} sertifika süresi doluyor", "source": ev["source"]})
            if kind == "archived_url":
                ts = parse_iso(details.get("timestamp"))
                if ts and (ts, "Wayback Arşivi", val) not in seen:
                    seen.add((ts, "Wayback Arşivi", val))
                    events.append({"timestamp": ts, "category": "Arşiv", "event": f"Wayback anlık görüntüsü: {val}", "source": ev["source"]})
            if kind == "indexed_url":
                st = parse_iso(details.get("scan_time"))
                if st and (st, "urlscan Taraması", val) not in seen:
                    seen.add((st, "urlscan Taraması", val))
                    events.append({"timestamp": st, "category": "Tarama Kaydı", "event": f"urlscan indeksi: {val}", "source": ev["source"]})
            if kind == "security_directive" and rel.lower() == "expires":
                exp = parse_iso(val)
                if exp and (exp, "security.txt Bitişi", subj) not in seen:
                    seen.add((exp, "security.txt Bitişi", subj))
                    events.append({"timestamp": exp, "category": "Güvenlik Politikası", "event": f"{subj} security.txt son geçerlilik", "source": ev["source"]})
            if kind == "sitemap_url":
                lm = parse_iso(details.get("lastmod"))
                if lm and (lm, "Site Haritası Güncellemesi", val) not in seen:
                    seen.add((lm, "Site Haritası Güncellemesi", val))
                    events.append({"timestamp": lm, "category": "Site Haritası", "event": f"Sayfa son güncellenme: {val}", "source": ev["source"]})
    return sorted(events, key=lambda e: e["timestamp"], reverse=True)
