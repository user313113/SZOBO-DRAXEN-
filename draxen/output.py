import base64
import json
import math
import os
import tempfile
from collections import Counter
from pathlib import Path

from .analysis import ENTITY_TITLES, insight_level
from .exports import csv_report, graphml_report
from .terminal_ui import TerminalUI, safe_text

LABELS = {
    "observed": "Doğrudan gözlem",
    "unverified": "Doğrulanmamış kaynak kaydı",
    "dns_observed": "DNS gözlemi",
    "page_observed": "Sayfa gözlemi",
    "routing_observed": "Yönlendirme gözlemi",
    "input": "Kullanıcı girdisi",
    "security_audit": "Güvenlik denetimi",
    "cryptographic_audit": "Kriptografik denetim",
    "datacenter_fingerprint": "Veri merkezi tespiti",
    "port_probe": "Port yoklaması",
    "banner_grab": "Servis karşılama",
}


def escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def terminal(value):
    return safe_text(value)


def node_color(kind):
    if kind in ("target", "domain", "discovered_domain", "certificate_name", "linked_subdomain"):
        return "#58d8ae"
    if kind in ("dns_a", "dns_aaaa", "network_subnet", "historical_ip", "ptr", "ip_range", "ip_net_name", "ip_country", "ip_city", "ip_coordinates", "open_port"):
        return "#fca311"
    if kind in ("asn", "asn_holder", "bgp_prefix"):
        return "#b5838d"
    if kind in ("dns_mx", "public_email", "email_policy", "identified_service", "dkim_record"):
        return "#48cae4"
    if kind in ("cloud_footprint", "external_service_pointer", "nameserver", "dns_ns", "dns_cname", "server_banner", "datacenter_provider", "edge_infrastructure"):
        return "#80ed99"
    if kind in ("security_directive", "dnssec_record", "dns_caa_directive", "http_security_header", "cookie_policy", "cookie_insecurity", "tls_weak_signature", "public_identity", "public_bio", "gravatar_profile", "registry_contact_fn"):
        return "#ffd166"
    return "#aabcc9"


def graph_data(data):
    nodes = {data["target"]["value"]: "target"}
    edges = set()
    for item in data["findings"]:
        nodes.setdefault(item["subject"], "subject")
        nodes.setdefault(item["value"], item["kind"])
        edges.add((item["subject"], item["value"], item["relation"]))
    return nodes, sorted(edges)


def dot_report(data):
    nodes, edges = graph_data(data)
    ids = {name: "n" + str(i) for i, name in enumerate(nodes)}
    quote = lambda text: json.dumps(str(text), ensure_ascii=False)
    lines = ['digraph DRAXEN {', '  graph [bgcolor="#070b12", rankdir=LR];', '  edge [color="#1f374e", fontcolor="#7e9bb0"];']
    for name, kind in nodes.items():
        color = node_color(kind)
        lines.append(f'  {ids[name]} [shape=box, style=rounded, color="{color}", fontcolor="#e0ecf4", label={quote(name)}, tooltip={quote(kind)}];')
    for start, end, relation in edges:
        lines.append(f'  {ids[start]} -> {ids[end]} [label={quote(relation)}];')
    return "\n".join(lines + ["}", ""])


def graph_svg(data):
    nodes, edges = graph_data(data)
    names = list(nodes)[:50]
    positions = {}
    for i, name in enumerate(names):
        if i == 0:
            positions[name] = (500, 340)
        else:
            angle = 2 * math.pi * (i - 1) / max(1, len(names) - 1)
            positions[name] = (500 + 390 * math.cos(angle), 340 + 280 * math.sin(angle))
    svg = ['<svg viewBox="0 0 1000 680" id="graph-svg" role="img" aria-label="Bulguların ilişki grafiği">']
    for start, end, relation in edges:
        if start in positions and end in positions:
            x1, y1 = positions[start]
            x2, y2 = positions[end]
            svg.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#1f374e" stroke-width="1" />')
    for name, (x, y) in positions.items():
        kind = nodes.get(name, "unknown")
        color = node_color(kind)
        label = escape(name[:22] + "…" if len(name) > 23 else name)
        full_label = escape(name)
        kind_label = escape(kind)
        svg.append(f'<g class="graph-node" data-name="{full_label}" data-kind="{kind_label}" style="cursor:pointer;"><circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{color}" /><text x="{x + 10:.1f}" y="{y + 4:.1f}" fill="#e0ecf4" font-size="11" font-family="ui-monospace,monospace">{label}</text></g>')
    svg.append("</svg>")
    return "".join(svg), len(nodes)


def insight_severity(itype):
    level = insight_level(itype)
    return {
        "critical": ("critical", "🔴 KRİTİK", "#ff0055"),
        "warn": ("warn", "🟡 UYARI", "#ffb703"),
        "info": ("info", "🔵 BİLGİ", "#00e5ff"),
    }[level]


def analysis_html(data):
    analysis = data.get("analysis", {})
    insights = analysis.get("insights", [])
    entity_counts = analysis.get("entity_counts", {})
    timeline = data.get("timeline", [])

    entity_cards = "".join(
        f'<div class="card"><small>{escape(ENTITY_TITLES.get(cat, cat))}</small><strong>{count}</strong></div>'
        for cat, count in sorted(entity_counts.items())
    )
    entities_section = f'<section id="sec-entities"><h2>Varlık Dağılım Matrisi</h2><div class="cards">{entity_cards}</div></section>' if entity_cards else ""

    insight_items = []
    for item in insights:
        sev, badge, _ = insight_severity(item["type"])
        css_cls = f"tag-{sev}"
        val_str = " · ".join(item.get("values", []))
        insight_items.append(
            f'<li style="border-left:3px solid {"#ff0055" if sev == "critical" else "#ffb703" if sev == "warn" else "#00e5ff"};padding:12px;margin-bottom:12px;background:#09111c;border-radius:4px;">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">'
            f'<span class="tag {css_cls}">{badge}</span> <b>{escape(item.get("subject", ""))}</b> '
            f'<span class="tag">{escape(item["type"])}</span></div>'
            f'<p style="margin:4px 0;color:#e0ecf4;">{escape(item["message"])}</p>'
            + (f'<small style="color:#7e9bb0;">{escape(val_str)}</small>' if val_str else "")
            + "</li>"
        )

    insights_section = (
        '<section id="sec-insights"><h2>Risk Analizi &amp; Siber Güvenlik Göstergeleri</h2>'
        + (f'<ul style="list-style:none;padding:0;">{"".join(insight_items)}</ul>' if insight_items else "<p>Mevcut bulgulardan ek bir anomali veya güvenlik zafiyeti üretilmedi.</p>")
        + "</section>"
    )

    timeline_rows = "".join(
        f'<tr><td><span class="tag">{escape(ev["category"])}</span></td><td class="value">{escape(ev["timestamp"])}</td><td>{escape(ev["event"])}</td><td><small>{escape(ev["source"])}</small></td></tr>'
        for ev in timeline[:60]
    )
    timeline_section = (
        f'<section id="sec-timeline"><h2>Kronolojik Olay &amp; Sertifika Çizelgesi ({len(timeline)} olay)</h2><div class="table"><table><thead><tr><th>Kategori</th><th>Zaman (UTC)</th><th>Olay</th><th>Kaynak</th></tr></thead><tbody>{timeline_rows}</tbody></table></div></section>'
        if timeline
        else ""
    )

    comparison = data.get("comparison")
    comp_section = ""
    if comparison is not None:
        comp_section = f'<section id="sec-compare"><h2>Önceki Raporla Karşılaştırma</h2><p>{len(comparison["added"])} yeni · {len(comparison["not_observed"])} bu çalışmada görülmedi · {comparison["unchanged_count"]} aynı kayıt</p><small>{escape(comparison["caution"])}</small>'
        for key, title in (("added", "Yeni Gözlenen Bulgular"), ("not_observed", "Bu Çalışmada Görülmeyenler")):
            rows = "".join(f'<li><span class="tag">{escape(item["kind"])}</span> {escape(item["subject"])} → {escape(item["value"])}</li>' for item in comparison[key])
            comp_section += f'<details><summary>{title} ({len(comparison[key])})</summary><ul>{rows}</ul></details>'
        comp_section += "</section>"

    return entities_section + insights_section + timeline_section + comp_section


def markdown_report(data):
    target_val = data["target"]["value"]
    target_kind = data["target"]["kind"]
    started = data.get("started_at", "")
    finished = data.get("finished_at", "")
    findings = data.get("findings", [])
    sources = data.get("sources", [])
    insights = data.get("analysis", {}).get("insights", [])
    timeline = data.get("timeline", [])
    warnings = data.get("warnings", [])

    lines = [
        "# SZOBO | DRAXEN — Siber İstihbarat & OSINT Raporu",
        "",
        f"> **Hedef:** `{target_val}` ({target_kind})  ",
        f"> **Tarih:** {started} → {finished}  ",
        f"> **İstatistikler:** {len(findings)} Bulgu · {data.get('requests', 0)} HTTP İsteği · {len(timeline)} Zaman Damgası  ",
        "",
        "---",
        "",
        "## 1. Yönetici Özeti ve Risk Değerlendirmesi",
        "",
    ]

    if data.get("demo"):
        lines[2:2] = ["> **ÇEVRİMDIŞI DEMO:** Temsili örnek verilerdir; gerçek bir tarama veya hedef değerlendirmesi değildir.", ""]

    if insights:
        lines.extend([
            "| Seviye | Gösterge Türü | İlgili Varlık | Bulgular ve Açıklama |",
            "|:---:|:---|:---|:---|",
        ])
        for item in insights:
            _, badge, _ = insight_severity(item["type"])
            val_text = "<br>".join(f"`{v}`" for v in item.get("values", [])[:5])
            msg = item.get("message", "").replace("|", "\\|")
            lines.append(f"| {badge} | `{item['type']}` | `{item.get('subject', target_val)}` | {msg}<br>{val_text} |")
        lines.append("")
    else:
        lines.extend(["Mevcut bulgulardan güvenlik riski veya politika anomalisi tespit edilmedi.", ""])

    net_findings = [f for f in findings if f["kind"] in ("network_subnet", "bgp_prefix", "asn", "asn_holder", "datacenter_provider", "ip_range", "ip_net_name", "ip_country", "ip_city", "ip_coordinates", "rir_registry")]
    if net_findings:
        lines.extend([
            "## 2. IP, ASN, Veri Merkezi ve Ağ Konum Haritası",
            "",
            "| Tür | Değer | Özne | İlişki |",
            "|:---|:---|:---|:---|",
        ])
        for f in net_findings:
            lines.append(f"| `{f['kind']}` | `{f['value']}` | `{f['subject']}` | {f['relation']} |")
        lines.append("")

    dns_findings = [f for f in findings if f["kind"].startswith("dns_") or f["kind"] in ("domain", "discovered_domain", "certificate_name", "nameserver")]
    if dns_findings:
        lines.extend([
            "## 3. DNS Altyapısı ve Alt Alan Adı Yüzeyi",
            "",
            "| Tür | Değer | Özne | İlişki |",
            "|:---|:---|:---|:---|",
        ])
        for f in dns_findings[:40]:
            lines.append(f"| `{f['kind']}` | `{f['value']}` | `{f['subject']}` | {f['relation']} |")
        if len(dns_findings) > 40:
            lines.append(f"| ... | *(Toplam {len(dns_findings)} DNS bulgusu)* | ... | ... |")
        lines.append("")

    tls_findings = [f for f in findings if f["kind"].startswith("tls_")]
    if tls_findings:
        lines.extend([
            "## 4. SSL/TLS Sertifika ve Kripto Profili",
            "",
            "| Tür | Değer | Özne | İlişki |",
            "|:---|:---|:---|:---|",
        ])
        for f in tls_findings:
            lines.append(f"| `{f['kind']}` | `{f['value']}` | `{f['subject']}` | {f['relation']} |")
        lines.append("")

    web_findings = [f for f in findings if f["kind"] in ("http_security_header", "cookie_policy", "cookie_insecurity", "server_banner", "edge_infrastructure")]
    if web_findings:
        lines.extend([
            "## 5. Web Güvenlik Başlıkları ve Çerez (Cookie) Denetimi",
            "",
            "| Tür | Değer | Özne | İlişki |",
            "|:---|:---|:---|:---|",
        ])
        for f in web_findings:
            lines.append(f"| `{f['kind']}` | `{f['value']}` | `{f['subject']}` | {f['relation']} |")
        lines.append("")

    port_findings = [f for f in findings if f["kind"] in ("open_port", "service_banner")]
    if port_findings:
        lines.extend([
            "## 6. Açık Portlar ve Servis Banner Bilgileri",
            "",
            "| Tür | Değer | Hedef IP |",
            "|:---|:---|:---|",
        ])
        for f in port_findings:
            lines.append(f"| `{f['kind']}` | `{f['value']}` | `{f['subject']}` |")
        lines.append("")

    if timeline:
        lines.extend([
            f"## 7. Kronolojik Olay Zaman Çizelgesi ({len(timeline)} Olay)",
            "",
            "| Tarih (UTC) | Kategori | Olay Açıklaması | Kaynak |",
            "|:---|:---|:---|:---|",
        ])
        for ev in timeline[:30]:
            lines.append(f"| `{ev['timestamp']}` | `{ev['category']}` | {ev['event']} | `{ev['source']}` |")
        if len(timeline) > 30:
            lines.append(f"| ... | ... | *(Toplam {len(timeline)} zaman damgası)* | ... |")
        lines.append("")

    lines.extend([
        "## 8. Veri Toplama Kaynakları ve Kapsam",
        "",
        "| Kaynak Servis | Durum | Yeni Bulgu | Durum Mesajı |",
        "|:---|:---:|:---:|:---|",
    ])
    for s in sources:
        st_badge = "✅ Başarılı" if s["state"] == "ok" else "⚠️ Eksik/Hata"
        lines.append(f"| {s['name']} | {st_badge} | {s['new_findings']} | {s['message']} |")
    lines.append("")

    if warnings:
        lines.extend(["### Uyarılar ve Sınırlar", ""])
        for w in warnings:
            lines.append(f"- ⚠️ {w}")
        lines.append("")

    lines.extend([
        "---",
        f"*Rapor Oluşturucu: SZOBO | DRAXEN v{data.get('version', '1.6.0')}*",
        "",
    ])
    return "\n".join(lines)


def html_report(data):
    counts = Counter(item["kind"] for item in data["findings"])
    rows = []
    for item in data["findings"]:
        evidence = []
        for entry in item["evidence"]:
            source = entry["source"]
            source_html = f'<a href="{escape(source)}" target="_blank" rel="noreferrer noopener">Kaynak ↗</a>' if source.startswith("https://") else escape(source)
            details = f'<pre>{escape(json.dumps(entry["details"], ensure_ascii=False, indent=2))}</pre>' if entry.get("details") else ""
            evidence.append(f'<div class="evidence"><span class="tag">{escape(LABELS.get(entry["status"], entry["status"]))}</span> {source_html}<small>{escape(entry["observed_at"])}</small>{details}</div>')
        rows.append(f'<tr><td><span class="tag">{escape(item["kind"])}</span></td><td class="value">{escape(item["value"])}</td><td>{escape(item["subject"])}<small>{escape(item["relation"])}</small></td><td>{"".join(evidence)}</td></tr>')
    sources = "".join(f'<li><b>{escape(source["name"])}</b><span class="tag {"tag-warn" if source["state"] != "ok" else "tag-sec"}">{escape(source["state"])}</span><small>{source["new_findings"]} yeni bulgu · {escape(source["message"])}</small></li>' for source in data["sources"])
    warnings = "".join(f'<li>{escape(warning)}</li>' for warning in data["warnings"])
    options = "".join(f'<option value="{escape(kind)}">{escape(kind)} ({count})</option>' for kind, count in sorted(counts.items()))
    svg, total_nodes = graph_svg(data)
    json_export = json.dumps(data, ensure_ascii=False)
    csv_export = csv_report(data)
    md_export = markdown_report(data)

    json_b64 = base64.b64encode(json_export.encode("utf-8")).decode("ascii")
    csv_b64 = base64.b64encode(csv_export.encode("utf-8")).decode("ascii")
    md_b64 = base64.b64encode(md_export.encode("utf-8")).decode("ascii")
    demo_banner = ('<p class="tag tag-warn" role="note">ÇEVRİMDIŞI DEMO: Temsili örnek verilerdir; gerçek bir tarama değildir.</p>'
                   if data.get("demo") else "")

    return '''<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>SZOBO | DRAXEN — Siber İstihbarat Raporu</title>
<style>
:root{color-scheme:dark;--bg:#060a10;--panel:#0b131f;--panel-border:#152438;--neon-green:#00ff66;--neon-cyan:#00e5ff;--hazard-amber:#ffb703;--danger-red:#ff0055;--text-main:#e0ecf4;--text-muted:#7e9bb0;--font-mono:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text-main);font:14px/1.6 system-ui,-apple-system,sans-serif;letter-spacing:.01em}
main{max-width:1480px;margin:auto;padding:36px 4%}
header{border-bottom:1px solid var(--panel-border);padding-bottom:24px;position:relative}
.brand{letter-spacing:.3em;color:var(--neon-green);font-weight:900;font-family:var(--font-mono);font-size:16px;text-transform:uppercase;text-shadow:0 0 12px rgba(0,255,102,.35)}
.eyebrow{color:var(--neon-cyan);font-family:var(--font-mono);font-size:11px;letter-spacing:.15em;margin:8px 0 0}
h1{font-size:clamp(28px,4.5vw,52px);font-family:var(--font-mono);letter-spacing:-.03em;color:#fff;overflow-wrap:anywhere;margin:12px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:24px 0}
.card,section{background:var(--panel);border:1px solid var(--panel-border);border-radius:10px;padding:22px;margin-bottom:22px;box-shadow:0 8px 24px rgba(0,0,0,.45)}
.card{margin:0;border-left:3px solid var(--neon-cyan);transition:transform .15s ease}
.card:hover{transform:translateY(-2px);border-color:var(--neon-green)}
.card strong{display:block;font-size:32px;font-family:var(--font-mono);color:var(--neon-green);margin-top:6px;text-shadow:0 0 8px rgba(0,255,102,.25)}
.card small{color:var(--text-muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.tag{font-size:11px;font-family:var(--font-mono);border:1px solid #1e3a4b;border-radius:4px;color:var(--neon-cyan);padding:3px 8px;display:inline-block;overflow-wrap:anywhere}
.tag-critical{color:var(--danger-red);border-color:rgba(255,0,85,.5);background:rgba(255,0,85,.12)}
.tag-warn{color:var(--hazard-amber);border-color:rgba(255,183,3,.5);background:rgba(255,183,3,.12)}
.tag-info{color:var(--neon-cyan);border-color:rgba(0,229,255,.5);background:rgba(0,229,255,.12)}
.tag-sec{color:var(--neon-green);border-color:rgba(0,255,102,.5);background:rgba(0,255,102,.12)}
.nav-pills{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}
.nav-pill{background:#0e1724;color:#a8c4d8;border:1px solid var(--panel-border);padding:8px 16px;border-radius:6px;text-decoration:none;font-size:12px;font-family:var(--font-mono);cursor:pointer;transition:all .15s ease}
.nav-pill:hover{background:rgba(0,229,255,.12);color:var(--neon-cyan);border-color:var(--neon-cyan)}
.tools{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
input,select,button{background:#070d15;border:1px solid var(--panel-border);border-radius:6px;color:var(--text-main);padding:12px;min-width:0;font-family:inherit}
input{flex:1;font-family:var(--font-mono)}
input:focus,select:focus{outline:none;border-color:var(--neon-cyan);box-shadow:0 0 10px rgba(0,229,255,.25)}
.btn-export{background:#0d251d;color:var(--neon-green);border:1px solid #1a4d3b;cursor:pointer;font-weight:700;font-family:var(--font-mono);font-size:12px;text-transform:uppercase;letter-spacing:.05em;transition:all .15s ease}
.btn-export:hover{background:#153d2f;border-color:var(--neon-green);box-shadow:0 0 12px rgba(0,255,102,.3)}
.table{overflow:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;color:var(--neon-cyan);font-size:11px;text-transform:uppercase;letter-spacing:.1em;font-family:var(--font-mono);padding:14px 12px;border-bottom:2px solid var(--panel-border)}
td{padding:14px 12px;border-bottom:1px solid #121e2d;vertical-align:top}
td.value{font-family:var(--font-mono);color:#fff;word-break:break-word}
a{color:var(--neon-cyan);text-decoration:none}
a:hover{text-decoration:underline;color:var(--neon-green)}
pre{white-space:pre-wrap;font-size:11px;font-family:var(--font-mono);color:var(--text-muted);background:#070d15;padding:8px;border-radius:4px;border:1px solid #162335}
svg{width:100%;max-height:680px;background:#080e18;border-radius:8px;border:1px solid var(--panel-border)}
#inspector{display:none;background:#09111c;border:1px solid var(--neon-cyan);border-radius:8px;padding:16px;margin-top:16px;box-shadow:0 0 20px rgba(0,229,255,.2)}
footer{color:var(--text-muted);font-size:12px;font-family:var(--font-mono);padding:24px 0;border-top:1px solid var(--panel-border);margin-top:40px}
</style></head><body><main>''' + f'''
<header><div class="brand">SZOBO | DRAXEN</div><p class="eyebrow">AÇIK KAYNAK İSTİHBARATI &amp; SİBER TEHDİT ANALİZİ</p>{demo_banner}<h1>{escape(data["target"]["value"])}</h1><small style="color:var(--neon-cyan);font-family:var(--font-mono)">{escape(data["started_at"])} → {escape(data.get("finished_at", ""))} · {escape(data["target"]["kind"])}</small>
<div class="nav-pills">
<a class="nav-pill" href="#sec-overview">Genel Bakış</a>
<a class="nav-pill" href="#sec-insights">Risk Analizi</a>
<a class="nav-pill" href="#sec-entities">Varlık Dağılımı</a>
<a class="nav-pill" href="#sec-graph">İlişki Haritası</a>
<a class="nav-pill" href="#sec-timeline">Zaman Çizelgesi</a>
<a class="nav-pill" href="#sec-table">Bulgular Tablosu</a>
</div>
</header>
<section id="sec-overview"><h2>Görev &amp; Tarama İstatistikleri</h2><div class="cards"><div class="card"><small>TOPLAM BULGU</small><strong>{len(data["findings"])}</strong></div><div class="card"><small>KAYNAK İŞLEMİ</small><strong>{len(data["sources"])}</strong></div><div class="card"><small>HTTP İSTEĞİ</small><strong>{data.get("requests", 0)}</strong></div><div class="card"><small>ZAMAN ÇİZELGESİ</small><strong>{len(data.get("timeline", []))} olay</strong></div></div>
<div class="tools"><button id="btn-html-md" class="btn-export">Markdown Raporu İndir (.md)</button><button id="btn-json" class="btn-export">JSON Olarak İndir (.json)</button><button id="btn-csv" class="btn-export">CSV Olarak İndir (.csv)</button></div>
</section>
<section><h2>İstihbarat Kaynakları Durumu</h2><ul style="list-style:none;padding:0;">{sources}</ul></section>
{analysis_html(data)}
<section id="sec-graph"><h2>Topoloji ve İlişki Haritası</h2><small>İlk {min(total_nodes, 50)} / {total_nodes} düğüm. Tam grafik graph.dot ve graph.graphml dosyalarındadır. Düğümlerin üzerine gelerek veya tıklayarak bağlı ilişkileri görebilirsiniz.</small>{svg}<div id="inspector"></div></section>
<section id="sec-table"><h2>Bulgular ve Kanıt Envanteri</h2><div class="tools"><input id="search" aria-label="Bulgularda ara" placeholder="Alan adı, IP, port, servis, hash veya kaynak ara…"><select id="kind" aria-label="Bulgu türü"><option value="">Tüm türler ({len(data["findings"])})</option>{options}</select></div><small id="count" style="color:var(--neon-cyan);font-family:var(--font-mono)"></small><div class="table"><table><thead><tr><th>Tür</th><th>Bulgu</th><th>Özne / İlişki</th><th>Kanıt</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
<section><h2>Kapsam ve Değerlendirme İlkeleri</h2><p>{escape(data["policy"])}</p><ul>{warnings}</ul></section><footer>SZOBO | DRAXEN v{escape(data["version"])} · Sıfır harici CDN bağımlılığıyla çevrimdışı çalışır. Güvenli, kaynak izlenebilir siber istihbarat motoru.</footer>''' + f'''
<script>
const jsonData = decodeURIComponent(escape(atob('{json_b64}')));
const csvData = decodeURIComponent(escape(atob('{csv_b64}')));
const mdData = decodeURIComponent(escape(atob('{md_b64}')));

document.getElementById('btn-json').onclick = function() {{
    const blob = new Blob([jsonData], {{type: 'application/json;charset=utf-8'}});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'report.json';
    link.click();
}};

document.getElementById('btn-csv').onclick = function() {{
    const blob = new Blob([csvData], {{type: 'text/csv;charset=utf-8'}});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'findings.csv';
    link.click();
}};

document.getElementById('btn-html-md').onclick = function() {{
    const blob = new Blob([mdData], {{type: 'text/markdown;charset=utf-8'}});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'report.md';
    link.click();
}};

const search = document.getElementById('search');
const kind = document.getElementById('kind');
const count = document.getElementById('count');
const rows = Array.from(document.querySelectorAll('tbody tr'));
function filter() {{
    const query = search.value.toLowerCase();
    const type = kind.value;
    let visible = 0;
    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        const matchesQuery = !query || text.includes(query);
        const matchesType = !type || row.children[0].textContent.trim() === type;
        const show = matchesQuery && matchesType;
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    }});
    count.textContent = `Gösterilen bulgu: ${{visible}} / ${{rows.length}}`;
}}
search.oninput = filter;
kind.onchange = filter;
filter();

document.addEventListener('DOMContentLoaded', () => {{
    const inspector = document.getElementById('inspector');
    document.querySelectorAll('.graph-node').forEach(node => {{
        node.addEventListener('click', () => {{
            const name = node.getAttribute('data-name');
            const kind = node.getAttribute('data-kind');
            inspector.style.display = 'block';
            inspector.innerHTML = `<strong>Seçilen Varlık:</strong> <span class="tag">${{kind}}</span> <span class="value">${{name}}</span>`;
        }});
    }});
}});
</script></main></body></html>'''


def save_reports(data, directory):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    files = {
        "report.json": json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        "report.html": html_report(data),
        "report.md": markdown_report(data),
        "graph.dot": dot_report(data),
        "findings.csv": csv_report(data),
        "graph.graphml": graphml_report(data),
    }
    paths = []
    for name, content in files.items():
        destination = root / name
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
                temporary = handle.name
                handle.write(content)
            os.replace(temporary, destination)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        paths.append(destination)
    return paths


def print_summary(data, *, console=None, paths=(), banner=True, interrupted=False):
    """Render the terminal view without changing the complete report data."""
    (console or TerminalUI()).summary(data, paths=paths, banner=banner, interrupted=interrupted)
