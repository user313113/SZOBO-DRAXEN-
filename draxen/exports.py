import csv
import io
import json
import xml.etree.ElementTree as ET


def safe_cell(value):
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def csv_report(data):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(("kind", "value", "subject", "relation", "status", "source", "observed_at", "details"))
    for item in data["findings"]:
        for evidence in item["evidence"]:
            writer.writerow([safe_cell(value) for value in (
                item["kind"], item["value"], item["subject"], item["relation"],
                evidence["status"], evidence["source"], evidence["observed_at"],
                json.dumps(evidence.get("details", {}), ensure_ascii=False),
            )])
    return stream.getvalue()


def xml_text(value):
    return "".join(c for c in str(value) if c in "\t\n\r" or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF)


def graphml_report(data):
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    tag = lambda value: "{" + namespace + "}" + value
    root = ET.Element(tag("graphml"))
    for key, scope in (("label", "node"), ("relation", "edge"), ("kind", "edge"), ("evidence", "edge")):
        ET.SubElement(root, tag("key"), {"id": key, "for": scope, "attr.name": key, "attr.type": "string"})
    graph = ET.SubElement(root, tag("graph"), {"id": "DRAXEN", "edgedefault": "directed"})
    nodes = {}
    def node(value):
        if value not in nodes:
            nodes[value] = "n" + str(len(nodes))
            element = ET.SubElement(graph, tag("node"), {"id": nodes[value]})
            ET.SubElement(element, tag("data"), {"key": "label"}).text = xml_text(value)
        return nodes[value]
    node(data["target"]["value"])
    for item in data["findings"]:
        node(item["subject"])
        node(item["value"])
    for index, item in enumerate(data["findings"]):
        edge = ET.SubElement(graph, tag("edge"), {"id": "e" + str(index), "source": nodes[item["subject"]], "target": nodes[item["value"]]})
        for key in ("kind", "relation", "evidence"):
            value = json.dumps(item[key], ensure_ascii=False) if key == "evidence" else item[key]
            ET.SubElement(edge, tag("data"), {"key": key}).text = xml_text(value)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)
