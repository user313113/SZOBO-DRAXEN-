"""Read-only test tool catalog (data/test_tools.json).

Display only: DRAXEN lists names, categories, dependencies and links. It never
downloads, installs or runs a catalogued tool. The JSON file stays the single
source of truth; extend it in place, no code change is required.
"""

import json
from pathlib import Path

DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "data" / "test_tools.json"

DISCLAIMER = ("Bu sayfa yalnızca listeleme yapar; aracı indirmez, kurmaz "
              "ya da çalıştırmaz.")
ETHICS = ("Araçları yalnızca araştırma yetkinizin bulunduğu hedeflerde, "
          "eğitim amaçlı kullanın.")


def _as_list(value):
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_tool(key, raw):
    """Tolerant entry mapping; missing fields fall back to safe defaults."""
    raw = raw if isinstance(raw, dict) else {}
    slug = str(key).strip() or str(key)
    name = str(raw.get("name") or "").strip() or slug
    url = str(raw.get("url") or "").strip()
    desc = str(raw.get("desc") or "").strip()
    categories = _as_list(raw.get("category")) or ["uncategorized"]
    dependencies = _as_list(raw.get("dependency"))
    manager = str(raw.get("package_manager") or "git").strip().casefold() or "git"
    return {
        "slug": slug,
        "name": name,
        "desc": desc,
        "url": url,
        "categories": categories,
        "dependencies": dependencies,
        "package_manager": manager,
    }


class ToolCatalog:
    def __init__(self, tools, source=""):
        self.tools = list(tools)
        self.source = str(source)
        self.by_slug = {tool["slug"]: tool for tool in self.tools}

    def __len__(self):
        return len(self.tools)

    def __iter__(self):
        return iter(self.tools)

    def search(self, query):
        """Case-insensitive substring match over name, url, categories and desc."""
        needle = str(query).strip().casefold()
        if not needle:
            return list(self.tools)
        hits = []
        for tool in self.tools:
            haystack = " ".join(
                (tool["name"], tool["slug"], tool["url"], tool["desc"],
                 " ".join(tool["categories"]))
            ).casefold()
            if needle in haystack:
                hits.append(tool)
        return hits

    def categories(self):
        """Ordered (category, count) pairs in first-seen file order."""
        counts, order = {}, []
        for tool in self.tools:
            for category in tool["categories"]:
                if category not in counts:
                    order.append(category)
                counts[category] = counts.get(category, 0) + 1
        return [(name, counts[name]) for name in order]

    def install_hint(self, tool):
        """Display-only command suggestion; DRAXEN never executes it."""
        url = tool.get("url", "")
        if not url:
            return "Kayıtta bağlantı yok."
        manager = tool.get("package_manager", "git")
        if manager == "curl":
            return "curl -L " + url
        if manager == "git":
            return "git clone " + url
        return url


def load_catalog(path=None):
    """Load the JSON catalog. Never raises: returns (catalog, error)."""
    source = Path(path) if path is not None else DEFAULT_CATALOG
    if not source.is_file():
        return None, "Katalog bulunamadı: " + str(source)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "Katalog okunamadı ya da bozuk JSON: " + source.name
    if not isinstance(raw, dict) or not raw:
        return None, "Katalog boş ya da biçimi geçersiz: " + source.name
    tools = [normalize_tool(key, value) for key, value in raw.items()]
    return ToolCatalog(tools, source=source), None
