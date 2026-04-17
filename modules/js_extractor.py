"""
js_extractor.py
Crawlea los bundles JS de Next.js y extrae Next-Action IDs estaticamente.

Next.js embebe los action IDs como hashes SHA en el bundle:
  registerServerReference(fn, "<ACTION_ID>", null)
  $$ACTION_0.__ACTION_ID = "<ACTION_ID>"
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

# Patrones conocidos en bundles Next.js
PATTERNS = [
    # registerServerReference(action, "HASH", null)
    re.compile(r'registerServerReference\s*\([^,]+,\s*"([0-9a-f]{10,64})"', re.I),
    # __ACTION_ID = "HASH"
    re.compile(r'__ACTION_ID\s*=\s*"([0-9a-f]{10,64})"', re.I),
    # $$ACTION_REF_0 = "HASH"
    re.compile(r'\$\$ACTION_REF_\w+\s*=\s*"([0-9a-f]{10,64})"', re.I),
    # "Next-Action": "HASH" en fetch calls embebidos
    re.compile(r'"Next-Action"\s*:\s*"([0-9a-f]{10,64})"', re.I),
    # Hashes solos de longitud tipica (40 o 64 chars) — mas ruidoso
    re.compile(r'"([0-9a-f]{40})"'),
    re.compile(r'"([0-9a-f]{64})"'),
]


@dataclass
class ActionID:
    value: str
    source_url: str
    pattern_matched: str
    context: str = ""  # fragmento de JS donde fue encontrado


@dataclass
class ExtractionResult:
    action_ids: list[ActionID] = field(default_factory=list)
    js_urls_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class JSExtractor:
    def __init__(self, base_url: str, timeout: int = 10, verify_ssl: bool = True, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security-Scanner/1.0)"
        })

    def _get(self, url: str) -> str | None:
        try:
            r = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.text
        except Exception as e:
            if self.verbose:
                print(f"  [!] Error GET {url}: {e}")
        return None

    def _find_js_urls(self, html: str, page_url: str) -> list[str]:
        """Encuentra todas las URLs de scripts JS en una pagina HTML."""
        soup = BeautifulSoup(html, "html.parser")
        urls = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            full = urljoin(page_url, src)
            if urlparse(full).netloc == urlparse(self.base_url).netloc:
                urls.append(full)
        return urls

    def _find_next_chunks(self) -> list[str]:
        """Busca los chunks de Next.js en rutas conocidas."""
        common_paths = [
            "/_next/static/chunks/",
            "/_next/static/",
        ]
        chunk_urls = []

        # Parsea la pagina principal para encontrar script tags
        html = self._get(self.base_url)
        if html:
            chunk_urls.extend(self._find_js_urls(html, self.base_url))

        # Busca el manifest de Next.js
        for manifest_path in [
            "/_next/static/development/_devMiddlewareManifest.json",
            "/_next/server/pages-manifest.json",
        ]:
            data = self._get(urljoin(self.base_url, manifest_path))
            if data and self.verbose:
                print(f"  [+] Manifest encontrado: {manifest_path}")

        return list(set(chunk_urls))

    def _extract_from_js(self, js_content: str, source_url: str) -> list[ActionID]:
        """Aplica todos los patrones a un bloque de JS."""
        found = []
        seen = set()

        for pattern in PATTERNS:
            for match in pattern.finditer(js_content):
                action_id = match.group(1)
                if action_id in seen:
                    continue
                seen.add(action_id)

                # Contexto: 80 chars alrededor del match
                start = max(0, match.start() - 80)
                end = min(len(js_content), match.end() + 80)
                context = js_content[start:end].replace("\n", " ")

                found.append(ActionID(
                    value=action_id,
                    source_url=source_url,
                    pattern_matched=pattern.pattern[:50],
                    context=context,
                ))

        return found

    def run(self) -> ExtractionResult:
        result = ExtractionResult()

        print("  [*] Buscando scripts JS...")
        js_urls = self._find_next_chunks()

        if not js_urls:
            result.errors.append("No se encontraron scripts JS en la pagina")
            return result

        print(f"  [+] {len(js_urls)} scripts encontrados")

        for url in js_urls:
            if self.verbose:
                print(f"  [~] Escaneando: {url}")

            content = self._get(url)
            if not content:
                result.errors.append(f"No se pudo descargar: {url}")
                continue

            result.js_urls_scanned.append(url)
            ids = self._extract_from_js(content, url)

            if ids and self.verbose:
                print(f"      -> {len(ids)} action IDs encontrados")

            result.action_ids.extend(ids)

        # Deduplica manteniendo el primero encontrado por valor
        seen = set()
        deduped = []
        for aid in result.action_ids:
            if aid.value not in seen:
                seen.add(aid.value)
                deduped.append(aid)
        result.action_ids = deduped

        return result
