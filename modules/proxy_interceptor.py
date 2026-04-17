"""
proxy_interceptor.py
Proxy HTTP local que captura Next-Action IDs en tiempo real.

Uso: configura tu browser para usar 127.0.0.1:8080 como proxy,
navega el SaaS y el interceptor captura los IDs automaticamente.

Requiere: mitmproxy (pip install mitmproxy)
"""

import threading
import json
import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CapturedAction:
    action_id: str
    url: str
    method: str
    timestamp: str
    request_body: str = ""
    response_status: int = 0
    response_redirect: str = ""


class ActionStore:
    """Store thread-safe de acciones capturadas."""
    def __init__(self):
        self._lock = threading.Lock()
        self._actions: list[CapturedAction] = []
        self._seen: set[str] = set()

    def add(self, action: CapturedAction) -> bool:
        with self._lock:
            if action.action_id not in self._seen:
                self._seen.add(action.action_id)
                self._actions.append(action)
                return True
        return False

    def all(self) -> list[CapturedAction]:
        with self._lock:
            return list(self._actions)

    def count(self) -> int:
        with self._lock:
            return len(self._actions)


# Store global accesible desde el addon mitmproxy
_store = ActionStore()


def get_store() -> ActionStore:
    return _store


# ---------------------------------------------------------------------------
# Addon para mitmproxy
# ---------------------------------------------------------------------------

class NextActionAddon:
    """Addon de mitmproxy que intercepta requests con header Next-Action."""

    def __init__(self, store: ActionStore, target_host: str = "", verbose: bool = False):
        self.store = store
        self.target_host = target_host.replace("https://", "").replace("http://", "").rstrip("/")
        self.verbose = verbose

    def request(self, flow):
        headers = dict(flow.request.headers)
        action_id = headers.get("next-action") or headers.get("Next-Action")

        if not action_id:
            return

        # Filtra por host si se especifico
        if self.target_host and self.target_host not in flow.request.pretty_host:
            return

        body = ""
        try:
            body = flow.request.content.decode("utf-8", errors="replace")[:500]
        except Exception:
            pass

        action = CapturedAction(
            action_id=action_id,
            url=flow.request.pretty_url,
            method=flow.request.method,
            timestamp=datetime.now().isoformat(),
            request_body=body,
        )

        if self.store.add(action):
            print(f"\n  [CAPTURADO] Next-Action: {action_id}")
            print(f"             URL: {action.url}")
            if self.verbose:
                print(f"             Body: {body[:100]}")

    def response(self, flow):
        """Captura el response para acciones ya registradas."""
        headers = dict(flow.request.headers)
        action_id = headers.get("next-action") or headers.get("Next-Action")
        if not action_id:
            return

        redirect = flow.response.headers.get("x-action-redirect", "")
        status = flow.response.status_code

        # Actualiza la accion con datos del response
        store = self.store
        with store._lock:
            for action in store._actions:
                if action.action_id == action_id and not action.response_status:
                    action.response_status = status
                    action.response_redirect = redirect
                    break


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_proxy(port: int = 8080, target_url: str = "", verbose: bool = False) -> ActionStore:
    """
    Lanza el proxy mitmproxy en un thread separado.
    Retorna el ActionStore donde se acumulan los IDs capturados.
    """
    try:
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy import options
    except ImportError:
        raise ImportError(
            "mitmproxy no instalado. Ejecuta: pip install mitmproxy"
        )

    store = ActionStore()
    addon = NextActionAddon(store=store, target_host=target_url, verbose=verbose)

    def _run():
        opts = options.Options(listen_host="127.0.0.1", listen_port=port)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(addon)
        try:
            master.run()
        except KeyboardInterrupt:
            master.shutdown()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return store


# ---------------------------------------------------------------------------
# Modo sin mitmproxy: polling manual de requests con requests-mock
# ---------------------------------------------------------------------------

class SimpleInterceptor:
    """
    Alternativa liviana: monkey-patch de requests para capturar
    Next-Action headers en scripts que usan requests internamente.
    No requiere mitmproxy.
    """

    def __init__(self):
        self.store = ActionStore()
        self._original_send = None

    def start(self):
        import requests
        original_send = requests.Session.send

        store = self.store

        def patched_send(session_self, prepared_request, **kwargs):
            action_id = prepared_request.headers.get("Next-Action")
            if action_id:
                action = CapturedAction(
                    action_id=action_id,
                    url=prepared_request.url,
                    method=prepared_request.method,
                    timestamp=datetime.now().isoformat(),
                )
                if store.add(action):
                    print(f"  [INTERCEPTADO] Next-Action: {action_id} @ {prepared_request.url}")

            return original_send(session_self, prepared_request, **kwargs)

        self._original_send = original_send
        requests.Session.send = patched_send

    def stop(self):
        if self._original_send:
            import requests
            requests.Session.send = self._original_send
