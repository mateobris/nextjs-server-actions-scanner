"""
reporter.py
Output formateado para el scanner.
"""

import json
import sys
from datetime import datetime

# Fuerza UTF-8 en Windows para evitar UnicodeEncodeError con caracteres de caja
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

RISK_COLOR = {
    "high":   RED + BOLD,
    "medium": YELLOW,
    "low":    GREEN,
}


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║   Next.js Server Actions Scanner  v2.0                  ║
║   Prototype Pollution + Action ID Discovery              ║
║   Solo para entornos propios/autorizados                 ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def section(title: str):
    print(f"\n{CYAN}{BOLD}{'═' * 55}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * 55}{RESET}")


def print_action_ids(action_ids, analyses=None):
    section("ACTION IDs ENCONTRADOS")

    analysis_map = {}
    if analyses:
        for a in analyses:
            analysis_map[a.action_id] = a

    if not action_ids:
        print(f"  {YELLOW}No se encontraron action IDs{RESET}")
        return

    for aid in action_ids:
        analysis = analysis_map.get(aid.value)
        risk = analysis.risk if analysis else "unknown"
        color = RISK_COLOR.get(risk, DIM)

        print(f"\n  {color}[{risk.upper()}]{RESET} {BOLD}{aid.value}{RESET}")
        print(f"  {DIM}Fuente: {aid.source_url[:70]}{RESET}")

        if analysis:
            print(f"  Funcion probable : {analysis.probable_function}")
            print(f"  Input de usuario : {'Si' if analysis.handles_user_input else 'No'}")
            print(f"  Payload sugerido : {analysis.suggested_payload_type}")
            if analysis.notes:
                print(f"  Notas            : {DIM}{analysis.notes[:100]}{RESET}")

        if aid.context:
            ctx_preview = aid.context[:120].replace("\n", " ")
            print(f"  Contexto JS      : {DIM}{ctx_preview}...{RESET}")


def print_exploit_results(results: list[dict]):
    section("RESULTADOS DE EXPLOTACION")

    vulns = [r for r in results if r.get("vulnerable")]
    safe  = [r for r in results if not r.get("vulnerable")]

    if vulns:
        print(f"\n  {RED}{BOLD}VULNERABILIDADES ENCONTRADAS: {len(vulns)}{RESET}")
        for r in vulns:
            print(f"\n  {RED}[VULN]{RESET} Action: {r['action_id']}")
            print(f"         Payload : {r['payload_desc']}")
            print(f"         Status  : {r['status']}")
            if r.get("output"):
                print(f"         Output  : {BOLD}{r['output'][:200]}{RESET}")
    else:
        print(f"\n  {GREEN}No se detectaron vulnerabilidades con los payloads probados.{RESET}")
        print(f"  {DIM}Esto puede significar que esta parchado, o que el action ID no es valido.{RESET}")

    if safe:
        print(f"\n  {DIM}Endpoints sin indicadores: {len(safe)}{RESET}")


def print_summary(target: str, n_ids: int, n_vuln: int, backend: str, elapsed: float):
    section("RESUMEN")
    print(f"  Target         : {target}")
    print(f"  Action IDs     : {n_ids}")
    print(f"  Vulnerables    : {RED + BOLD if n_vuln else GREEN}{n_vuln}{RESET}")
    print(f"  Backend IA     : {backend}")
    print(f"  Tiempo total   : {elapsed:.1f}s")
    print(f"  Timestamp      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if n_vuln:
        print(f"\n  {RED}{BOLD}ACCION REQUERIDA: Actualizar Next.js a >= 14.2.25{RESET}")
    print()


def save_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  {GREEN}[+] Reporte guardado en: {path}{RESET}")
