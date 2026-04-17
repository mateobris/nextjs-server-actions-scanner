"""
ai_analyzer.py
Modulo opcional de IA para analizar fragmentos JS y action IDs.

Backends soportados:
  - claude   : Anthropic Claude API (requiere ANTHROPIC_API_KEY)
  - ollama   : Modelo local via Ollama (requiere ollama corriendo)
  - none     : Sin IA, solo heuristica

El modulo toma un fragmento de JS + lista de action IDs y devuelve:
  - Clasificacion de cada ID (form action, API call, auth, etc.)
  - Estimacion de superficie de ataque
  - Sugerencias de payloads especificos
"""

import os
import json
import re
from dataclasses import dataclass

SYSTEM_PROMPT = """Eres un experto en seguridad web especializado en Next.js.
Se te proporcionaran fragmentos de codigo JavaScript de una aplicacion Next.js
y una lista de Next-Action IDs encontrados en el bundle.

Tu tarea:
1. Identificar que hace cada action ID basandote en el contexto JS
2. Clasificar su peligrosidad (alta/media/baja) para prototype pollution
3. Sugerir el payload mas apropiado para testear cada uno
4. Indicar si el action parece manejar input del usuario (mayor riesgo)

Responde en JSON con el formato:
{
  "actions": [
    {
      "id": "<action_id>",
      "probable_function": "<descripcion>",
      "risk": "high|medium|low",
      "handles_user_input": true|false,
      "suggested_payload_type": "<tipo>",
      "notes": "<observaciones>"
    }
  ],
  "general_notes": "<observaciones generales>"
}
"""

USER_PROMPT_TEMPLATE = """Analiza estos Next-Action IDs encontrados en el bundle JS:

ACTION IDs:
{action_ids}

FRAGMENTOS DE CONTEXTO JS:
{js_contexts}

Clasifica cada action ID segun las instrucciones."""


@dataclass
class ActionAnalysis:
    action_id: str
    probable_function: str
    risk: str  # high / medium / low
    handles_user_input: bool
    suggested_payload_type: str
    notes: str


@dataclass
class AnalysisResult:
    analyses: list[ActionAnalysis]
    general_notes: str
    backend_used: str
    error: str = ""


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class ClaudeBackend:
    def __init__(self, model: str = "claude-haiku-4-5-20251001", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY no configurada. Exporta la variable o usa --ai-key")

    def analyze(self, action_ids: list[str], js_contexts: list[str]) -> dict:
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install anthropic")

        client = anthropic.Anthropic(api_key=self.api_key)

        user_msg = USER_PROMPT_TEMPLATE.format(
            action_ids="\n".join(f"  - {aid}" for aid in action_ids),
            js_contexts="\n\n".join(
                f"[Contexto {i+1}]:\n{ctx[:300]}"
                for i, ctx in enumerate(js_contexts[:10])  # max 10 contextos
            )
        )

        response = client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )

        raw = response.content[0].text
        # Extrae JSON de la respuesta
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {"actions": [], "general_notes": raw}


class OllamaBackend:
    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def analyze(self, action_ids: list[str], js_contexts: list[str]) -> dict:
        try:
            import requests
        except ImportError:
            raise ImportError("pip install requests")

        import requests as req

        user_msg = USER_PROMPT_TEMPLATE.format(
            action_ids="\n".join(f"  - {aid}" for aid in action_ids),
            js_contexts="\n\n".join(
                f"[Contexto {i+1}]:\n{ctx[:300]}"
                for i, ctx in enumerate(js_contexts[:10])
            )
        )

        full_prompt = f"{SYSTEM_PROMPT}\n\n{user_msg}"

        response = req.post(
            f"{self.host}/api/generate",
            json={"model": self.model, "prompt": full_prompt, "stream": False},
            timeout=120,
        )
        response.raise_for_status()
        raw = response.json().get("response", "")

        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {"actions": [], "general_notes": raw}


# ---------------------------------------------------------------------------
# Heuristica sin IA
# ---------------------------------------------------------------------------

class HeuristicBackend:
    """
    Clasifica action IDs sin IA usando heuristica sobre el contexto JS.
    Menos preciso pero sin dependencias externas.
    """

    HIGH_RISK_KEYWORDS = [
        "exec", "eval", "spawn", "child_process", "shell", "cmd",
        "upload", "file", "delete", "admin", "password", "auth",
        "token", "session", "cookie", "env", "process",
    ]
    MEDIUM_RISK_KEYWORDS = [
        "form", "submit", "create", "update", "save", "send",
        "email", "user", "data", "input", "request",
    ]

    def analyze(self, action_ids: list[str], js_contexts: list[str]) -> dict:
        actions = []
        combined_ctx = " ".join(js_contexts).lower()

        for aid in action_ids:
            # Busca contexto especifico de este ID
            specific_ctx = ""
            for ctx in js_contexts:
                if aid in ctx:
                    specific_ctx = ctx.lower()
                    break

            search_ctx = specific_ctx or combined_ctx

            # Determina riesgo por keywords
            risk = "low"
            matched_high = [k for k in self.HIGH_RISK_KEYWORDS if k in search_ctx]
            matched_med = [k for k in self.MEDIUM_RISK_KEYWORDS if k in search_ctx]

            if matched_high:
                risk = "high"
            elif matched_med:
                risk = "medium"

            handles_input = any(k in search_ctx for k in ["input", "form", "user", "body", "request"])

            actions.append({
                "id": aid,
                "probable_function": f"Desconocida (keywords: {matched_high or matched_med or ['ninguna']})",
                "risk": risk,
                "handles_user_input": handles_input,
                "suggested_payload_type": "prototype_pollution" if risk in ("high", "medium") else "detection_only",
                "notes": f"Heuristica. Keywords detectadas: {matched_high + matched_med}",
            })

        return {"actions": actions, "general_notes": "Analisis heuristico sin IA"}


# ---------------------------------------------------------------------------
# Interfaz publica
# ---------------------------------------------------------------------------

def analyze(
    action_ids: list[str],
    js_contexts: list[str],
    backend: str = "heuristic",
    model: str = "",
    api_key: str = "",
    ollama_host: str = "http://localhost:11434",
) -> AnalysisResult:
    """
    Analiza una lista de action IDs.

    backend: "claude" | "ollama" | "heuristic"
    """
    try:
        if backend == "claude":
            b = ClaudeBackend(model=model or "claude-haiku-4-5-20251001", api_key=api_key)
        elif backend == "ollama":
            b = OllamaBackend(model=model or "llama3", host=ollama_host)
        else:
            b = HeuristicBackend()

        raw = b.analyze(action_ids, js_contexts)

        analyses = []
        for a in raw.get("actions", []):
            analyses.append(ActionAnalysis(
                action_id=a.get("id", ""),
                probable_function=a.get("probable_function", ""),
                risk=a.get("risk", "low"),
                handles_user_input=a.get("handles_user_input", False),
                suggested_payload_type=a.get("suggested_payload_type", ""),
                notes=a.get("notes", ""),
            ))

        return AnalysisResult(
            analyses=analyses,
            general_notes=raw.get("general_notes", ""),
            backend_used=backend,
        )

    except Exception as e:
        return AnalysisResult(
            analyses=[],
            general_notes="",
            backend_used=backend,
            error=str(e),
        )
