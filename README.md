# Next.js Server Actions Scanner

A security research tool for testing **Prototype Pollution** vulnerabilities in Next.js applications that use Server Actions. Automatically discovers `Next-Action` IDs from JS bundles and tests for RCE escalation.

> Built as part of a personal cybersecurity portfolio. For authorized testing only.

---

## Features

- **Static analysis** — crawls Next.js JS bundles and extracts Server Action IDs using regex patterns (`registerServerReference`, `__ACTION_ID`, etc.)
- **Live proxy capture** — intercepts `Next-Action` headers in real time as you browse the app (requires mitmproxy)
- **Manual mode** — test a specific action ID you already know
- **Prototype pollution payloads** — multiple payload strategies (`__proto__`, `constructor.prototype`, `NODE_OPTIONS`)
- **Optional AI analysis** — classify action IDs by risk using Claude API or a local Ollama model
- **JSON reporting** — export full results for documentation

---

## The Vulnerability

Next.js Server Actions automatically generate hidden HTTP endpoints for every `"use server"` function. These endpoints accept JSON bodies — if the JSON contains `__proto__`, it can pollute the Node.js prototype chain and escalate to RCE via `constructor.constructor`.

```
"use server" function
      ↓
Hidden POST endpoint (Next-Action: <hash>)
      ↓
JSON body with __proto__
      ↓
Prototype pollution → constructor.constructor
      ↓
Remote Code Execution
```

**Affected versions:** Next.js < 14.2.25  
**Fix:** Upgrade to Next.js >= 14.2.25

---

## Installation

```bash
git clone https://github.com/your-username/nextjs-server-actions-scanner
cd nextjs-server-actions-scanner
pip install -r requirements.txt
```

**Optional dependencies:**

```bash
# For live proxy mode
pip install mitmproxy

# For Claude AI backend
pip install anthropic
```

---

## Usage

### Static scan (recommended first step)
```bash
python scanner.py http://localhost:3000 --mode static
```

### Static scan + full exploitation
```bash
python scanner.py http://localhost:3000 --mode all --cmd "whoami"
```

### Live proxy — browse the app while it captures action IDs
```bash
# 1. Start the interceptor
python scanner.py http://localhost:3000 --mode proxy --proxy-port 8080

# 2. Configure your browser to use 127.0.0.1:8080 as HTTP proxy
# 3. Browse the app normally — action IDs are captured automatically
# 4. Press Ctrl+C when done
```

### Manual mode — test a known action ID
```bash
python scanner.py http://localhost:3000 --mode manual --action-id abc123def456 --cmd "id"
```

### With AI analysis
```bash
# Claude API
export ANTHROPIC_API_KEY=sk-...
python scanner.py http://localhost:3000 --mode static --ai claude

# Local Ollama (no API key needed)
python scanner.py http://localhost:3000 --mode static --ai ollama --ai-model llama3
```

### Export report
```bash
python scanner.py http://localhost:3000 --mode all --output report.json
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--mode` | `static` / `proxy` / `manual` / `all` | `static` |
| `--path` | Endpoint path to test | `/` |
| `--action-id` | Action ID for manual mode | — |
| `--cmd` | Command for RCE payloads | `id` |
| `--ai` | AI backend: `none` / `claude` / `ollama` | `none` |
| `--ai-model` | Model name for AI backend | auto |
| `--ai-key` | Anthropic API key | env var |
| `--ollama-host` | Ollama server URL | `http://localhost:11434` |
| `--proxy-port` | Port for proxy interceptor | `8080` |
| `--timeout` | Request timeout in seconds | `10` |
| `--no-verify` | Disable SSL verification | false |
| `--no-exploit` | Discovery only, skip payloads | false |
| `--output` | Save JSON report to file | — |
| `-v` / `--verbose` | Verbose output | false |

---

## Project Structure

```
nextjs-server-actions-scanner/
├── scanner.py                  # Main CLI and orchestrator
├── requirements.txt
└── modules/
    ├── js_extractor.py         # Static JS analysis + action ID extraction
    ├── proxy_interceptor.py    # Live mitmproxy-based capture
    ├── ai_analyzer.py          # Claude / Ollama / heuristic analysis
    └── reporter.py             # Formatted output and JSON export
```

---

## How Action IDs Are Found

Next.js embeds Server Action IDs as SHA hashes in the compiled JS bundle. The scanner looks for these patterns:

```js
// Pattern 1 — most common
registerServerReference(fn, "a1b2c3d4e5f6...", null)

// Pattern 2
$$ACTION_REF_0 = "a1b2c3d4e5f6..."

// Pattern 3
__ACTION_ID = "a1b2c3d4e5f6..."
```

If static analysis fails (e.g. the bundle is heavily obfuscated), use `--mode proxy` to capture IDs organically while browsing.

---

## AI Backends

| Backend | Model | Requires |
|---------|-------|----------|
| `heuristic` | Keyword-based (no AI) | Nothing |
| `claude` | Claude Haiku (fast + cheap) | `ANTHROPIC_API_KEY` |
| `ollama` | Any local model | Ollama running locally |

The AI module classifies each action ID by probable function, risk level, and whether it handles user input — helping you prioritize which IDs to test first.

---

## Disclaimer

**This tool is intended strictly for authorized security testing, CTF challenges, and educational purposes.**

- Only use this tool against systems you own or have explicit written permission to test.
- The author assumes no responsibility for any misuse, damage, or illegal activity resulting from the use of this software.
- Unauthorized use against systems you do not own is illegal and unethical.
- Always obtain proper authorization before conducting any security assessment.

By using this tool, you agree that you are solely responsible for your actions and that you will use it only in legal and authorized contexts.

---

## References

- [Next.js Security Advisory](https://nextjs.org/blog/security-advisories)
- [Prototype Pollution — PortSwigger](https://portswigger.net/web-security/prototype-pollution)
- [OWASP — Injection](https://owasp.org/www-community/attacks/Code_Injection)

---

## Author

Built by **[mateobris](https://github.com/mateobris)** as part of a cybersecurity portfolio.  
Feel free to open issues or PRs.
