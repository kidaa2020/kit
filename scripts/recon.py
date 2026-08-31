#!/usr/bin/env python3
"""
ReconKit — Script de recon para GitHub Actions
Lee variables de entorno y ejecuta todos los módulos
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import aiohttp

# ── Config desde env ──────────────────────────────────────
TARGET     = os.environ.get("TARGET", "").strip().lower()
TARGET     = re.sub(r"https?://", "", TARGET).rstrip("/")
MODULES    = [m.strip() for m in os.environ.get("MODULES", "subdomains,ports,js,web,ai").split(",")]
PORT_MODE  = os.environ.get("PORT_MODE", "fast")
API_KEY    = os.environ.get("OPENROUTER_KEY", "")

if not TARGET:
    print("✗ TARGET no definido", file=sys.stderr)
    sys.exit(1)

DATE_STR  = datetime.now().strftime("%Y-%m-%d_%H-%M")
AUDIT_DIR = Path("audits") / TARGET / DATE_STR
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE  = AUDIT_DIR / "scan.log"

def log(msg, level="INFO"):
    ts  = datetime.now().strftime("%H:%M:%S")
    icons = {"INFO": "→", "OK": "✔", "WARN": "⚠", "ERROR": "✗", "SECTION": "\n┌─"}
    icon = icons.get(level, "→")
    line = f"[{ts}] {icon}  {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def run(cmd, capture=False, timeout=600):
    log(f"$ {cmd[:100]}")
    try:
        if capture:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout + r.stderr
        else:
            r = subprocess.run(cmd, shell=True, timeout=timeout)
            return r.returncode, ""
    except subprocess.TimeoutExpired:
        log(f"Timeout: {cmd[:60]}", "WARN")
        return 1, ""
    except Exception as e:
        log(f"Error: {e}", "ERROR")
        return 1, ""

def count_lines(path):
    try:
        return sum(1 for l in open(path) if l.strip())
    except Exception:
        return 0

def tool_ok(name):
    rc, _ = run(f"which {name}", capture=True)
    return rc == 0

# ══════════════════════════════════════════════════════════
# MÓDULO 1 — Subdominios
# ══════════════════════════════════════════════════════════

async def run_subdomains():
    log("SUBDOMINIOS", "SECTION")
    subs_file  = AUDIT_DIR / "subdomains_raw.txt"
    alive_file = AUDIT_DIR / "subdomains_alive.txt"
    results    = {"subdomains_found": 0, "subdomains_alive": 0, "files": []}

    # subfinder
    if tool_ok("subfinder"):
        log("subfinder...")
        run(f"subfinder -d {TARGET} -silent -o {subs_file}")
    
    # assetfinder
    if tool_ok("assetfinder"):
        log("assetfinder...")
        tmp = AUDIT_DIR / "assetfinder_tmp.txt"
        run(f"assetfinder --subs-only {TARGET} > {tmp} 2>/dev/null")
        run(f"cat {tmp} >> {subs_file} 2>/dev/null; sort -u {subs_file} -o {subs_file} 2>/dev/null")

    # crt.sh
    log("crt.sh...")
    try:
        async with aiohttp.ClientSession() as s:
            url = f"https://crt.sh/?q=%.{TARGET}&output=json"
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    subs = {e["name_value"].replace("*.", "").strip()
                            for e in data if TARGET in e.get("name_value", "")}
                    with open(subs_file, "a") as f:
                        f.write("\n".join(subs) + "\n")
                    run(f"sort -u {subs_file} -o {subs_file}")
                    log(f"crt.sh: {len(subs)} entradas", "OK")
    except Exception as e:
        log(f"crt.sh falló: {e}", "WARN")

    if subs_file.exists():
        results["subdomains_found"] = count_lines(subs_file)
        results["files"].append(str(subs_file))
        log(f"{results['subdomains_found']} subdominios únicos", "OK")

    # httpx
    if tool_ok("httpx") and subs_file.exists():
        log("httpx — filtrando vivos...")
        run(f"httpx -l {subs_file} -silent -o {alive_file} -status-code -title -tech-detect")
        if alive_file.exists():
            results["subdomains_alive"] = count_lines(alive_file)
            results["files"].append(str(alive_file))
            log(f"{results['subdomains_alive']} subdominios vivos", "OK")

    return results


# ══════════════════════════════════════════════════════════
# MÓDULO 2 — Puertos
# ══════════════════════════════════════════════════════════

def run_ports():
    log("PUERTOS", "SECTION")
    out_file = AUDIT_DIR / "ports.txt"
    xml_file = AUDIT_DIR / "ports.xml"
    results  = {"ports_open": 0, "interesting_services": [], "files": []}

    profiles = {
        "fast":     f"nmap -T4 -F --open -oN {out_file} -oX {xml_file} {TARGET}",
        "full":     f"nmap -T4 -p- --open -sV -oN {out_file} -oX {xml_file} {TARGET}",
        "stealth":  f"nmap -sS -T2 --open -oN {out_file} -oX {xml_file} {TARGET}",
        "services": f"nmap -T4 -p- --open -sV -sC -oN {out_file} -oX {xml_file} {TARGET}",
    }

    if not tool_ok("nmap"):
        log("nmap no encontrado", "ERROR")
        return results

    run(profiles.get(PORT_MODE, profiles["fast"]))

    if out_file.exists():
        content = out_file.read_text()
        open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", content)
        results["ports_open"] = len(open_ports)
        interesting_set = {"8080","8443","9200","6379","27017","5432","3306",
                           "2375","4243","9000","8888","3000","5000","21","23","25"}
        results["interesting_services"] = [p for p, _ in open_ports if p in interesting_set]
        results["files"].append(str(out_file))
        log(f"{len(open_ports)} puertos abiertos", "OK")
        if results["interesting_services"]:
            log(f"Puertos sensibles: {', '.join(results['interesting_services'])}", "WARN")

    return results


# ══════════════════════════════════════════════════════════
# MÓDULO 3 — JavaScript
# ══════════════════════════════════════════════════════════

def run_js():
    log("JAVASCRIPT", "SECTION")
    js_dir         = AUDIT_DIR / "js_files"
    js_dir.mkdir(exist_ok=True)
    js_list        = AUDIT_DIR / "js_urls.txt"
    secrets_file   = AUDIT_DIR / "secrets.txt"
    endpoints_file = AUDIT_DIR / "endpoints.txt"
    results        = {"js_files": 0, "secrets_found": 0, "endpoints_found": 0, "files": []}

    # gau
    if tool_ok("gau"):
        log("gau...")
        run(f"gau {TARGET} --blacklist png,jpg,gif,svg,woff,ttf,css 2>/dev/null | grep -E '\\.js(\\?|$)' | sort -u >> {js_list}")

    # katana
    if tool_ok("katana"):
        log("katana...")
        tmp = AUDIT_DIR / "katana_tmp.txt"
        run(f"katana -u https://{TARGET} -silent -jc -d 3 -o {tmp} 2>/dev/null")
        if tmp.exists():
            run(f"grep -E '\\.js(\\?|$)' {tmp} >> {js_list} 2>/dev/null")

    # fallback curl
    if not js_list.exists() or count_lines(js_list) == 0:
        log("Fallback curl para JS...")
        rc, html = run(f"curl -sk --max-time 15 https://{TARGET}", capture=True)
        if rc == 0:
            found = []
            for u in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html):
                if u.startswith("http"):     found.append(u)
                elif u.startswith("//"):     found.append("https:" + u)
                elif u.startswith("/"):      found.append(f"https://{TARGET}{u}")
                else:                        found.append(f"https://{TARGET}/{u}")
            if found:
                with open(js_list, "w") as f:
                    f.write("\n".join(set(found)) + "\n")
                log(f"curl encontró {len(set(found))} JS", "OK")

    if js_list.exists():
        run(f"sort -u {js_list} -o {js_list}")

    total = count_lines(js_list) if js_list.exists() else 0
    log(f"{total} archivos JS a descargar")

    # Descargar
    downloaded = 0
    if js_list.exists():
        with open(js_list) as f:
            urls = [l.strip() for l in f if l.strip()]
        for url in urls:
            fname = re.sub(r"https?://", "", url)
            fname = re.sub(r"[^\w.]", "_", fname)[:100] + ".js"
            out = js_dir / fname
            rc, _ = run(f"curl -sk --max-time 20 -L -o '{out}' '{url}'", capture=True)
            if rc == 0 and out.exists() and out.stat().st_size > 0:
                downloaded += 1

    results["js_files"] = downloaded
    log(f"{downloaded} JS descargados", "OK")

    # Análisis patterns
    secret_patterns = [
        (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']',          "API Key"),
        (r'(?i)(secret|token|password|passwd)\s*[=:]\s*["\']([A-Za-z0-9\-_!@#$%^&*]{8,})["\']', "Secret/Token"),
        (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']([A-Z0-9]{20})["\']',                    "AWS Access Key"),
        (r'(?i)(aws_secret_access_key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',          "AWS Secret Key"),
        (r'(?i)bearer\s+([A-Za-z0-9\-_=.]{20,})',                                          "Bearer Token"),
        (r'(mongodb|postgresql|mysql|redis|amqp)://[^\s"\'<>]+',                            "DB Connection"),
        (r'(?i)(client[_\-]?id|client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{8,})["\']', "OAuth"),
        (r'AIza[0-9A-Za-z\-_]{35}',                                                        "Google API Key"),
        (r'ghp_[A-Za-z0-9]{36}',                                                           "GitHub Token"),
        (r'xox[baprs]-[A-Za-z0-9\-]+',                                                     "Slack Token"),
    ]
    endpoint_patterns = [
        r'(?i)["\'](/api/v\d+/[a-zA-Z0-9/_\-?=&]+)["\']',
        r'(?i)["\'](/graphql[^\s"\']*)["\']',
        r'(?i)["\'](/rest/[a-zA-Z0-9/_\-]+)["\']',
        r'(?i)fetch\(["\']([^\s"\']+)["\']',
        r'(?i)axios\.[a-z]+\(["\']([^\s"\']+)["\']',
    ]

    secrets   = []
    endpoints = set()
    for jf in js_dir.glob("*.js"):
        try:
            content = jf.read_text(errors="replace")
            for pat, label in secret_patterns:
                for m in re.finditer(pat, content):
                    secrets.append(f"[{label}] {jf.name}: {m.group(0)[:100]}")
            for pat in endpoint_patterns:
                for m in re.finditer(pat, content):
                    ep = m.group(1)
                    if len(ep) > 3:
                        endpoints.add(ep)
        except Exception:
            continue

    if secrets:
        secrets = list(dict.fromkeys(secrets))
        secrets_file.write_text("\n".join(secrets))
        results["secrets_found"] = len(secrets)
        results["files"].append(str(secrets_file))
        log(f"⚠ {len(secrets)} posibles secrets", "WARN")

    if endpoints:
        endpoints_file.write_text("\n".join(sorted(endpoints)))
        results["endpoints_found"] = len(endpoints)
        results["files"].append(str(endpoints_file))
        log(f"{len(endpoints)} endpoints extraídos", "OK")

    # nuclei
    if tool_ok("nuclei") and js_list.exists():
        log("nuclei sobre JS...")
        nuclei_out = AUDIT_DIR / "nuclei_js.txt"
        run(f"nuclei -l {js_list} -t exposures/ -silent -o {nuclei_out} 2>/dev/null")
        if nuclei_out.exists() and nuclei_out.stat().st_size > 0:
            results["files"].append(str(nuclei_out))

    results["files"].append(str(js_list))
    return results


# ══════════════════════════════════════════════════════════
# MÓDULO 4 — Web
# ══════════════════════════════════════════════════════════

def run_web():
    log("ANÁLISIS WEB", "SECTION")
    headers_file = AUDIT_DIR / "headers.txt"
    tech_file    = AUDIT_DIR / "technologies.txt"
    fuzz_file    = AUDIT_DIR / "fuzz_results.txt"
    base_url     = f"https://{TARGET}"
    results      = {"vuln_hints": 0, "files": []}

    # Headers
    run(f"curl -sI --max-time 10 {base_url} > {headers_file}")
    if headers_file.exists():
        content = headers_file.read_text().lower()
        sec = ["strict-transport-security","content-security-policy",
               "x-frame-options","x-content-type-options","permissions-policy","referrer-policy"]
        missing = [h for h in sec if h not in content]
        results["vuln_hints"] += len(missing)
        if missing:
            log(f"Headers ausentes: {', '.join(missing)}", "WARN")

    # whatweb
    if tool_ok("whatweb"):
        run(f"whatweb -a 3 {base_url} > {tech_file} 2>/dev/null")
        results["files"].append(str(tech_file))

    # ffuf
    if tool_ok("ffuf"):
        wordlists = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        wl = next((w for w in wordlists if Path(w).exists()), None)
        if wl:
            run(f"ffuf -u {base_url}/FUZZ -w {wl} -mc 200,201,301,302,403 -t 50 -o {fuzz_file} -of json -s 2>/dev/null")
            if fuzz_file.exists():
                try:
                    hits = json.loads(fuzz_file.read_text()).get("results", [])
                    results["vuln_hints"] += len(hits)
                    log(f"{len(hits)} rutas encontradas con ffuf", "OK")
                    results["files"].append(str(fuzz_file))
                except Exception:
                    pass

    results["files"].append(str(headers_file))
    return results


# ══════════════════════════════════════════════════════════
# MÓDULO 5 — IA
# ══════════════════════════════════════════════════════════

async def ai_call(prompt):
    if not API_KEY:
        return "[Sin API key configurada]"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://reconkit.gh",
        "X-Title": "ReconKit-GH",
    }
    body = {
        "model": "openrouter/free",
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers, json=body,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status != 200:
                    err = await resp.text()
                    return f"[Error {resp.status}]: {err[:200]}"
                data = await resp.json()
                return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[Error]: {e}"


async def run_ai(all_results):
    log("ANÁLISIS IA", "SECTION")
    if not API_KEY:
        log("OPENROUTER_KEY no configurado en Secrets — saltando módulo IA", "WARN")
        return {"ai_report": "⚠ Sin API key configurada. Añade OPENROUTER_KEY en Settings → Secrets."}

    sub   = all_results.get("subdomains", {})
    ports = all_results.get("ports",      {})
    js    = all_results.get("js",         {})
    web   = all_results.get("web",        {})
    report_parts = []

    # Peticiones activas a endpoints
    probe_targets = []
    for f in sub.get("files", []):
        if "alive" in f:
            try:
                for line in Path(f).read_text().splitlines()[:15]:
                    url = line.split()[0] if line.strip() else ""
                    if url.startswith("http"):
                        probe_targets.append(url)
            except Exception:
                pass
    for f in js.get("files", []):
        if "endpoints" in f:
            try:
                for ep in Path(f).read_text().splitlines()[:10]:
                    ep = ep.strip()
                    if ep.startswith("/"):
                        probe_targets.append(f"https://{TARGET}{ep}")
            except Exception:
                pass

    probe_targets = list(dict.fromkeys(probe_targets))
    log(f"Sondeando {len(probe_targets)} targets...")

    responses_data = []
    for url in probe_targets[:20]:
        rc, output = run(f"curl -sk --max-time 10 -L -i -A 'Mozilla/5.0' '{url}'", capture=True)
        if rc == 0 and output:
            parts      = output.split("\r\n\r\n", 1) if "\r\n\r\n" in output else output.split("\n\n", 1)
            headers_r  = parts[0] if parts else ""
            body_r     = parts[1][:600] if len(parts) > 1 else ""
            sm         = re.search(r"HTTP/[\d.]+ (\d+)", headers_r)
            responses_data.append({
                "url": url, "status": sm.group(1) if sm else "?",
                "headers": headers_r[:400], "body": body_r,
            })
            log(f"[{sm.group(1) if sm else '?'}] {url[:70]}")

    # Análisis IA de respuestas
    if responses_data:
        chunk_size = 4
        findings = []
        for i in range(0, len(responses_data), chunk_size):
            chunk = responses_data[i:i+chunk_size]
            text  = ""
            for r in chunk:
                text += f"\n--- {r['url']} [{r['status']}] ---\n"
                text += f"HEADERS:\n{r['headers'][:250]}\nBODY:\n{r['body'][:350]}\n"

            prompt = f"""Eres experto en bug bounty. Analiza estas respuestas HTTP del target '{TARGET}' y detecta vulnerabilidades.

Para cada hallazgo:
HALLAZGO: [nombre]
SEVERIDAD: [CRÍTICO/ALTO/MEDIO/BAJO/INFORMATIVO]
URL: [url]
DESCRIPCIÓN: [qué es]
EVIDENCIA: [fragmento concreto]
RECOMENDACIÓN: [cómo arreglarlo]
---

{text}

Si no hay nada: "Sin hallazgos en este bloque." Sé conciso."""

            log(f"IA analizando bloque {i//chunk_size+1}...")
            result = await ai_call(prompt)
            if "Sin hallazgos" not in result:
                findings.append(result)

        if findings:
            report_parts.append("### 🔎 Hallazgos en respuestas HTTP\n\n" + "\n\n".join(findings))
        else:
            report_parts.append("### 🔎 Respuestas HTTP\n✅ Sin vulnerabilidades evidentes detectadas.")

    # Análisis de secrets
    secret_lines = []
    for f in js.get("files", []):
        if "secrets" in f:
            try:
                secret_lines = Path(f).read_text().splitlines()[:25]
            except Exception:
                pass

    if secret_lines:
        prompt = f"""Clasifica estos posibles secrets de JS del target '{TARGET}':
{chr(10).join(secret_lines)}

Para cada uno:
SECRET: [valor parcial]
TIPO: [tipo]
SEVERIDAD: [CRÍTICO/ALTO/MEDIO/BAJO]
IMPACTO: [qué puede hacer un atacante]
VÁLIDO: [probablemente sí/no/verificar]
---"""
        log("IA clasificando secrets...")
        result = await ai_call(prompt)
        report_parts.append("### 🔑 Clasificación de Secrets\n\n" + result)

    # Superficie de ataque
    context = []
    if sub.get("subdomains_alive", 0): context.append(f"- {sub['subdomains_alive']} subdominios vivos")
    if ports.get("interesting_services"): context.append(f"- Puertos sensibles: {', '.join(ports['interesting_services'])}")
    if js.get("endpoints_found", 0): context.append(f"- {js['endpoints_found']} endpoints JS")
    if js.get("secrets_found", 0): context.append(f"- {js['secrets_found']} posibles secrets")

    if context:
        prompt = f"""Experto en bug bounty. Datos del target '{TARGET}':
{chr(10).join(context)}

1. Evalúa la superficie de ataque (2-3 líneas)
2. Top 5 vectores más prometedores
3. Próximos pasos concretos
4. Puntuación de superficie del 1 al 10

Directo y práctico."""
        log("IA evaluando superficie de ataque...")
        result = await ai_call(prompt)
        report_parts.append("### 📊 Superficie de ataque\n\n" + result)

    ai_report = "\n\n---\n\n".join(report_parts)
    ai_file   = AUDIT_DIR / "AI_REPORT.md"
    ai_file.write_text(f"# 🤖 Informe IA — {TARGET}\n\n" + ai_report)
    log(f"Informe IA guardado: {ai_file}", "OK")
    return {"ai_report": ai_report}


# ══════════════════════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════════════════════

def build_summary(all_results):
    sub   = all_results.get("subdomains", {})
    ports = all_results.get("ports",      {})
    js    = all_results.get("js",         {})
    web   = all_results.get("web",        {})
    ai    = all_results.get("ai",         {})

    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    severity = "🟢 LIMPIO"
    if js.get("secrets_found", 0) > 0:       severity = "🔴 CRÍTICO — secrets expuestos"
    elif ports.get("interesting_services"):   severity = "🟠 ATENCIÓN — servicios sensibles"
    elif web.get("vuln_hints", 0) > 2:        severity = "🟡 REVISAR — headers / rutas"

    def rf(path):
        try: return Path(path).read_text(errors="replace").splitlines()
        except: return []

    alive_lines    = next((rf(f) for f in sub.get("files",[]) if "alive" in f), [])
    port_lines     = next(([l for l in rf(f) if "/tcp" in l] for f in ports.get("files",[]) if f.endswith(".txt")), [])
    secret_lines   = next((rf(f) for f in js.get("files",[]) if "secrets" in f), [])
    endpoint_lines = next((rf(f) for f in js.get("files",[]) if "endpoints" in f), [])
    fuzz_hits      = []
    for f in web.get("files",[]):
        if "fuzz" in f:
            try: fuzz_hits = json.loads(Path(f).read_text()).get("results",[])
            except: pass

    secrets_by_type = {}
    for s in secret_lines:
        m = re.match(r'\[([^\]]+)\]', s)
        label = m.group(1) if m else "Otro"
        secrets_by_type.setdefault(label, []).append(s)

    endpoints_by_cat = {"API":[], "GraphQL":[], "Auth":[], "Otro":[]}
    for ep in endpoint_lines:
        if "/graphql" in ep.lower():                                    endpoints_by_cat["GraphQL"].append(ep)
        elif any(x in ep.lower() for x in ["/api/","/v1/","/v2/"]):   endpoints_by_cat["API"].append(ep)
        elif any(x in ep.lower() for x in ["/auth","/login","/token"]): endpoints_by_cat["Auth"].append(ep)
        else:                                                            endpoints_by_cat["Otro"].append(ep)

    SEP = "\n---\n"
    md  = []
    md.append(f"# 🔍 ReconKit — Auditoría de seguridad")
    md.append(f"> **Target:** `{TARGET}`  \n> **Fecha:** {date_str}  \n> **Run:** [{os.environ.get('GITHUB_RUN_ID','local')}]")
    md.append(SEP)

    md.append(f"## Resumen ejecutivo — {severity}\n")
    md.append("| Módulo | Resultado |")
    md.append("|--------|-----------|")
    md.append(f"| 🌐 Subdominios | {sub.get('subdomains_found',0)} encontrados · {sub.get('subdomains_alive',0)} vivos |")
    md.append(f"| 🔌 Puertos | {ports.get('ports_open',0)} abiertos · sensibles: {', '.join(ports.get('interesting_services',[])) or 'ninguno'} |")
    md.append(f"| ⚡ JS | {js.get('js_files',0)} archivos · {js.get('endpoints_found',0)} endpoints · **{js.get('secrets_found',0)} secrets** |")
    md.append(f"| 🔍 Web | {web.get('vuln_hints',0)} hallazgos |")
    md.append(SEP)

    md.append("## 🌐 Subdominios vivos\n")
    if alive_lines:
        md.append("```"); md.extend(alive_lines[:50]); md.append("```")
    else: md.append("_Sin resultados._")
    md.append(SEP)

    md.append("## 🔌 Puertos abiertos\n")
    interesting_set = {"8080","8443","9200","6379","27017","5432","3306","2375","9000","3000","5000","21","23","25"}
    if port_lines:
        md.append("```")
        for l in port_lines:
            pn = re.match(r"(\d+)/", l)
            md.append(f"{'  ⚠' if pn and pn.group(1) in interesting_set else '   '}  {l}")
        md.append("```")
    else: md.append("_Sin resultados._")
    md.append(SEP)

    md.append("## ⚡ JavaScript — Secrets\n")
    if secrets_by_type:
        for stype, items in secrets_by_type.items():
            icon = "🔴" if stype in ("AWS Access Key","AWS Secret Key","GitHub Token") else "🟠"
            md.append(f"### {icon} {stype} ({len(items)})\n```")
            md.extend(i[:120] for i in items[:10])
            md.append("```\n")
    else: md.append("✅ Sin secrets detectados.\n")
    md.append(SEP)

    md.append("## ⚡ JavaScript — Endpoints\n")
    for cat, eps in endpoints_by_cat.items():
        if eps:
            md.append(f"### {cat} ({len(eps)})\n```")
            md.extend(sorted(eps)[:30]); md.append("```\n")
    if not any(endpoints_by_cat.values()): md.append("_Sin endpoints._\n")
    md.append(SEP)

    md.append("## 🔍 Web — Rutas (ffuf)\n")
    if fuzz_hits:
        md.append("| Código | URL | Bytes |")
        md.append("|--------|-----|-------|")
        for h in fuzz_hits[:40]:
            md.append(f"| `{h.get('status','-')}` | `{h.get('url','')}` | {h.get('length','-')} |")
    else: md.append("_Sin resultados._")
    md.append(SEP)

    if ai.get("ai_report"):
        md.append("## 🤖 Análisis IA\n")
        md.append(ai["ai_report"])
        md.append(SEP)

    summary_file = AUDIT_DIR / "SUMMARY.md"
    summary_file.write_text("\n".join(md))
    log(f"SUMMARY.md guardado: {summary_file}", "OK")

    # JSON para la web
    json_file = AUDIT_DIR / "results.json"
    json_file.write_text(json.dumps({
        "target": TARGET, "date": date_str, "severity": severity,
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "repo":   os.environ.get("GITHUB_REPOSITORY", ""),
        "subdomains_found":    sub.get("subdomains_found", 0),
        "subdomains_alive":    sub.get("subdomains_alive", 0),
        "ports_open":          ports.get("ports_open", 0),
        "interesting_services":ports.get("interesting_services", []),
        "js_files":            js.get("js_files", 0),
        "secrets_found":       js.get("secrets_found", 0),
        "endpoints_found":     js.get("endpoints_found", 0),
        "vuln_hints":          web.get("vuln_hints", 0),
        "alive_lines":         alive_lines[:30],
        "port_lines":          port_lines[:30],
        "secrets_by_type":     {k: v[:5] for k, v in secrets_by_type.items()},
        "endpoints_by_cat":    {k: v[:20] for k, v in endpoints_by_cat.items()},
        "fuzz_hits":           [{"status": h.get("status"), "url": h.get("url"), "length": h.get("length")} for h in fuzz_hits[:40]],
        "ai_report":           ai.get("ai_report", ""),
    }, indent=2))

    return str(json_file)


# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════

async def main():
    log(f"══ ReconKit — GitHub Actions ══")
    log(f"Target:  {TARGET}")
    log(f"Módulos: {', '.join(MODULES)}")
    log(f"Nmap:    {PORT_MODE}")

    all_results = {}

    if "subdomains" in MODULES:
        all_results["subdomains"] = await run_subdomains()
    if "ports" in MODULES:
        all_results["ports"] = run_ports()
    if "js" in MODULES:
        all_results["js"] = run_js()
    if "web" in MODULES:
        all_results["web"] = run_web()
    if "ai" in MODULES:
        all_results["ai"] = await run_ai(all_results)

    json_path = build_summary(all_results)

    # Guardar path del JSON para build_web.py
    Path("audits/latest.txt").write_text(json_path)
    log(f"✔ Scan completado → {AUDIT_DIR}", "OK")


if __name__ == "__main__":
    asyncio.run(main())
