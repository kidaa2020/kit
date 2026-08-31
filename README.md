# 🔍 ReconKit — GitHub Actions Edition

Herramienta de bug bounty que corre **completamente en GitHub Actions** y publica los resultados en **GitHub Pages**. Sin servidor, sin VM, gratis.

---

## ⚡ Setup en 5 minutos

### 1. Crear el repositorio

```bash
# Crear repo privado en GitHub y clonarlo
git clone https://github.com/TU_USUARIO/reconkit-gh
cd reconkit-gh
```

### 2. Copiar los archivos

```
reconkit-gh/
├── .github/
│   └── workflows/
│       └── recon.yml
├── scripts/
│   ├── recon.py
│   └── build_web.py
├── web/
│   └── (vacío, lo genera automáticamente)
└── README.md
```

### 3. Añadir el Secret de OpenRouter

1. Ve a tu repo → **Settings → Secrets and variables → Actions**
2. Pulsa **"New repository secret"**
3. Nombre: `OPENROUTER_KEY`
4. Valor: tu API key de OpenRouter (`sk-or-v1-...`)
5. Pulsa **"Add secret"**

### 4. Activar GitHub Pages

1. Ve a **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: **gh-pages** / **/ (root)**
4. Pulsa **Save**

> ⚠️ La rama `gh-pages` se crea automáticamente en el primer scan.

### 5. Hacer push del código

```bash
git add .
git commit -m "🚀 ReconKit setup"
git push
```

---

## 🚀 Lanzar un scan

### Desde el móvil o navegador

1. Ve a tu repo → **Actions**
2. Selecciona **"🔍 ReconKit — Bug Bounty Scan"**
3. Pulsa **"Run workflow"**
4. Rellena los campos:
   - **Target**: `ejemplo.com`
   - **Módulos**: `subdomains,ports,js,web,ai`
   - **Modo nmap**: `fast`
5. Pulsa **"Run workflow"** verde

### Ver resultados

- **En tiempo real**: pestaña Actions → tu workflow en ejecución → logs
- **Web de resultados**: `https://TU_USUARIO.github.io/reconkit-gh`
- **Archivos completos**: Actions → tu run → sección Artifacts → descargar ZIP

---

## 📦 Módulos disponibles

| Módulo | Herramientas | Qué hace |
|--------|-------------|----------|
| `subdomains` | subfinder, assetfinder, crt.sh, httpx | Enumeración y filtrado de subdominios vivos |
| `ports` | nmap | Escaneo de puertos con perfil configurable |
| `js` | gau, katana, curl, nuclei | Descarga y análisis de JS — secrets y endpoints |
| `web` | ffuf, whatweb, curl | Headers, tecnologías, fuzzing de directorios |
| `ai` | OpenRouter (openrouter/free) | Análisis inteligente de respuestas y hallazgos |

Puedes activar solo los que quieras separados por coma:
```
subdomains,js,ai
```

---

## 🔌 Modos de escaneo nmap

| Modo | Comando | Velocidad |
|------|---------|-----------|
| `fast` | `-T4 -F --open` | ~1 min — top 100 puertos |
| `full` | `-T4 -p- --open -sV` | ~20 min — todos los puertos |
| `stealth` | `-sS -T2 --open` | ~15 min — sigiloso |
| `services` | `-T4 -p- -sV -sC` | ~30 min — detección completa |

---

## 📁 Estructura de resultados

Cada scan guarda todo en `audits/TARGET/FECHA/`:

```
audits/
└── ejemplo.com/
    └── 2026-08-30_14-32/
        ├── SUMMARY.md          ← Informe completo para write-up
        ├── AI_REPORT.md        ← Análisis de IA
        ├── results.json        ← Datos para la web
        ├── scan.log            ← Log completo de ejecución
        ├── subdomains_raw.txt
        ├── subdomains_alive.txt
        ├── ports.txt
        ├── ports.xml
        ├── js_urls.txt
        ├── js_files/           ← JS descargados
        ├── secrets.txt
        ├── endpoints.txt
        ├── technologies.txt
        ├── headers.txt
        ├── fuzz_results.txt
        └── nuclei_js.txt
```

---

## ⏱️ Tiempos estimados por módulo

| Módulo | Tiempo aprox. |
|--------|--------------|
| subdomains | 2–5 min |
| ports (fast) | 1–2 min |
| ports (full) | 15–30 min |
| js | 3–8 min |
| web | 3–6 min |
| ai | 2–5 min |
| **Total típico** | **~15 min** |

---

## 🔐 Seguridad

- El repo es **privado** → nadie ve tus targets ni resultados
- La API key va en **Secrets** → nunca aparece en los logs
- GitHub Pages del repo privado solo es accesible para ti (con cuenta de GitHub)
- Los artifacts se eliminan automáticamente a los **30 días**

---

## 💡 Tips

**Ver el scan en tiempo real desde el móvil:**
1. App GitHub → tu repo → Actions → workflow en ejecución
2. Toca el job → verás los logs en directo

**Descargar todos los archivos del scan:**
1. Actions → tu run completado
2. Scroll abajo → sección "Artifacts"
3. Descarga el ZIP con todo

**Usar solo IA sobre un target ya escaneado:**
- Pon módulos: `ai` (sin los demás)
- Será muy rápido porque no hace recon, solo análisis

**Límites de GitHub Actions (plan gratuito):**
- 2.000 minutos/mes en repos privados
- Un scan completo consume ~15-20 min → tienes para ~100 scans/mes
