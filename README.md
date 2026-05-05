```
  ████   █████  ████████ ██   ██
 ██  ██ ██   ██ ██       ██   ██
 ██  ██ ██   ██ ██        ██ ██
 ██████ ██   ██ ██████     ███
 ██  ██ ██   ██ ██        ██ ██
 ██  ██ ██   ██ ██       ██   ██
 ██  ██ █████   ████████ ██   ██
```

> **Active Directory Security Auditor** — Pentest & SOC teams

ADEX is a modular, terminal-driven Active Directory security audit tool. It collects raw LDAP data, analyzes it for misconfigurations and common attack vectors, scores findings by severity, and presents everything in an interactive web dashboard.

---

## Features

- **LDAP Collection** — Connects to a Domain Controller and enumerates users, groups, GPOs, password policies, delegation settings, and more
- **Security Analysis** — Detects 11+ attack surface categories including Kerberoasting, AS-REP Roasting, unconstrained delegation, AdminSDHolder misuse, LAPS coverage gaps, stale accounts, and SMB signing issues
- **Risk Scoring** — Each finding is scored Critical / High / Medium / Low based on a weighted severity matrix
- **Remediation Guidance** — Every finding ships with actionable remediation steps pulled from a local knowledge base
- **Web Dashboard** — Single-file HTML dashboard that loads a JSON report and visualises findings with filtering and detail panels
- **Single Binary CLI** — One executable (`adex-cli`) drives the entire workflow from an interactive terminal menu

---

## Architecture

```
adex-cli  (adex/main.go)
    │
    ├── [1] Scan ──────► collector/   (LDAP enumeration)
    │                        ├── modules/users.go
    │                        ├── modules/kerberoast.go
    │                        ├── modules/asrep.go
    │                        ├── modules/delegation.go
    │                        ├── modules/adminsdholder.go
    │                        ├── modules/gpo.go
    │                        ├── modules/group.go
    │                        ├── modules/laps.go
    │                        ├── modules/pwdpolicy.go
    │                        ├── modules/signing.go
    │                        └── modules/stale.go
    │                        └── ► adex_raw.json
    │
    ├── [2] Analyze ───► analyzer/   (scoring + remediation)
    │                        ├── parser/
    │                        ├── scoring/matrix.go
    │                        └── remediation/
    │                        └── ► adex_report.json
    │
    └── [3] Report ────► web/dist/index.html  (browser dashboard)
```

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Go   | 1.21+   |
| Node | 18+     |
| npm  | 9+      |

Network access to a Domain Controller on port **389** (LDAP) or **636** (LDAPS).

---

### 1. Clone

```bash
git clone https://github.com/<your-username>/adex.git
cd adex
```

### 2. Build all binaries

```bash
# Collector
cd collector && go build -o collector . && cd ..

# Analyzer
cd analyzer  && go build -o analyzer  . && cd ..

# CLI launcher
cd adex      && go build -o ../adex-cli . && cd ..
```

### 3. Build the web dashboard

```bash
cd web
npm install
npm run build   # outputs web/dist/index.html
cd ..
```

### 4. Run

```bash
./adex-cli
```

You will see the interactive menu:

```
  [1] Scan    - Scan Active Directory
  [2] Analyze - Analyze raw JSON.
  [3] Report  - Open dashboard in browser.
  [4] Exit
```

---

## Workflow

### Step 1 — Scan

Select **[1]** and provide:

| Prompt | Example |
|--------|---------|
| DC IP or Hostname | `192.168.1.10` |
| Domain | `company.local` |
| Username | `Administrator@company.local` |
| Password | *(masked input)* |
| Port | `389` (default) |
| Output file | `adex_raw.json` (default) |

The collector connects over LDAP, runs all enumeration modules, and writes raw results to JSON.

### Step 2 — Analyze

Select **[2]** and point it at the raw JSON. The analyzer:

1. Parses each LDAP object
2. Runs it through the scoring matrix (`Critical / High / Medium / Low`)
3. Attaches remediation steps from the local knowledge base
4. Outputs `adex_report.json`

### Step 3 — Report

Select **[3]** to open the dashboard in your default browser. The dashboard lets you:

- Filter findings by severity
- Expand any finding for full details and remediation guidance
- Load a new report via drag & drop

---

## Detection Modules

| Module | What it checks |
|--------|----------------|
| `kerberoast` | Service accounts with SPNs (Kerberoastable) |
| `asrep` | Accounts with pre-auth disabled (AS-REP Roastable) |
| `delegation` | Unconstrained & constrained delegation |
| `adminsdholder` | AdminSDHolder ACL misconfigurations |
| `gpo` | Dangerous GPO settings |
| `group` | Privileged group membership anomalies |
| `laps` | Machines without LAPS coverage |
| `pwdpolicy` | Weak or missing password policies |
| `signing` | SMB signing not enforced |
| `stale` | Inactive / stale user and computer accounts |
| `users` | Sensitive user attribute misconfigurations |

---

## Project Layout

```
adex/
├── adex/           # CLI launcher (interactive menu)
├── collector/      # LDAP data collection
│   ├── ldap/       # LDAP connection helpers
│   ├── modules/    # Per-check enumeration modules
│   ├── config/     # Runtime configuration
│   └── output/     # JSON serialisation
├── analyzer/       # Risk scoring & remediation mapping
│   ├── parser/     # Raw JSON ingestion
│   ├── scoring/    # Severity matrix
│   └── remediation/# Remediation step lookup
├── remediation/    # Remediation knowledge base (db.json)
├── web/            # React + Vite dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   └── dist/       # Built dashboard (single HTML file)
└── adex-cli        # Compiled launcher binary
```

---

## License

MIT — see [LICENSE](LICENSE)
