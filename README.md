<div align="center">

<img src="icons/icon128.png" alt="PhishGuard Logo" width="96" height="96"/>

# PhishGuard

### Browser Threat Detection Extension

**Real-time phishing and malware detection powered by heuristic analysis and live threat-intelligence APIs.**

[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?style=flat-square&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/)
[![Chrome](https://img.shields.io/badge/Chrome-102+-yellow?style=flat-square&logo=googlechrome&logoColor=white)](https://www.google.com/chrome/)
[![Brave](https://img.shields.io/badge/Brave-Compatible-orange?style=flat-square&logo=brave&logoColor=white)](https://brave.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-cyan?style=flat-square)]()
[![Phase](https://img.shields.io/badge/Phase-2-purple?style=flat-square)]()

---

*Scan any website in one click. Get a full VirusTotal-style security report in seconds.*

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Detection Engine](#-detection-engine)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Permissions](#-permissions)
- [Installation](#-installation)
- [API Key Setup](#-api-key-setup)
- [How It Works](#-how-it-works)
- [Threat APIs](#-threat-apis)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🛡️ Overview

**PhishGuard** is a lightweight, privacy-respecting Chrome/Chromium browser extension that analyses any website you visit for phishing attempts, malware distribution, and social engineering attacks — all in real time.

Unlike browser-native warnings that only trigger on known bad URLs, PhishGuard layers **local heuristic intelligence** on top of **three live threat databases**, giving you proactive protection even against newly registered phishing domains that haven't yet been added to global blocklists.

> **No data is collected. No telemetry is sent. All heuristic analysis runs 100% locally in your browser.**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **One-click scanning** | Scan the current page instantly from the toolbar popup |
| 🧠 **15-point URL heuristic engine** | Local analysis — no network required |
| 🌐 **Live DOM page analysis** | Injected into the real page via Chrome Scripting API |
| 🗄️ **URLhaus lookup** | Cross-checks against Abuse.ch's malware URL database (no key needed) |
| 🎣 **PhishTank lookup** | Checks against OpenDNS's verified phishing database |
| 🔒 **Google Safe Browsing** | Queries Google's real-time threat intelligence API |
| 📊 **0–100 Risk Score** | Weighted score combining all five detection layers |
| 📋 **Full VirusTotal-style Report** | Detailed breakdown in a separate full-page report |
| 🔑 **API key manager** | Securely store your free API keys inside the extension |
| 🎨 **Dark cybersecurity UI** | Clean, professional dark-mode interface |

---

## 🔬 Detection Engine

PhishGuard uses a **five-layer detection pipeline**. All five checks run simultaneously in parallel.

```
User clicks "Scan Now"
         │
         ├─── Layer 1: URL Heuristics (local, ~0ms)
         │      15 checks including:
         │      • HTTPS / HTTP
         │      • IP-as-hostname detection
         │      • Punycode / IDN homograph attacks
         │      • Suspicious TLDs (.tk .ml .xyz .top …)
         │      • Phishing keyword detection in domain
         │      • Brand typosquatting (Google, PayPal, Microsoft …)
         │      • Brand-in-subdomain impersonation
         │      • Open redirect parameters
         │      • Non-standard ports
         │      • Double-slash obfuscation
         │      • @ symbol in URL
         │      • Excessive subdomains
         │      • Digit substitution in domain
         │      • URL length anomaly
         │      • Known phishing patterns
         │
         ├─── Layer 2: Page DOM Analysis (chrome.scripting injection)
         │      • Hidden iframe detection
         │      • Link-text vs href mismatch
         │      • Meta-refresh redirect tags
         │      • External script count
         │      • Favicon domain spoofing
         │      • Password / login form signals
         │      • External link ratio
         │      • Body onload with forms
         │
         ├─── Layer 3: URLhaus API (Abuse.ch)
         │      Real-time malware URL database — no API key required
         │
         ├─── Layer 4: PhishTank API (OpenDNS)
         │      Crowdsourced, human-verified phishing URL database
         │
         └─── Layer 5: Google Safe Browsing API
                MALWARE · SOCIAL_ENGINEERING · UNWANTED_SOFTWARE
                         │
                         ▼
              Combined Score (0–100)
              URL × 0.6 + Content × 0.4 + API result weight
                         │
              ┌──────────┼──────────┐
           0–25        26–55      56–100
          ✅ Safe    ⚠️ Warning  🔴 Danger
```

### Score Weighting

| Source | Weight |
|---|---|
| URL Heuristics | 36% |
| Page Content   | 24% |
| API Results    | 40% |

> **Note:** A confirmed API threat (URLhaus / PhishTank / Safe Browsing) raises the minimum score to **65**, ensuring no confirmed threat is under-reported.

---

## 📁 Project Structure

```
PhishGuard/
│
├── manifest.json              # Extension manifest (Manifest V3)
│
├── popup/
│   ├── popup.html             # Extension toolbar popup UI
│   ├── popup.css              # Dark cybersecurity stylesheet
│   └── popup.js               # 5-layer scan engine + UI logic
│
├── report/
│   ├── report.html            # Full VirusTotal-style report page
│   ├── report.css             # Premium report stylesheet
│   └── report.js              # Report renderer + API key manager
│
├── icons/
│   ├── icon16.png             # 16×16 toolbar icon
│   ├── icon48.png             # 48×48 extensions page icon
│   ├── icon128.png            # 128×128 store / install icon
│   └── README.md              # Icon guidelines
│
└── README.md                  # This file
```

---

## 🛠️ Tech Stack

| Technology | Role |
|---|---|
| **Manifest V3** | Chrome extension API standard |
| **HTML5** | Semantic popup and report page structure |
| **Vanilla CSS** | Dark theme, animations, responsive layout |
| **Vanilla JavaScript (ES2020+)** | Detection logic, Chrome API calls |
| **`chrome.tabs`** | Reads the active tab URL |
| **`chrome.scripting`** | Injects DOM analyzer into live pages |
| **`chrome.storage.session`** | Stores scan report for the report page |
| **`chrome.storage.sync`** | Persists API keys across devices |
| **`Promise.allSettled`** | Runs all 5 detection layers in parallel |
| **URLhaus REST API** | Malware URL database (Abuse.ch) |
| **PhishTank REST API** | Phishing URL database (OpenDNS) |
| **Google Safe Browsing v4** | Broad threat intelligence (Google) |

**Zero third-party libraries or frameworks.** Pure browser APIs only.

---

## 🔐 Permissions

PhishGuard requests only the minimum permissions required.

| Permission | Why it's needed |
|---|---|
| `activeTab` | Reads the current tab's URL when the popup is opened |
| `scripting` | Injects the DOM content analyser into the active page |
| `storage` | Stores API keys (`sync`) and scan reports (`session`) |
| `https://urlhaus-api.abuse.ch/*` | Allows fetch to URLhaus API |
| `https://checkurl.phishtank.com/*` | Allows fetch to PhishTank API |
| `https://safebrowsing.googleapis.com/*` | Allows fetch to Safe Browsing API |

> No `<all_urls>` host permission. No background service worker. No persistent access to your browsing history.

---

## 🚀 Installation

### Load as Unpacked Extension (Developer Mode)

> **Requirements:** Google Chrome 102+, Brave, or any Chromium-based browser.

**Step 1 — Download the source**

```bash
git clone https://github.com/Hareesh0x01/PhishGuard.git
```

Or download and extract the ZIP from the [Releases](../../releases) page.

**Step 2 — Open the Extensions page**

| Browser | URL |
|---|---|
| Chrome | `chrome://extensions` |
| Brave  | `brave://extensions` |
| Edge   | `edge://extensions` |

**Step 3 — Enable Developer Mode**

Toggle the **Developer mode** switch in the **top-right corner**.

**Step 4 — Load the extension**

1. Click **"Load unpacked"**
2. Select the **`PhishGuard/`** folder (the one containing `manifest.json`)
3. Click **"Select Folder"**

**Step 5 — Pin to toolbar (recommended)**

1. Click the 🧩 puzzle icon in the Chrome toolbar
2. Find **PhishGuard**
3. Click the 📌 pin icon

---

## 🔑 API Key Setup

PhishGuard works **immediately without any API keys** — URLhaus and the heuristic engine require no registration.

To unlock the full three-engine scan, add your free API keys from the **Full Report page → API Key Configuration** section.

### PhishTank (Free)

1. Visit [phishtank.com/api_register.php](https://www.phishtank.com/api_register.php)
2. Create a free account
3. Copy your API key
4. Open PhishGuard → Scan a site → **View Full Report** → paste key under *PhishTank*

### Google Safe Browsing (Free)

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or use an existing one)
3. Enable the **Safe Browsing API**
4. Go to **Credentials** → **Create API Key**
5. (Optional) Restrict the key to the Safe Browsing API
6. Open PhishGuard → Scan a site → **View Full Report** → paste key under *Safe Browsing*

> **Free tier:** Safe Browsing allows up to **10,000 requests/day** at no cost. PhishTank has no stated rate limit for normal usage.

---

## ⚙️ How It Works

### Popup Flow

```
1. User opens popup       → displays current tab hostname
2. User clicks "Scan Now" → all 5 layers fire simultaneously
3. Results arrive         → risk score calculated, engine chips update
4. "View Full Report"     → opens report.html in a new tab
                             (data passed via chrome.storage.session)
```

### Report Page

The report page reads from `chrome.storage.session` (per-session, auto-cleared when browser closes) and renders:

- **Verdict banner** — coloured by risk level with glow effect
- **URL metadata** — full URL, hostname, scan timestamp
- **Animated risk bar** — gradient from green → yellow → red
- **4 engine result cards** — URLhaus · PhishTank · Safe Browsing · Heuristic
- **URL findings table** — all 15 heuristic checks with severity badges
- **Page content signals** — 8 DOM metric cards + detailed findings
- **API key configuration** — save keys to `chrome.storage.sync`

---

## 🌐 Threat APIs

| API | Provider | Key Required | Database Size | Detects |
|---|---|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) | Abuse.ch | ❌ No | 1M+ URLs | Malware distribution |
| [PhishTank](https://www.phishtank.com/) | OpenDNS / Cisco | ✅ Free | 1M+ URLs | Phishing (human-verified) |
| [Safe Browsing v4](https://developers.google.com/safe-browsing) | Google | ✅ Free | Billions of URLs | Malware, phishing, social engineering |

---

## 🗺️ Roadmap

| Phase | Status | Description |
|---|---|---|
| **Phase 1** | ✅ Complete | Project structure, UI shell, Chrome API wiring |
| **Phase 2** | ✅ Complete | URL heuristics, DOM analysis, URLhaus + PhishTank + Safe Browsing integration, full report page |
| **Phase 3** | 🔜 Planned | Domain age & WHOIS lookup, SSL certificate analysis |
| **Phase 4** | 🔜 Planned | Scan history log with local persistence |
| **Phase 5** | 🔜 Planned | ML-based risk scoring (TensorFlow.js) |
| **Phase 6** | 🔜 Planned | Browser notifications for auto-detected threats |
| **Phase 7** | 🔜 Planned | Settings page, whitelist/blacklist management |
| **Phase 8** | 🔜 Planned | Chrome Web Store publication |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature-name`
3. **Commit** your changes with clear, descriptive messages
4. **Test** the extension by loading it unpacked in Chrome
5. **Open** a Pull Request with a description of what you changed and why

### Development Guidelines

- Keep the extension zero-dependency (no npm, no bundler)
- Every new detection check should be documented with a comment
- New API integrations must degrade gracefully when the key is missing
- Follow the existing code style (ESLint-compatible vanilla JS)

---

## 🐛 Known Issues

- **PhishTank CORS**: Some network configurations may block the PhishTank API request. The extension handles this gracefully and reports an error in the engine card.
- **chrome:// pages**: Browser internal pages cannot be scanned (restricted by Chrome's API).
- **Iframes on sandboxed pages**: Content injection is blocked on some CSP-strict pages; the extension falls back to URL-only analysis.

---

## 📄 License

```
MIT License

Copyright (c) 2026 PhishGuard Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

<div align="center">

**Built with ❤️ for a safer web**

[⭐ Star this repo](../../stargazers) · [🐛 Report a bug](../../issues/new) · [💡 Request a feature](../../issues/new)

</div>
