---
tags: [offensive-security, mobile-security, pwa-security, service-worker, web-security, static-analysis, dynamic-analysis]
category: "Mobile Security"
difficulty: "Intermediate"
real_world_problem: "Progressive Web Apps (PWAs) combine web technologies with native mobile capabilities, exposing devices to unique threats like service worker poisoning, manifest spoofing, and storage exposure."
tools: [Lighthouse, Playwright, Python, Burp Suite, Chrome DevTools Protocol]
estimated_duration: "4 weeks"
---

# 🎯 Progressive Web App (PWA) Security Testing Suite
> **Category**: [[Mobile Security]] | **Difficulty**: ⭐⭐ | **Duration**: 4 weeks

---

## 📋 Problem Statement

> [!CAUTION] Real-World Impact
> Progressive Web Apps (PWAs) leverage modern web APIs (Service Workers, Web App Manifests, IndexedDB, Web Bluetooth/NFC) to deliver native-like mobile experiences directly through web browsers. Misconfigured PWA Service Workers or permissive manifest declarations allow cross-site scripting (XSS) to permanently hijack offline functionality, poison local caches, exfiltrate sensitive local storage data, and execute privileged hardware APIs.

Unlike traditional native mobile apps subject to app store review policies, PWAs bypass distribution gates and install directly from web browsers. However, their security relies on the web origin model and Service Worker lifecycle controls. If a Service Worker script is vulnerable to XSS or lacks strict cache-busting headers, an attacker can execute a Service Worker Poisoning attack, silently intercepting all offline network requests, serving malicious fake login overlays, and exfiltrating tokens stored in IndexedDB or CacheStorage. Furthermore, insecure Web App Manifest declarations can lead to app scope hijacking and unauthorized OAuth origin grants. A Progressive Web App Security Testing Suite provides automated security auditing tailored to the unique hybrid attack surface of PWAs.

### 🌍 Real-World Incidents
- **E-Commerce PWA Cache Poisoning (2023)**: Attackers exploited a DOM XSS flaw in a major retailer's PWA to overwrite the cached Service Worker script, injecting persistent credit card skimming scripts that survived page reloads and cache clears.
- **Enterprise PWA Scope Hijacking (2024)**: Insecure `scope` parameters in a Web App Manifest allowed an attacker hosted on a shared subdomain to inherit PWA installation privileges, stealing user session tokens from IndexedDB.

---

## 🔬 Research Paper References

| # | Paper Title | Authors | Year | Source | Key Contribution |
|---|-------------|---------|------|--------|-----------------|
| 1 | Security and Privacy Vulnerabilities in Progressive Web Applications | Overdorf et al. | 2023 | USENIX Security | Comprehensive taxonomy of Service Worker poisoning, origin isolation flaws, and Web App Manifest security risks. |
| 2 | Automated Discovery of Service Worker Hijacking and Cache Poisoning in PWAs | Calzavara et al. | 2024 | ACM CCS | Formulated dynamic browser instrumentation models to detect persistent script injection inside PWA CacheStorage. |
| 3 | Evaluating Storage Security and API Permission Models in Modern PWAs | Johns et al. | 2024 | IEEE S&P | Analyzed IndexedDB and local storage encryption practices across 10,000 top installed PWA applications. |

---

## 🏗️ System Architecture
Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project 102: 102 - Progressive Web App (PWA) Security Testing Suite|Excalidraw Architecture Diagram]]


```mermaid
graph TD
    subgraph PWA Target Ingestion
        A[PWA Target URL] --> B[Web App Manifest Parser]
        A --> C[Service Worker Script Downloader]
        A --> D[Browser Storage Inspector]
    end

    subgraph Static Configuration Auditor
        B --> E[Scope & Start URL Security Checker]
        B --> F[Display & Permission Auditor]
        C --> G[Service Worker Cache Poisoning Analyzer]
        C --> H[Fetch Event Interception Auditor]
    end

    subgraph Dynamic Browser Sandbox (Playwright)
        D --> I[IndexedDB / CacheStorage Cleartext Scanner]
        A --> J[Cross-Site Scripting (XSS) Fuzzer]
        J --> K[Service Worker Overwrite Verifier]
        A --> L[HTTPS & CSP Security Inspector]
    end

    subgraph Audit Aggregation & Output
        E --> M[PWA Security Scoring Engine]
        F --> M
        G --> M
        H --> M
        I --> M
        K --> M
        L --> M
        M --> N[HTML Security Assessment Report]
        M --> O[Developer Hardening Playbook]
    end
```

---

## 📐 Technical Implementation

### Phase 1: Research & Environment Setup (Week 1)
- Install Python 3.10+, Node.js, `Playwright`, `Lighthouse CLI`, `mitmproxy`, and `Burp Suite`.
- Study PWA architecture: Service Worker lifecycle (`install`, `activate`, `fetch`), Web App Manifest specifications (`manifest.json`), CacheStorage API, and Web Push notifications.
- Set up target vulnerable PWA environments (e.g., OWASP Juice Shop PWA, custom vulnerable Service Worker apps).

### Phase 2: Core Module Development (Weeks 2–3)
- **Web App Manifest Security Auditor**:
  - Download and parse `manifest.json`.
  - Validate `scope` boundaries to prevent scope hijacking by cross-origin subdomains.
  - Audit `start_url` and `theme_color` parameter sanitation.
  - Inspect requested Web Permissions (`geolocation`, `notifications`, `camera`).
- **Service Worker Poisoning & Cache Inspector**:
  - Download Service Worker JavaScript source code using Playwright.
  - Search for unsafe `importScripts()`, `eval()`, or dynamic `fetch()` handling without origin validation.
  - Verify if `Cache-Control: no-cache` headers are set on `sw.js` to ensure immediate browser updates.
- **Dynamic Storage & XSS Scanner**:
  - Launch Playwright headless browser instance to simulate user interaction and PWA installation.
  - Audit `IndexedDB`, `localStorage`, and `CacheStorage` for unencrypted JWTs, session cookies, and PII.
  - Inject XSS test vectors into dynamic PWA routes to verify if XSS can gain access to `navigator.serviceWorker`.

### Phase 3: Integration & Testing (Week 4)
- Combine manifest analyzer, service worker checker, and Playwright storage scanner into an automated testing runner (`pwa_security_suite.py`).
- Run security test suite against popular public PWA applications.
- Benchmark scanning accuracy and execution time.

### Phase 4: Analysis & Documentation (Week 5)
- Design an HTML report format displaying PWA risk grades, Service Worker security metrics, storage exposure findings, and Content Security Policy (CSP) headers.
- Publish a PWA Developer Security Baseline Guide covering Service Worker integrity, storage encryption, and scope isolation.

---

## 🔧 Tools & Technologies

| Tool | Purpose | Alternative |
|------|---------|-------------|
| **Playwright** | Headless browser automation for dynamic PWA testing | Puppeteer / Selenium |
| **Lighthouse CLI** | Audit PWA compliance and baseline performance | WebPageTest |
| **Python** | Test suite orchestration, parsing, and report generation | JavaScript / Node.js |
| **Burp Suite** | Manual proxy inspection of Service Worker network traffic | Mitmproxy |
| **Chrome DevTools Protocol** | Direct inspection of Service Workers and browser storage | Firefox Debugger API |

---

## 💡 Key Features

- ✅ **Automated Web App Manifest Audit**: Flags scope hijacking vectors, insecure start URLs, and excessive permission requests.
- ✅ **Service Worker Poisoning Scanner**: Detects unsafe script imports, unvalidated fetch handlers, and missing cache-control headers.
- ✅ **Browser Storage Cleartext Inspector**: Scans IndexedDB, CacheStorage, and localStorage for exposed session tokens and PII.
- ✅ **Dynamic XSS & Cache Injection Verifier**: Simulates dynamic XSS payloads to test Service Worker registration hijacking defenses.
- ✅ **Comprehensive HTML Reporting**: Generates developer-ready audit scorecards with CSP header recommendations.

---

## 📊 Expected Results

> [!NOTE] Deliverables
> An automated security assessment suite tailored specifically for Progressive Web Apps, delivering deep inspection of Service Workers, storage mechanisms, and Web App Manifests.

### Performance Metrics
- **Assessment Speed**: Full automated PWA security scan completed in < 30 seconds per URL.
- **Coverage**: Audits 100% of PWA web manifests, Service Worker scripts, and browser storage spaces.
- **False Positive Rate**: < 5% on standard web storage and header evaluations.

### Output Artifacts
1. PWA Security Testing Suite CLI tool (`pwa_security_tester.py`).
2. Playwright headless storage scanner module (`storage_inspector.js`).
3. Executive PWA Security Audit Report template (`pwa_audit_report.html`).

---

## 🎓 Learning Outcomes

1. 📚 Master Progressive Web App (PWA) architecture, Service Worker lifecycles, and Web App Manifest specifications.
2. 📚 Identify unique PWA threat vectors, including Service Worker poisoning, cache manipulation, and scope hijacking.
3. 📚 Develop automated browser security testing tools using `Playwright` and `Python`.
4. 📚 Acquire practical experience auditing HTML5 client-side storage mechanisms (`IndexedDB`, `CacheStorage`).

---

## ⚠️ Ethical Considerations

> [!WARNING] Legal & Ethical Notice
> Automated scanning and XSS fuzzing must only be conducted against PWAs you own or have explicit authorization to test. Scanning external web applications without consent may violate computer misuse regulations and terms of service.

---

## 🔗 Related Projects

- [[095 - Mobile App API Traffic Interception Framework]]
- [[097 - Mobile Banking App Security Assessment Tool]]
- [[101 - Mobile App Repackaging & Tamper Detection]]

---
*📅 Created: 2026-07-30 | 🏷️ Category: Mobile Security | 🔐 Offensive Security Research*
