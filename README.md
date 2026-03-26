# Ghostflow 👻

[![Visual Studio Marketplace](https://img.shields.io/visual-studio-marketplace/v/cchoiyon.ghostflow?style=flat-square&color=007acc&label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=cchoiyon.ghostflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/cchoiyon/Ghostflow/ci.yml?style=flat-square&label=Build)](https://github.com/cchoiyon/Ghostflow/actions)
[![VS Code Compatibility](https://img.shields.io/badge/VS%20Code-1.80+-blue?style=flat-square&logo=visual-studio-code)](https://code.visualstudio.com/)

> **Security architecture is not a checkbox; it's a map. Let's draw it.**

Ghostflow is a developer-native VS Code extension that brings security architecture out of the shadows. It automatically scans your TypeScript/JavaScript codebase, identifies trust boundaries, and renders a live, interactive **Data Flow Diagram (DFD)**—enabling you to see exactly how sensitive data moves through your system before it ever hits production.

---

## 🛡️ Why Ghostflow?

Security analysis is often disconnected from the code authoring process. Ghostflow bridges that gap by providing **instant, visual security feedback** directly in the IDE.

- **🚀 Vibe with Confidence** — Built for the era of AI-first development. When you're moving fast and leveraging AI to generate logic, Ghostflow provides the visual safety net you need to ensure your "vibes" haven't accidentally bypassed your trust boundaries.
- **Stop Data Leaks Early** — See "Sensitive Sources" (API keys, PII) flowing toward "Dangerous Sinks" in real-time.
- **Understand Trust Boundaries** — Visual boundaries show you exactly where data transitions between local files, third-party SDKs, and the network.
- **Positive Reinforcement** — When you add a sanitizer or encryption, Ghostflow rewards you with **Green Secure Lines** in the map.
- **Privacy-First Design** — Built by developers for developers. Your code never leaves your machine.

---

## 🏗️ Supported Languages

Ghostflow is currently specialized for the **modern web ecosystem**:

- **TypeScript** (`.ts`, `.tsx`) - Full AST support for enterprise-scale typed codebases.
- **JavaScript** (`.js`, `.jsx`) - Deep taint analysis for standard ESM and CommonJS modules.

---

## ✨ Key Features

### 🔍 Deep Taint Analysis & Sanitization
- **Advanced Taint Tracking** — Tracks credentials, secrets, and tokens from declaration to execution.
- **Sanitizer Awareness (Green Lines)** — Automatically recognizes security neutralizers (`encrypt()`, `hash()`, `sanitize()`). Data flows passing through these are rendered as **Secure Green Lines**.
- **Smart Filtering** — Intelligently ignores `node_modules`, minified files, and build artifacts (`dist/`, `build/`) to focus exclusively on your unique application logic.
- **Cross-File Awareness** — Resolves module imports and exports to track data flows that span your entire workspace.

### 🗺️ Hierarchical D3.js Visualizer
- **Trust Boundary Enforcement** — Groups connected AST nodes into file-based security context boundaries.
- **Organic Data Flow** — Forces a source-to-sink (left-to-right) simulation for intuitive architectural reading.
- **Third-Party SDK Tracking** — Highlights sensitive values actively handed off to external dependencies as "SDK Handoffs".
- **Interactive Navigation**:
  - **Click-to-Jump**: Navigate from a node in the map directly to the corresponding line in your source code.
  - **Smooth Viewport**: Professional zoom, pan, and high-fidelity **PNG/PDF Export** for security audits.

---

## 🔒 Privacy & Security

### Local Processing
- **100% Local Scanning**: All AST parsing, taint tracking, and graph generation happen **entirely on your local machine**.
- **Zero Exfiltration**: No source code, snippets, or even metadata are ever sent to external APIs or servers.
- **Static Analysis Only**: Ghostflow performs safe static analysis of your AST. It does not execute your code.

---

## ⚙️ How It Works

Ghostflow operates through a multi-stage security pipeline:

1.  **AST Extraction**: Uses the TypeScript Compiler API to build a high-fidelity syntax tree of your workspace.
2.  **Taint Indexing**: Identifies "Sensitive Sources" (variables matching known secret patterns) and "Dangerous Sinks" (network, FS, logging).
3.  **Flow Resolution**: Tracks variable aliasing and sanitization across the entire project graph.
4.  **D3 Mapping**: Converts the resolved data flows into a hierarchical graph layout, grouping nodes by file context.
5.  **Threat Modeling**: Applies STRIDE logic to the resulting edges to surface architectural risks.

---

## 🚀 Getting Started

### Quick Install
1. Clone the repository: `git clone https://github.com/cchoiyon/Ghostflow.git`
2. Install dependencies: `npm install`
3. Compile the extension: `npm run compile`
4. Press `F5` in VS Code to launch the **Extension Development Host**.

---

## 🤝 Contributing

Ghostflow is in active development. We welcome contributions that improve AST coverage, visual fidelity, or threat detection rules! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

*Ghostflow — Visualizing the hidden architecture of the web.* 👻
