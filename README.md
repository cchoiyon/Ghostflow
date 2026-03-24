# Ghostflow 👻

> **Visualize the hidden security architecture of your code.**

Ghostflow is a developer-native VS Code extension that brings security architecture out of the shadows and into the IDE. It automatically scans your TypeScript/JavaScript source code, identifies trust boundaries and insecure patterns, and renders a live, interactive Data Flow Diagram — all without leaving your editor.

---

## ✨ Features

### 🔍 Deep AST Taint Analysis
- **Advanced Taint Tracking** — Tracks "Sensitive Sources" (API keys, secrets, tokens) into "Dangerous Sinks" (network calls, file writes, logging).
- **Cross-File Awareness** — Resolves imports and exports to track data flows that span across multiple files in the workspace.
- **Incremental Scanning** — Uses mtime-based caching for high-performance AST indexing without blocking the UI.
- **Non-Blocking** — Traversal yields to the event loop via `setImmediate`, keeping VS Code responsive.

### 🗺️ Hierarchical D3.js Visualizer
- **File-Based Clustering** — Automatically groups nodes into "File Containers" for a clean, architectural view of your project.
- **Edge Bundling** — Aggregates multiple data flows between files into a single bundle with a flow count label to eliminate clutter.
- **Interactive Navigation**:
  - **Zoom to File**: Double-click any file container to center and focus on its internal nodes.
  - **Click-to-Jump**: Click any node to jump directly to the corresponding line in source code.
  - **Smooth Zoom/Pan**: Full mouse wheel and touch support for large-scale maps.
- **Live Sync** — DFD updates instantly on every file save.

### 🛡️ STRIDE Threat Intel & Reporting
- **STRIDE-Categorized Findings** — Automatically maps tainted flows to Spoofing, Tampering, Repudiation, Information Disclosure, DoS, and Elevation of Privilege.
- **Professional PDF Export** — Generate audit-ready "Security Architecture Assessment" reports with executive summaries and detailed findings tables.
- **Sidebar Workflow** — Permanent Activity Bar integration with dual views: "Architecture Map" and "Threat Report".

---

## 🚀 Getting Started

### Prerequisites
- [VS Code](https://code.visualstudio.com/) v1.80+
- [Node.js](https://nodejs.org/) v18+

### Install & Run
```bash
git clone https://github.com/cchoiyon/Ghostflow.git
cd Ghostflow
npm install
npm run compile
```

### Test in VS Code
1. Open the `Ghostflow` folder in VS Code.
2. Press **`F5`** to launch the Extension Development Host.
3. Open the **Ghostflow** icon in the Activity Bar.
4. Click **"🌐 Scan Entire Workspace"** to index your project.
5. Save any changes to `.ts` files to see live updates.

---

## 📁 Project Structure

```
Ghostflow/
├── src/
│   ├── extension.ts          # Core extension logic and command registration
│   ├── Scanner.ts            # Deep AST Taint Engine & resolution logic
│   ├── ProjectScanner.ts     # Workspace-wide indexing and export caching
│   ├── FlowGraph.ts          # Hierarchical Graph data structures
│   ├── VisualizerProvider.ts # D3.js Hierarchical Renderer
│   ├── ThreatAnalyzer.ts     # STRIDE-based risk logic
│   └── ThreatReportProvider.ts # Sidebar reporting UI & PDF generation
├── package.json               # Extension manifest and UI contributions
└── tsconfig.json              # Strict TypeScript configuration
```

---

## 🛣️ Roadmap

- [x] **Alpha 0.1:** Core AST scanner with insecure pattern detection
- [x] **Alpha 0.2:** Live DFD Visualizer with Mermaid.js
- [x] **Alpha 0.3:** Connected graph with edge inference
- [x] **Beta 1.0:** Deep Taint Analysis & Cross-File Tracking
- [x] **Beta 1.1:** Hierarchical D3.js Visualization & Edge Bundling
- [x] **Beta 1.2:** Sidebar Integration & PDF Reporting
- [ ] **V1.0:** Full VS Code Marketplace launch

---

## 🧰 Tech Stack
| Component | Technology |
|-----------|------------|
| Language | TypeScript (strict mode) |
| AST Parsing | TypeScript Compiler API |
| Visualization | D3.js (v7) |
| Reporting | jsPDF & autoTable |
| Icons | Codicons |
| Theming | VS Code CSS Variables |

---

## 🤝 Contributing

This project is in active early development. Contributions, feedback, and feature requests are welcome!

---

**"Security is not a checkbox; it's a map. Let's draw it."** 👻
