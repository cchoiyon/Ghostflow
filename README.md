# Ghostflow 👻

> **Visualize the hidden security architecture of your code.**

Ghostflow is a developer-native VS Code extension that brings security architecture out of the shadows and into the IDE. It automatically scans your TypeScript/JavaScript source code, identifies trust boundaries and insecure patterns, and renders a live, interactive Data Flow Diagram — all without leaving your editor.

---

## ✨ Features

### 🛡️ Deep Taint Analysis & Sanitization
- **Advanced Taint Tracking** — Tracks "Sensitive Sources" (API keys, secrets, tokens) into "Dangerous Sinks" (network calls, file writes, logging).
- **Sanitizer Awareness (Green Lines)** — Automatically recognizes security neutralizers (`encrypt()`, `hash()`, `sanitize()`). Data flows passing through these are rendered as **Secure Green Lines** in the visualizer and resolved from the threat report.
- **Smart Node Filtering** — Intelligently ignores `node_modules`, minified files, and build artifacts to focus exclusively on your unique application logic.
- **Cross-File Awareness** — Resolves imports and exports to track data flows that span across multiple files in the workspace.
- **Non-Blocking Performance** — Incremental scanning and event-loop yielding via `setImmediate` ensure zero UI lag during deep AST traversal.

### 🗺️ Hierarchical D3.js Visualizer
- **Trust Boundary Enforcement** — Automatically groups connected AST nodes into stark, dashed red "Trust Boundaries" indicating their file container security context.
- **Organic Left-to-Right Dynamics** — Evaluates structural architecture to map data flow natively from sources (left) to sinks (right), aggressively pruning entirely isolated nodes that don't transition across boundaries.
- **Third-Party SDK Tracking** — Tracks sensitive values actively handed off into external `node_modules` dependencies as "SDK Handoffs", painting them distinctly as Insecure Flows.
- **Edge Bundling** — Aggregates multiple data pipelines between files into a single bundled arc with dynamic flow-count relationship typography to eliminate intersection clutter.
- **Interactive Navigation**:
  - **Zoom to File**: Double-click any Trust Boundary to center and focus on its internal nodes.
  - **Click-to-Jump**: Click any node to jump intuitively directly to the corresponding AST line in the raw source code.
  - **Smooth Zoom/Pan**: Full mouse wheel and touch integration for large-scale enterprise mapping.
- **Live Sync** — Visualizer layout responds and adapts instantly on every file save.

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
│   ├── Scanner.ts            # Deep AST Taint Engine & Sanitization logic
│   ├── ProjectScanner.ts     # Workspace-wide indexing and export caching
│   ├── FlowGraph.ts          # Hierarchical Graph data structures
│   ├── VisualizerProvider.ts # D3.js Hierarchical Renderer
│   ├── ThreatAnalyzer.ts     # STRIDE-based risk logic
│   └── ThreatReportProvider.ts # Sidebar reporting UI & PDF generation
├── media/                    # External HTML templates & D3 assets
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
- [x] **Beta 1.3:** Node Deduplication, Trust Boundaries, & SDK Dependencies
- [x] **Beta 1.4:** High-Fidelity SVG Viewport PNG Export Engine
- [x] **Beta 1.5:** Sanitizer Tracking (Green Lines) & Smart Node Filtering
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
