# Ghostflow

[![Visual Studio Marketplace](https://img.shields.io/visual-studio-marketplace/v/cchoiyon.ghostflow?style=flat-square&color=007acc&label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=cchoiyon.ghostflow)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/cchoiyon/Ghostflow/ci.yml?style=flat-square&label=Build)](https://github.com/cchoiyon/Ghostflow/actions)
[![VS Code](https://img.shields.io/badge/VS%20Code-1.80+-blue?style=flat-square&logo=visual-studio-code)](https://code.visualstudio.com/)

Ghostflow is a developer-native VS Code extension for live security architecture visualization and automated Data Flow Diagram (DFD) generation. It statically analyzes TypeScript and JavaScript codebases using the TypeScript Compiler API, identifies trust boundaries and sensitive data flows, and renders an interactive, STRIDE-annotated graph directly in the editor sidebar — enabling developers to reason about security architecture without leaving the IDE.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Threat Detection](#threat-detection)
- [Privacy and Data Handling](#privacy-and-data-handling)
- [Supported Languages](#supported-languages)
- [Getting Started](#getting-started)
- [Commands](#commands)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Taint Analysis

Ghostflow performs multi-stage interprocedural taint analysis across the entire workspace:

- **Sensitive Source Detection** — Variables whose names match known credential, secret, and PII patterns (`apiKey`, `password`, `token`, `ssn`, etc.) are automatically identified as taint sources.
- **Taint Aliasing** — Assignments propagate taint status to alias variables, including destructured values, property chains, and function return values.
- **Sanitizer Recognition** — Calls to recognized security functions (`encrypt`, `hash`, `bcrypt`, `hmac`, `cipher`, `sanitize`) mark the resulting value as secure, rendering the downstream edge green in the DFD.
- **Cross-File Resolution** — Sensitive variables exported from one module and imported into another carry their taint status across file boundaries.
- **Dangerous Sink Detection** — Tainted values reaching network calls (`fetch`, `axios`, `http.request`), file writes, logging functions, shell execution, or dynamic code evaluation are flagged as concrete data flow violations.

### Visualization

The Architecture Map panel renders a force-directed Data Flow Diagram using D3.js:

- **Trust Boundaries** — Nodes are grouped by source file into labeled boundary clusters.
- **Left-to-Right Flow** — The simulation enforces a source-to-sink directional layout for intuitive architectural reading.
- **Edge Coloring** — Green edges indicate secure or sanitized flows; red edges indicate insecure flows crossing a trust boundary without protection.
- **Click-to-Jump** — Clicking any node opens the corresponding file at the exact line in the editor.
- **Third-Party SDK Handoff Detection** — Sensitive values passed to non-relative imported libraries are flagged as SDK handoffs and rendered distinctly.
- **Export** — The DFD can be exported as a high-resolution PNG or as a detailed HTML audit report.

### Threat Report

The Threat Report panel lists all findings produced by the STRIDE analysis engine, including:

| Column | Description |
|---|---|
| Severity | Critical / High / Medium / Low |
| CWE | Linked CWE identifier (e.g. CWE-319, CWE-798) |
| Name | CWE weakness name |
| OWASP | Mapped OWASP Top 10 2021 category |
| File | Source file and line number |
| Remediation | Specific, actionable remediation guidance |

Reports can be exported as a self-contained HTML document or a PDF via jsPDF.

---

## Architecture

Ghostflow follows a strict separation between the analysis pipeline and the rendering layer:

```
src/
  core/
    Scanner.ts           # AST traversal, taint source collection, sink detection
    ProjectScanner.ts    # Workspace-level sensitive export cache for cross-file taint
    FlowGraph.ts         # Graph data model (nodes, edges, tainted flows)
    ThreatAnalyzer.ts    # STRIDE threat engine, CWE/OWASP metadata mapping
  providers/
    VisualizerProvider.ts     # WebviewViewProvider for the Architecture Map panel
    ThreatReportProvider.ts   # WebviewViewProvider for the Threat Report panel
  export/
    htmlReportGenerator.ts    # HTML audit report generation
    ReportGenerator.ts        # PDF report generation via jsPDF
    reportTemplate.html       # HTML report template
  utils/
    constants.ts         # Sensitive and sanitizer pattern definitions
    nullGuards.ts        # Null-safe utility functions
    remediations.ts      # Remediation text library
  extension.ts           # Extension entry point, command and event registration
media/
  visualizer.html        # D3.js webview document for the Architecture Map
```

**Pipeline stages:**

1. **AST Extraction** — `Scanner` parses documents using `ts.createSourceFile` and traverses the AST asynchronously via `setImmediate` to avoid blocking the main thread.
2. **Taint Indexing** — Sensitive sources are collected and taint aliases are resolved in a single traversal pass.
3. **Cross-File Resolution** — `ProjectScanner` maintains a workspace-level cache of sensitive exports, resolved on import declarations.
4. **Edge Inference** — Structural edges (HTTP-to-Localhost, Env-to-DB) are inferred in a post-traversal pass.
5. **Taint Flow Detection** — A second AST pass detects tainted identifiers reaching dangerous sink call expressions.
6. **Threat Analysis** — `ThreatAnalyzer` maps graph nodes, edges, and tainted flows to STRIDE categories with CWE and OWASP metadata.
7. **Rendering** — The `FlowGraph` is serialized and posted to the D3 webview via `postMessage`.

---

## Threat Detection

Ghostflow applies the STRIDE threat modeling framework. The following patterns are detected:

| Pattern | STRIDE Category | Example CWE |
|---|---|---|
| Cleartext HTTP outbound call | Information Disclosure, Tampering | CWE-319 |
| Hardcoded database connection string | Elevation of Privilege, Information Disclosure | CWE-798, CWE-312 |
| Environment variable access | Information Disclosure | CWE-526 |
| Hardcoded localhost binding | Tampering, Denial of Service | CWE-1188 |
| ORM / database query call | Information Disclosure, Tampering | CWE-89 |
| `eval()` / `new Function()` | Elevation of Privilege, Tampering | CWE-95 |
| Shell command execution | Elevation of Privilege, Tampering | CWE-78 |
| Sensitive variable reaching a network sink | Information Disclosure | CWE-200 |
| Insecure data flow across trust boundary | Information Disclosure / Elevation of Privilege | CWE-319, CWE-311 |

---

## Privacy and Data Handling

All analysis is performed entirely on the local machine.

- No source code, AST data, file paths, or findings are transmitted to any external server or API.
- Ghostflow performs read-only static analysis. It does not execute user code.
- No telemetry is collected.

---

## Supported Languages

| Language | Extensions | Notes |
|---|---|---|
| TypeScript | `.ts`, `.tsx` | Full AST support via the TypeScript Compiler API |
| JavaScript | `.js`, `.jsx` | Parsed as `ScriptTarget.Latest`; type information is not available |

Minified files (`.min.js`, `.min.ts`) and third-party directories (`node_modules/`, `dist/`, `build/`) are automatically excluded from analysis.

---

## Getting Started

**Prerequisites**

- Node.js 18 or later
- VS Code 1.80 or later

**Installation from source**

```bash
git clone https://github.com/cchoiyon/Ghostflow.git
cd Ghostflow
npm install
npm run compile
```

Open the repository in VS Code and press `F5` to launch the Extension Development Host. The Ghostflow sidebar will appear in the Activity Bar.

**Installation from the VS Code Marketplace**

Search for `Ghostflow` in the Extensions panel or install from the [Marketplace page](https://marketplace.visualstudio.com/items?itemName=cchoiyon.ghostflow).

---

## Commands

| Command | Title | Description |
|---|---|---|
| `ghostflow.scan` | Ghostflow: Scan Active File | Scans the currently active editor document and updates the DFD. |
| `ghostflow.scanWorkspace` | Ghostflow: Scan Entire Workspace | Batch scans all TypeScript and JavaScript files in the workspace. |
| `ghostflow.exportReport` | Ghostflow: Export HTML Audit Report | Exports a self-contained HTML security audit report. |

The extension also triggers an incremental scan automatically on `onDidSaveTextDocument` for TypeScript and JavaScript files, excluding test files (`.test.ts`, `.spec.ts`) and declaration files (`.d.ts`).

---

## Contributing

Contributions that improve AST detection coverage, STRIDE rule accuracy, visualization fidelity, or test coverage are welcome. Please open an issue before submitting a pull request for significant changes.

```bash
npm run watch   # Incremental TypeScript compilation
npm run compile # Full compilation
npm run lint    # ESLint (requires eslint to be installed)
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
