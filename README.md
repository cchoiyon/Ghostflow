# Ghostflow 👻

> **Visualize the hidden security architecture of your code.**

Ghostflow is a developer-native VS Code extension that brings security architecture out of the shadows and into the IDE. It automatically scans your TypeScript/JavaScript source code, identifies trust boundaries and insecure patterns, and renders a live, interactive Data Flow Diagram — all without leaving your editor.

---

## ✨ Features

### 🔍 Core Scanner
- **AST-Powered Analysis** — Uses the TypeScript Compiler API to traverse the Abstract Syntax Tree of your active file.
- **Insecure Pattern Detection** — Automatically identifies:
  - `fetch` / `axios` HTTP calls
  - Hardcoded `localhost` / `127.0.0.1` bindings
  - `process.env` access (potential secret exposure)
  - Database connection strings (`mongodb://`, `postgres://`, `mysql://`)
- **Non-Blocking** — Heavy AST traversal yields to the event loop via `setImmediate` every 500 nodes, keeping VS Code responsive.
- **Live Sync** — Scans trigger automatically on every file save (`onDidSaveTextDocument`).

### 🗺️ DFD Visualizer
- **Connected Graph** — Nodes aren't just listed; they are connected by directed edges representing actual data flow relationships.
- **Subgraph Grouping** — Nodes are organized into architectural regions:
  - **External Network** — HTTP calls and outbound requests
  - **Internal Services** — Localhost-bound processes
  - **Data Layer** — Database connections and environment variables
- **Color-Coded Trust Boundaries**:
  - 🔴 **Red** arrows for insecure `http://` connections
  - 🟢 **Green** arrows for secure `https://` connections
- **Click-to-Jump** — Click any node in the diagram to jump directly to the corresponding line in your source code.
- **VS Code Themed** — The visualizer respects your editor's dark/light theme.

### 🛡️ STRIDE-Aligned
The scanner is built on the **STRIDE** threat modeling methodology, treating every I/O operation, network call, and database interaction as a potential trust boundary transition.

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
3. In the new window, open any `.ts` or `.js` file (or create a `test.ts` with sample code below).
4. **Save** the file — the scanner runs automatically.
5. Open the Command Palette (`Ctrl+Shift+P`) → **`Ghostflow: Show Live Visualizer`**.

### Sample Test File
```typescript
const dbUrl = "mongodb://user:pass@localhost:27017/db";
const secret = process.env.AWS_SECRET_KEY;

function getUserData() {
    axios.get("http://localhost:8080/api/users");
    fetch("http://127.0.0.1/auth");
}
```

---

## 📁 Project Structure

```
Ghostflow/
├── src/
│   ├── extension.ts      # VS Code entry point, commands, and event wiring
│   ├── Scanner.ts         # AST traversal and insecure pattern detection
│   ├── FlowGraph.ts       # Node/Edge data structures for the DFD
│   └── DFDWebview.ts      # Webview panel with Mermaid.js rendering
├── package.json           # Extension manifest and dependencies
├── tsconfig.json          # Strict TypeScript configuration
└── .vscode/
    ├── launch.json        # F5 debug configuration
    └── tasks.json         # Build task for tsc watch
```

---

## 🛣️ Roadmap

- [x] **Alpha 0.1:** Core AST scanner with insecure pattern detection
- [x] **Alpha 0.2:** Live DFD Visualizer with Mermaid.js in a Webview
- [x] **Alpha 0.3:** Connected graph with edge inference and color-coded trust boundaries
- [ ] **Beta 1.0:** Automated STRIDE table generation via AI
- [ ] **Beta 1.1:** Multi-file scanning and cross-module data flow tracking
- [ ] **V1.0:** Full VS Code Marketplace launch

---

## 🧰 Tech Stack
| Component | Technology |
|-----------|------------|
| Language | TypeScript (strict mode) |
| Extension Host | VS Code Extension API |
| AST Parsing | TypeScript Compiler API |
| Visualization | Mermaid.js |
| Theming | VS Code CSS Variables |

---

## 🤝 Contributing

This project is in active early development. Contributions, feedback, and feature requests are welcome!

---

**"Security is not a checkbox; it's a map. Let's draw it."** 👻
