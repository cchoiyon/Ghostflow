# Ghostflow 👻

> **Visualize the hidden security architecture of your code.**

Traditional threat modeling is the "ghost" in the development lifecycle—often talked about, rarely seen, and usually appearing too late to make a difference. **Ghostflow** is a developer-native VS Code extension that brings security architecture out of the shadows and into the IDE.

---

## The Problem
Security design is currently a bottleneck. Developers ship code in minutes, but architectural threat modeling (STRIDE) takes hours of manual diagramming and documentation in disconnected tools. 

* **Static Models:** Diagrams are outdated the moment the code changes.
* **Context Gap:** AI coding assistants find bugs in files but are "blind" to system-wide trust boundaries.
* **The "Chore" Factor:** Documentation feels like paperwork, not engineering.

##  The Vision
Ghostflow treats **System Architecture as Code**. It automatically maps data flows, identifies trust boundaries, and suggests mitigations in real-time during the development process.

### Phase 1: The Visualizer (Current Focus)
* **Live DFD Generation:** Uses `Tree-sitter` to parse source code and render live Data Flow Diagrams using the `D2` engine.
* **Auto-Discovery:** Automatically identifies Web Servers, Databases, and External APIs based on library imports and connection strings.
* **Trust Boundary Mapping:** Visualizes the "Red Line" where untrusted internet traffic meets internal logic.

### Phase 2: AI-Powered Justification
* **Automated STRIDE:** Leverages LLMs to analyze the diagram and suggest "Mitigated" or "N/A" justifications for every flow.
* **One-Click Reports:** Generates audit-ready compliance reports (HTML/JSON) without leaving the editor.

### Phase 3: Boundary Enforcement
* **Architectural Guardrails:** Alerts developers when a code change creates a new, unauthenticated path across a trust boundary.
* **Verification:** Checks configuration files to ensure that "Mitigated" claims (like TLS 1.3) are actually implemented in the code.

---

##  Tech Stack
* **Language:** TypeScript
* **Extension Host:** VS Code Extension API
* **Parsing:** Tree-sitter (Multi-language support)
* **Diagramming:** D2 (Declarative Diagramming)
* **Intelligence:** Gemini / OpenAI API integration

##  Roadmap
- [ ] **Alpha 0.1:** Basic D2 rendering in a VS Code Webview.
- [ ] **Alpha 0.2:** Node.js/Express route discovery.
- [ ] **Beta 1.0:** Automated STRIDE table generation via AI.
- [ ] **V1.0:** Full marketplace launch.

---

##  Contribution
This repository is currently **Private**. Access is restricted to core contributors and early-stage partners. 

**"Security is not a checkbox; it’s a map. Let’s draw it."**
