# Contributing to Ghostflow

First off, thank you for considering contributing to Ghostflow! It's people like you that make this security tool better.

## Where to Start?

1. **Bug Reports & Feature Requests**: Please use the GitHub Issue Tracker to report bugs or suggest new features. Include clear steps to reproduce the issue.
2. **Development**:
   - Ghostflow is built as a TypeScript VS Code extension.
   - You will need `Node.js` and `npm` installed.
   - Run `npm install` to install dependencies.
   - Press `F5` in VS Code to run the extension inside a specialized Development Host window.

## Code Standards
- **Strict TypeScript**: We strictly avoid `any`. Ensure all inputs and nodes are strictly typed.
- **Security Checkers**: When editing `Scanner.ts` or modifying `ThreatAnalyzer.ts`, ensure that you aren't adding any recursive sync methods that could block the main thread. Always defer deep property evaluations with `fs.promises` and explicit stacks.
- **Webview Security**: Any UI additions must adhere to VS Code's strict CSP protocols. Inline `onclick` evaluation is prohibited.

## Pull Request Process
1. Ensure your code compiles correctly (`npm run compile`).
2. Add inline TSDoc comments for any significant API interface additions to the analyzer codebase.
3. Your PR will be evaluated by the repository maintainers. Be prepared to address code review comments.

Thank you!
