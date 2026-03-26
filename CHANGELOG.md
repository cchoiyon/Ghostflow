# Changelog

All notable changes to the Ghostflow extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-26
### Added
- Initial release of Ghostflow Security Visualizer.
- Introduced offline webview data flow visualization using D3.js.
- Implemented core STRIDE threat modeling analysis.
- Real-time file taint flow scanning with asynchronous recursive resolution.
- Added comprehensive PDF Report Generation tool.
- Introduced strict data flow diagnostics and editor highlighting for security vulnerabilities.
- Packaged secure templates avoiding inline JavaScript evaluation across Webviews (`VisualizerProvider.ts` and `ThreatReportProvider.ts`).
