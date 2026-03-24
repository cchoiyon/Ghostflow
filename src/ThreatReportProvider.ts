import * as vscode from 'vscode';
import { ThreatEntry, StrideCategory, ThreatSeverity } from './ThreatAnalyzer';

/**
 * Provides the Ghostflow Threat Report as a sidebar Webview in the Activity Bar.
 * Renders STRIDE-categorized threat findings with clickable entries
 * that jump to the corresponding line of source code.
 *
 * Security implication: This view surfaces actionable threat intelligence
 * directly in the developer's workflow, reducing the gap between code
 * authoring and security review.
 */
export class ThreatReportProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'ghostflow.threatReport';
    private _view?: vscode.WebviewView;
    private _threats: ThreatEntry[] = [];
    private _onGenerateReport?: () => void;

    constructor(private readonly _extensionUri: vscode.Uri) {}

    /**
     * Registers a callback to be invoked when the user clicks "Generate PDF Report".
     * @param callback The function to call when report generation is requested.
     */
    public onGenerateReport(callback: () => void): void {
        this._onGenerateReport = callback;
    }

    /**
     * Called by VS Code when the sidebar view needs to be rendered.
     */
    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ): void {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        // Handle messages from the webview
        webviewView.webview.onDidReceiveMessage(message => {
            if (message.command === 'jumpToCode') {
                const uri = vscode.Uri.file(message.filePath);
                vscode.workspace.openTextDocument(uri).then(doc => {
                    vscode.window.showTextDocument(doc, {
                        viewColumn: vscode.ViewColumn.One,
                        selection: new vscode.Range(
                            message.line, message.character,
                            message.line, message.character
                        ),
                        preserveFocus: false
                    });
                });
            } else if (message.command === 'generateReport') {
                if (this._onGenerateReport) {
                    this._onGenerateReport();
                }
            }
        });

        this._updateHtml();
    }

    /**
     * Updates the threat report with new findings from the ThreatAnalyzer.
     * @param threats Array of ThreatEntry items to display.
     */
    public updateThreats(threats: ThreatEntry[]): void {
        this._threats = threats;
        this._updateHtml();
    }

    /**
     * Rebuilds the HTML content of the sidebar webview.
     */
    private _updateHtml(): void {
        if (!this._view) {
            return;
        }

        const threats = this._threats;
        const threatsJson = JSON.stringify(threats);

        // Group threats by STRIDE category for organized display
        const grouped = new Map<string, ThreatEntry[]>();
        for (const t of threats) {
            const existing = grouped.get(t.category) ?? [];
            existing.push(t);
            grouped.set(t.category, existing);
        }

        // Build HTML sections per category
        let sectionsHtml = '';

        if (threats.length === 0) {
            sectionsHtml = '<div class="empty">No threats detected. Save a TS/JS file to scan.</div>';
        } else {
            // Summary bar
            const critical = threats.filter(t => t.severity === ThreatSeverity.Critical).length;
            const high = threats.filter(t => t.severity === ThreatSeverity.High).length;
            const medium = threats.filter(t => t.severity === ThreatSeverity.Medium).length;
            const low = threats.filter(t => t.severity === ThreatSeverity.Low).length;

            sectionsHtml += `<div class="summary-bar">
                <span class="badge critical">${critical} Critical</span>
                <span class="badge high">${high} High</span>
                <span class="badge medium">${medium} Medium</span>
                <span class="badge low">${low} Low</span>
            </div>`;

            const categoryIcons: Record<string, string> = {
                [StrideCategory.Spoofing]: '🎭',
                [StrideCategory.Tampering]: '🔧',
                [StrideCategory.Repudiation]: '📝',
                [StrideCategory.InformationDisclosure]: '🔓',
                [StrideCategory.DenialOfService]: '🚫',
                [StrideCategory.ElevationOfPrivilege]: '⬆️'
            };

            for (const [category, entries] of grouped) {
                const icon = categoryIcons[category] ?? '⚠️';
                sectionsHtml += `<div class="category-section">`;
                sectionsHtml += `<h3>${icon} ${this._escapeHtml(category)}</h3>`;

                for (const entry of entries) {
                    const severityClass = entry.severity.toLowerCase();
                    const escapedFilePath = this._escapeHtml(entry.filePath).replace(/\\/g, '\\\\');
                    sectionsHtml += `
                        <div class="threat-item ${severityClass}"
                             onclick="jumpTo('${escapedFilePath}', ${entry.line}, ${entry.character})">
                            <span class="severity-dot ${severityClass}"></span>
                            <div class="threat-content">
                                <div class="threat-message">${this._escapeHtml(entry.message)}</div>
                                <div class="threat-location">Line ${entry.line + 1} · ${this._escapeHtml(entry.sourceLabel)}</div>
                            </div>
                            <span class="jump-icon">→</span>
                        </div>`;
                }
                sectionsHtml += `</div>`;
            }
        }

        this._view.webview.html = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: var(--vscode-sideBar-background);
            color: var(--vscode-sideBar-foreground);
            font-family: var(--vscode-font-family);
            font-size: 12px;
            padding: 8px;
        }
        h2 {
            font-size: 13px;
            font-weight: 600;
            padding: 6px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
            margin-bottom: 8px;
            color: var(--vscode-editor-foreground);
        }
        .summary-bar {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .badge {
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge.critical { background: #dc262620; color: #f87171; border: 1px solid #f8717140; }
        .badge.high { background: #f9731620; color: #fb923c; border: 1px solid #fb923c40; }
        .badge.medium { background: #eab30820; color: #fbbf24; border: 1px solid #fbbf2440; }
        .badge.low { background: #22c55e20; color: #4ade80; border: 1px solid #4ade8040; }
        .category-section {
            margin-bottom: 12px;
        }
        h3 {
            font-size: 12px;
            font-weight: 600;
            padding: 4px 0;
            color: var(--vscode-editor-foreground);
            opacity: 0.9;
        }
        .threat-item {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            padding: 8px;
            margin: 4px 0;
            border-radius: 4px;
            cursor: pointer;
            border-left: 3px solid transparent;
            transition: background 0.15s ease;
        }
        .threat-item:hover {
            background: var(--vscode-list-hoverBackground);
        }
        .threat-item.critical { border-left-color: #f87171; }
        .threat-item.high { border-left-color: #fb923c; }
        .threat-item.medium { border-left-color: #fbbf24; }
        .threat-item.low { border-left-color: #4ade80; }
        .severity-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-top: 4px;
            flex-shrink: 0;
        }
        .severity-dot.critical { background: #f87171; }
        .severity-dot.high { background: #fb923c; }
        .severity-dot.medium { background: #fbbf24; }
        .severity-dot.low { background: #4ade80; }
        .threat-content {
            flex: 1;
            min-width: 0;
        }
        .threat-message {
            color: var(--vscode-editor-foreground);
            line-height: 1.4;
            word-wrap: break-word;
        }
        .threat-location {
            color: var(--vscode-descriptionForeground);
            font-size: 11px;
            margin-top: 2px;
        }
        .jump-icon {
            color: var(--vscode-textLink-foreground);
            font-size: 14px;
            flex-shrink: 0;
            margin-top: 2px;
            opacity: 0;
            transition: opacity 0.15s ease;
        }
        .threat-item:hover .jump-icon {
            opacity: 1;
        }
        .empty {
            text-align: center;
            padding: 24px 8px;
            color: var(--vscode-descriptionForeground);
            font-style: italic;
        }
        #generate-btn {
            display: block;
            width: 100%;
            padding: 8px 12px;
            margin-bottom: 10px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s ease;
        }
        #generate-btn:hover {
            background: var(--vscode-button-hoverBackground);
        }
    </style>
</head>
<body>
    <h2>🛡️ STRIDE Threat Report</h2>
    <button id="generate-btn" onclick="generateReport()">Generate PDF Report</button>
    ${sectionsHtml}

    <script>
        const vscodeApi = acquireVsCodeApi();
        function jumpTo(filePath, line, character) {
            vscodeApi.postMessage({
                command: 'jumpToCode',
                filePath: filePath.replace(/\\\\\\\\/g, '\\\\'),
                line: line,
                character: character
            });
        }
        function generateReport() {
            vscodeApi.postMessage({ command: 'generateReport' });
        }
    </script>
</body>
</html>`;
    }

    /**
     * Escapes HTML special characters to prevent XSS in the webview.
     */
    private _escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}
