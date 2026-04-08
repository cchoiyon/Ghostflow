import * as vscode from 'vscode';
import { ThreatEntry, StrideCategory, ThreatSeverity } from '../core/ThreatAnalyzer';

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
            } else if (message.command === 'scanWorkspace') {
                vscode.commands.executeCommand('ghostflow.scanWorkspace');
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
                             data-filepath="${escapedFilePath}" data-line="${entry.line}" data-character="${entry.character}">
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

        const cspNonce = this.getNonce();
        const webviewCspSource = this._view.webview.cspSource;
        const templateUri = vscode.Uri.joinPath(this._extensionUri, 'media', 'threatReport.html');
        
        let htmlTemplate = '';
        try {
            const fs = require('fs');
            htmlTemplate = fs.readFileSync(templateUri.fsPath, 'utf8');
        } catch (err) {
            this._view.webview.html = `<html><body>Failed to load template: ${err}</body></html>`;
            return;
        }

        this._view.webview.html = htmlTemplate
            .replace(/\$\{cspNonce\}/g, cspNonce)
            .replace(/\$\{webviewCspSource\}/g, webviewCspSource)
            .replace('${sectionsHtml}', sectionsHtml);
    }

    private getNonce(): string {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
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
