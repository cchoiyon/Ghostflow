import * as vscode from 'vscode';
import * as path from 'path';
import { FlowGraph, FlowNode, FlowEdge, NodeType } from '../core/FlowGraph';
import { ThreatEntry } from '../core/ThreatAnalyzer';

/**
 * Provides the Ghostflow Architecture Map as a permanent sidebar Webview using D3.js.
 * Features hierarchical clustering by file, edge bundling for cross-file flows,
 * VS Code theme-aware styling, and interactive zoom/pan/jump-to-code.
 *
 * Data is passed to the webview EXCLUSIVELY through postMessage — never by
 * re-setting webview.html. This ensures the webview persists across scans.
 */
export class VisualizerProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'ghostflow.visualizerView';
    private _view?: vscode.WebviewView;

    constructor(private readonly _extensionUri: vscode.Uri) {}

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
            } else if (message.command === 'scanWorkspace') {
                vscode.commands.executeCommand('ghostflow.scanWorkspace');
            } else if (message.command === 'downloadPNG') {
                this._handleDownloadPNG(message.data);
            }
        });

        // Set HTML once — data will arrive via postMessage
        webviewView.webview.html = this._getWebviewHtml();
    }

    /**
     * Sends updated graph data to the webview via postMessage.
     * The webview receives and renders it without requiring a full HTML reload.
     * @param graph - The current FlowGraph with all nodes and edges.
     * @param threats - Array of ThreatEntry objects for severity mapping.
     */
    public update(graph: FlowGraph, threats: ThreatEntry[]): void {
        if (!this._view) return;

        // If the webview has lost its HTML (e.g. was hidden), re-set it
        if (!this._view.webview.html || this._view.webview.html.length < 100) {
            this._view.webview.html = this._getWebviewHtml();
        }

        // Transform nodes: compress, derive severity
        const allNodes = graph.getNodes();
        const compressedEdges = graph.getCompressedEdges();

        const activeNodeIds = new Set<string>();
        compressedEdges.forEach(e => {
            activeNodeIds.add(e.from);
            activeNodeIds.add(e.to);
        });
        allNodes.filter(n => !n.isInternal).forEach(n => activeNodeIds.add(n.id));

        const sinkNodeIds = new Set(compressedEdges.filter(e => e.tainted).map(e => e.to));
        const sourceNodeIds = new Set(compressedEdges.filter(e => e.tainted).map(e => e.from));

        function deriveNodeType(n: FlowNode): string {
            const lbl = (n.label + ' ' + n.description).toLowerCase();
            if (lbl.includes('sanitiz')) return 'sanitizer';
            if (lbl.includes('sdk') || lbl.includes('3rd-party') || lbl.includes('third-party')) return 'sdk';
            if (n.type === 'DataStore' || sourceNodeIds.has(n.id)) return 'source';
            if (sinkNodeIds.has(n.id)) return 'sink';
            return 'logic';
        }

        const nodes = allNodes.filter(n => activeNodeIds.has(n.id)).map(n => {
            const nodeThreats = threats.filter(t =>
                t.filePath === n.filePath && t.line === n.line
            );
            const severityRank: Record<string, number> = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
            const severityLabel: Record<number, string> = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' };
            const severeLevels: Record<string, number> = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0 };
            
            let maxRank = 0;
            let maxSeverity = 'None';
            for (const t of nodeThreats) {
                const rank = severityRank[t.severity] ?? 0;
                if (rank > maxRank) maxRank = rank;
                if ((severeLevels[t.severity] ?? 0) > (severeLevels[maxSeverity] ?? 0)) maxSeverity = t.severity;
            }
            return {
                ...n,
                severity: maxSeverity,
                riskLevel: severityLabel[maxRank] ?? 'safe',
                nodeType: deriveNodeType(n)
            };
        });

        // Send data via postMessage — the webview's message listener handles rendering
        this._view.webview.postMessage({
            command: 'renderGraph',
            nodes: nodes,
            edges: compressedEdges,
            threats: threats
        });

        this._view.description = `Scanned ${new Date().toLocaleTimeString()}`;
    }

    /**
     * Handles the PNG download request from the webview.
     * Converts the base64 data URL to a binary buffer and saves via VS Code file dialog.
     * @param dataUrl - The base64-encoded PNG data URL from the webview canvas.
     */
    private async _handleDownloadPNG(dataUrl: string): Promise<void> {
        const base64Data = dataUrl.replace(/^data:image\/png;base64,/, "");
        const buffer = Buffer.from(base64Data, 'base64');
        const uint8Array = new Uint8Array(buffer);

        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(path.join(vscode.workspace.workspaceFolders?.[0].uri.fsPath || '', 'ghostflow-map.png')),
            filters: { 'Images': ['png'] },
            title: 'Download Architecture Map'
        });

        if (uri) {
            try {
                await vscode.workspace.fs.writeFile(uri, uint8Array);
                vscode.window.showInformationMessage(`Successfully saved diagram to ${path.basename(uri.fsPath)}`);
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to save diagram: ${err}`);
            }
        }
    }

    /**
     * Builds the static webview HTML shell with CSP, nonce, and D3 script tag.
     * Nodes and edges are NOT embedded — they arrive later via postMessage.
     * @returns The complete HTML string for the webview.
     */
    private _getWebviewHtml(): string {
        const d3Uri = this._view!.webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'media', 'd3.min.js')
        );

        const cspNonce = this.getNonce();
        const webviewCspSource = this._view!.webview.cspSource;
        const templateUri = vscode.Uri.joinPath(this._extensionUri, 'media', 'visualizer.html');

        let htmlTemplate = '';
        try {
            const fs = require('fs');
            htmlTemplate = fs.readFileSync(templateUri.fsPath, 'utf8');
        } catch (err) {
            return `<html><body>Failed to load template: ${err}</body></html>`;
        }

        // Replace ONLY the static placeholders — data comes via postMessage
        return htmlTemplate
            .replace(/\$\{cspNonce\}/g, cspNonce)
            .replace(/\$\{webviewCspSource\}/g, webviewCspSource)
            .replace(/\$\{d3Uri\}/g, d3Uri.toString());
    }

    /**
     * Generates a cryptographically random nonce string for CSP script-src.
     * @returns A 32-character alphanumeric nonce string.
     */
    private getNonce(): string {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
}
