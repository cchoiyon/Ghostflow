import * as vscode from 'vscode';
import * as path from 'path';
import { FlowGraph, FlowNode, FlowEdge, NodeType } from './FlowGraph';

/**
 * Provides the Ghostflow Architecture Map as a permanent sidebar Webview using D3.js.
 * Features hierarchical clustering by file, edge bundling for cross-file flows,
 * VS Code theme-aware styling, and interactive zoom/pan/jump-to-code.
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

        webviewView.webview.html = this._getEmptyHtml();
    }

    public update(graph: FlowGraph): void {
        if (!this._view) return;
        this._view.webview.html = this._getHtmlForWebview(graph);
        this._view.description = `Scanned ${new Date().toLocaleTimeString()}`;
    }

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

    private _getEmptyHtml(): string {
        return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            background: var(--vscode-sideBar-background);
            color: var(--vscode-descriptionForeground);
            font-family: var(--vscode-font-family);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            text-align: center;
            padding: 20px;
        }
    </style>
</head>
<body>
    <p>Save a file or click "Scan Workspace" to generate the map.</p>
</body>
</html>`;
    }

    private _getHtmlForWebview(graph: FlowGraph): string {
        const nodes = graph.getNodes();
        const edges = graph.getEdges();

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

        return htmlTemplate
            .replace(/\$\{cspNonce\}/g, cspNonce)
            .replace(/\$\{webviewCspSource\}/g, webviewCspSource)
            .replace(/\$\{d3Uri\}/g, d3Uri.toString())
            .replace(/\/\* __NODES__ \*\/ \[\]/g, () => JSON.stringify(nodes))
            .replace(/\/\* __EDGES__ \*\/ \[\]/g, () => JSON.stringify(edges));
    }

    private getNonce(): string {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
}
