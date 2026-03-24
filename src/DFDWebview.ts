import * as vscode from 'vscode';
import { FlowGraph, FlowNode, FlowEdge, NodeType } from './FlowGraph';

/**
 * Manages the Ghostflow DFD Webview panel, rendering Mermaid.js flowcharts
 * with connected edges, subgraph grouping, and color-coded trust boundary lines.
 */
export class DFDWebview {
    public static currentPanel: DFDWebview | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    /**
     * Creates or reveals the Ghostflow Visualizer panel beside the active editor.
     * @param extensionUri The URI of the extension, used for local resource roots.
     */
    public static createOrShow(extensionUri: vscode.Uri): void {
        const column = vscode.window.activeTextEditor
            ? vscode.ViewColumn.Beside
            : vscode.ViewColumn.One;

        if (DFDWebview.currentPanel) {
            DFDWebview.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'ghostflowVisualizer',
            'Ghostflow Visualizer',
            column,
            {
                enableScripts: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')]
            }
        );

        DFDWebview.currentPanel = new DFDWebview(panel, extensionUri);
    }

    private constructor(panel: vscode.WebviewPanel, _extensionUri: vscode.Uri) {
        this._panel = panel;
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            message => {
                if (message.command === 'jumpToCode') {
                    this.jumpToCode(message.filePath, message.line, message.character);
                }
            },
            null,
            this._disposables
        );
    }

    /**
     * Updates the webview HTML with a freshly rendered Mermaid DFD from the graph.
     * @param graph The FlowGraph containing scan results with nodes and edges.
     */
    public update(graph: FlowGraph): void {
        this._panel.webview.html = this._getHtmlForWebview(graph);
    }

    /**
     * Opens the source file and jumps to the exact line/character of a detected boundary.
     */
    private jumpToCode(filePath: string, line: number, character: number): void {
        const uri = vscode.Uri.file(filePath);
        vscode.workspace.openTextDocument(uri).then(doc => {
            vscode.window.showTextDocument(doc, {
                viewColumn: vscode.ViewColumn.One,
                selection: new vscode.Range(line, character, line, character),
                preserveFocus: false
            });
        });
    }

    /**
     * Disposes the panel and all associated resources.
     */
    public dispose(): void {
        DFDWebview.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    /**
     * Sanitizes a string for safe use inside Mermaid node labels.
     * Removes characters that break Mermaid's parser.
     */
    private sanitize(text: string): string {
        return text.replace(/["\[\](){}|<>#&]/g, ' ').trim();
    }

    /**
     * Assigns a stable Mermaid-safe ID to each node based on its index.
     */
    private nodeIdMap(nodes: FlowNode[]): Map<string, string> {
        const map = new Map<string, string>();
        nodes.forEach((node, i) => {
            map.set(node.id, `n${i}`);
        });
        return map;
    }

    /**
     * Builds the complete Mermaid flowchart definition with subgraphs,
     * connected edges, and linkStyle directives for red/green coloring.
     */
    private _buildMermaidDefinition(nodes: FlowNode[], edges: FlowEdge[], idMap: Map<string, string>): string {
        if (nodes.length === 0) {
            return 'flowchart TD\n  empty["No boundaries detected."]';
        }

        let graph = 'flowchart TD\n';

        // --- Subgraph: External Network (HTTP calls) ---
        const httpNodes = nodes.filter(n => n.label === 'HTTP Call');
        if (httpNodes.length > 0) {
            graph += '  subgraph external["External Network"]\n';
            graph += '    direction TB\n';
            for (const node of httpNodes) {
                const mid = idMap.get(node.id) ?? 'unknown';
                const label = this.sanitize(`Trust Boundary: External - ${node.rawValue || node.label}`);
                graph += `    ${mid}["${label}"]\n`;
            }
            graph += '  end\n';
        }

        // --- Subgraph: Internal Services (Localhost) ---
        const localhostNodes = nodes.filter(n => n.label === 'Localhost');
        if (localhostNodes.length > 0) {
            graph += '  subgraph internal["Internal Services"]\n';
            graph += '    direction TB\n';
            for (const node of localhostNodes) {
                const mid = idMap.get(node.id) ?? 'unknown';
                const label = this.sanitize(`Process: ${node.rawValue || node.label}`);
                graph += `    ${mid}["${label}"]\n`;
            }
            graph += '  end\n';
        }

        // --- Subgraph: Data Layer (DB connections, env vars) ---
        const dataNodes = nodes.filter(n => n.type === NodeType.DataStore);
        if (dataNodes.length > 0) {
            graph += '  subgraph datalayer["Data Layer"]\n';
            graph += '    direction TB\n';
            for (const node of dataNodes) {
                const mid = idMap.get(node.id) ?? 'unknown';
                const label = this.sanitize(`Data Store: ${node.label}`);
                // Cylinder shape for data stores
                graph += `    ${mid}[("${label}")]\n`;
            }
            graph += '  end\n';
        }

        // --- Any remaining unclassified nodes ---
        const classifiedIds = new Set([...httpNodes, ...localhostNodes, ...dataNodes].map(n => n.id));
        const otherNodes = nodes.filter(n => !classifiedIds.has(n.id));
        for (const node of otherNodes) {
            const mid = idMap.get(node.id) ?? 'unknown';
            const label = this.sanitize(node.label);
            graph += `  ${mid}["${label}"]\n`;
        }

        // --- Edges with labels ---
        let edgeIndex = 0;
        const linkStyles: string[] = [];

        for (const edge of edges) {
            const fromId = idMap.get(edge.from);
            const toId = idMap.get(edge.to);
            if (!fromId || !toId) { continue; }
            // Skip self-referencing edges in Mermaid (they cause rendering issues)
            if (fromId === toId) { continue; }

            const safeLabel = this.sanitize(edge.label);
            graph += `  ${fromId} -->|${safeLabel}| ${toId}\n`;

            // Color: RED for insecure (http://), GREEN for secure (https://)
            const color = edge.secure ? '#22c55e' : '#ef4444';
            linkStyles.push(`  linkStyle ${edgeIndex} stroke:${color},stroke-width:3px`);
            edgeIndex++;
        }

        // Append all linkStyle directives at the end
        for (const style of linkStyles) {
            graph += style + '\n';
        }

        return graph;
    }

    /**
     * Generates the full HTML for the Webview, embedding Mermaid.js,
     * connected graph rendering, and click-to-jump handlers.
     */
    private _getHtmlForWebview(graph: FlowGraph): string {
        const nodes = graph.getNodes();
        const edges = graph.getEdges();
        const idMap = this.nodeIdMap(nodes);
        const mermaidDef = this._buildMermaidDefinition(nodes, edges, idMap);

        // Build JSON node map for click-to-jump
        const nodeMapEntries = nodes.map((node, index) => ({
            id: `n${index}`,
            filePath: node.filePath,
            line: node.line,
            character: node.character
        }));
        const nodeMapJson = JSON.stringify(nodeMapEntries);

        return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ghostflow Visualizer</title>
    <style>
        body {
            background-color: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            font-family: var(--vscode-font-family);
            padding: 16px;
            margin: 0;
        }
        h2 {
            text-align: center;
            color: var(--vscode-editor-foreground);
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
        }
        .legend {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 12px;
            font-size: 12px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .legend-line {
            width: 24px;
            height: 3px;
            border-radius: 2px;
        }
        .legend-red { background-color: #ef4444; }
        .legend-green { background-color: #22c55e; }
        #mermaid-container {
            display: flex;
            justify-content: center;
        }
        .node rect, .node polygon, .node circle, .node ellipse {
            cursor: pointer !important;
        }
        #error-msg {
            color: #ef4444;
            text-align: center;
            padding: 20px;
        }
    </style>
</head>
<body>
    <h2>Ghostflow Trust Boundary Map</h2>
    <div class="legend">
        <div class="legend-item">
            <span class="legend-line legend-red"></span>
            <span>Insecure (HTTP)</span>
        </div>
        <div class="legend-item">
            <span class="legend-line legend-green"></span>
            <span>Secure (HTTPS)</span>
        </div>
    </div>
    <div id="mermaid-container"></div>
    <div id="error-msg"></div>

    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        const vscodeApi = acquireVsCodeApi();
        const nodeMap = ${nodeMapJson};
        const graphDef = ${JSON.stringify(mermaidDef)};

        mermaid.initialize({
            startOnLoad: false,
            theme: 'dark',
            securityLevel: 'loose',
            flowchart: {
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis',
                rankSpacing: 60,
                nodeSpacing: 40
            }
        });

        async function renderDiagram() {
            const container = document.getElementById('mermaid-container');
            const errorEl = document.getElementById('error-msg');
            try {
                const { svg } = await mermaid.render('ghostflow-dfd', graphDef);
                container.innerHTML = svg;
                errorEl.textContent = '';
                attachClickHandlers();
            } catch (err) {
                errorEl.textContent = 'Render error: ' + err.message;
            }
        }

        function attachClickHandlers() {
            nodeMap.forEach(function(entry) {
                const nodeEl = document.querySelector('#ghostflow-dfd [id*="' + entry.id + '"]');
                if (!nodeEl) return;
                let target = nodeEl.closest('.node') || nodeEl;
                target.style.cursor = 'pointer';
                target.addEventListener('click', function() {
                    vscodeApi.postMessage({
                        command: 'jumpToCode',
                        filePath: entry.filePath,
                        line: entry.line,
                        character: entry.character
                    });
                });
            });
        }

        renderDiagram();
    </script>
</body>
</html>`;
    }
}
