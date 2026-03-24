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

        return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ghostflow D3 Architecture Map</title>
    <style>
        :root {
            --bg: var(--vscode-sideBar-background);
            --fg: var(--vscode-sideBar-foreground);
            --border: var(--vscode-panel-border);
            --container-bg: var(--vscode-editor-background);
            --tainted: var(--vscode-charts-red);
            --secure: var(--vscode-charts-green);
            --insecure: var(--vscode-charts-orange);
            --node-shadow: 0 8px 16px rgba(0,0,0,0.3);
        }
        body {
            background: var(--bg);
            color: var(--fg);
            font-family: var(--vscode-font-family);
            margin: 0;
            padding: 0;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            width: 100vw;
            height: 100vh;
        }
        #action-bar {
            flex: 0 0 auto;
            padding: 8px 12px;
            background: var(--bg);
            border-bottom: 1px solid var(--border);
            z-index: 10;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        .btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 10px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 4px;
            white-space: nowrap;
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        #chart-container { flex: 1 1 auto; overflow: hidden; position: relative; }
        #chart { width: 100%; height: 100%; }
        
        .cluster-rect {
            fill: var(--container-bg);
            stroke: var(--border);
            stroke-width: 2;
            rx: 10; ry: 10;
        }
        .cluster-label {
            font-size: 12px;
            font-weight: 800;
            fill: var(--fg);
            pointer-events: none;
            text-transform: uppercase;
        }
        .node circle {
            stroke-width: 2.5;
            cursor: pointer;
        }
        .edge {
            fill: none;
            stroke-opacity: 0.3;
        }
        .legend {
            position: absolute;
            bottom: 10px; left: 10px;
            background: var(--bg);
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            font-size: 10px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            box-shadow: var(--node-shadow);
            pointer-events: none;
        }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; }
    </style>
</head>
<body>
    <div id="action-bar">
        <button class="btn" onclick="scanWorkspace()">🌐 Scan</button>
        <button class="btn btn-secondary" onclick="resetZoom()">🏠 Reset</button>
        <button class="btn btn-secondary" onclick="downloadPNG()">📥 Download PNG</button>
    </div>
    <div id="chart-container">
        <div id="chart"></div>
        <div class="legend">
            <div class="legend-item"><span class="dot" style="background:var(--tainted)"></span> Tainted Flow</div>
            <div class="legend-item"><span class="dot" style="background:var(--insecure)"></span> Insecure Flow</div>
            <div class="legend-item"><span class="dot" style="background:var(--secure)"></span> Secure Flow</div>
        </div>
    </div>

    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
        const vscodeApi = acquireVsCodeApi();
        const rawNodes = ${JSON.stringify(nodes)};
        const rawEdges = ${JSON.stringify(edges)};

        function scanWorkspace() { vscodeApi.postMessage({ command: 'scanWorkspace' }); }
        
        const zoom = d3.zoom().on("zoom", (event) => g.attr("transform", event.transform));
        function resetZoom() {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }

        function downloadPNG() {
            const svgEl = document.querySelector("#chart svg");
            const serializer = new XMLSerializer();
            const source = '<?xml version="1.0" standalone="no"?>\\r\\n' + serializer.serializeToString(svgEl);
            
            const canvas = document.createElement("canvas");
            const bbox = svgEl.getBoundingClientRect();
            canvas.width = bbox.width * 2; // High res
            canvas.height = bbox.height * 2;
            const ctx = canvas.getContext("2d");
            ctx.scale(2, 2);
            
            const img = new Image();
            const svgBlob = new Blob([source], {type: "image/svg+xml;charset=utf-8"});
            const url = URL.createObjectURL(svgBlob);
            
            img.onload = function() {
                ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--bg");
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.drawImage(img, 0, 0);
                const pngUrl = canvas.toDataURL("image/png");
                vscodeApi.postMessage({ command: 'downloadPNG', data: pngUrl });
                URL.revokeObjectURL(url);
            };
            img.src = url;
        }

        // --- D3 Graph Logic ---
        const width = window.innerWidth;
        const height = Math.max(800, rawNodes.length * 40); // Vertical space scaling

        const svg = d3.select("#chart").append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", [0, 0, width, height])
            .call(zoom);

        const g = svg.append("g");

        // Structured Hierarchical Layout
        const files = d3.groups(rawNodes, d => d.filePath)
            .sort((a, b) => a[0].localeCompare(b[0]));
            
        const nodes = rawNodes.map(d => ({ ...d }));
        
        // Define Cluster Regions
        const clusterMap = new Map();
        files.forEach((f, i) => {
            clusterMap.set(f[0], {
                y: (i + 0.5) * (height / files.length),
                x: width / 2,
                nodes: f[1]
            });
        });

        // Compute bundles
        const bundles = new Map();
        const internalEdges = [];
        rawEdges.forEach(e => {
            const source = nodes.find(n => n.id === e.from);
            const target = nodes.find(n => n.id === e.to);
            if (!source || !target) return;

            if (source.filePath === target.filePath) {
                internalEdges.push({ ...e, source, target });
            } else {
                const bundleId = source.filePath < target.filePath ? 
                    source.filePath + "->" + target.filePath : 
                    target.filePath + "->" + source.filePath;
                if (!bundles.has(bundleId)) {
                    bundles.set(bundleId, {
                        id: bundleId, fileA: source.filePath, fileB: target.filePath,
                        count: 0, tainted: false
                    });
                }
                const b = bundles.get(bundleId);
                b.count++;
                if (e.tainted) b.tainted = true;
            }
        });

        // simulation logic
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(internalEdges).id(d => d.id).distance(100).strength(0.5))
            .force("charge", d3.forceManyBody().strength(-200))
            .force("y", d3.forceY().y(d => clusterMap.get(d.filePath).y).strength(2))
            .force("x", d3.forceX().x(d => {
                // Hierarchical Source -> Sink flow
                if (d.type === 'DataStore') return width * 0.7; // Sinks on right
                if (d.label.toLowerCase().includes('key') || d.label.toLowerCase().includes('secret')) return width * 0.3; // Sources on left
                return width * 0.5;
            }).strength(1))
            .force("collision", d3.forceCollide().radius(40))
            .alphaDecay(0.05); // Cool down fast

        // Draw clusters
        const clusters = g.append("g").selectAll("g").data(files).join("g");
        
        clusters.append("rect").attr("class", "cluster-rect");
        clusters.append("text").attr("class", "cluster-label")
            .text(d => d[0].split(/[\\\\/]/).pop().replace(/\\.(ts|js|tsx|jsx)$/, ''));

        // Draw bundle edges
        const bundleLinks = g.append("g").selectAll("line").data(Array.from(bundles.values())).join("line")
            .attr("stroke", d => d.tainted ? "var(--tainted)" : "var(--border)")
            .attr("stroke-width", d => Math.min(8, 2 + d.count))
            .attr("stroke-dasharray", "4,4")
            .attr("opacity", 0.4);

        // Draw internal edges
        const internalLinks = g.append("g").selectAll("path").data(internalEdges).join("path")
            .attr("fill", "none")
            .attr("stroke", d => d.tainted ? "var(--tainted)" : (d.secure ? "var(--secure)" : "var(--insecure)"))
            .attr("stroke-width", d => d.tainted ? 3 : 1.5)
            .attr("opacity", 0.8);

        // Draw nodes
        const node = g.append("g").selectAll("g").data(nodes).join("g")
            .attr("class", "node")
            .on("click", (event, d) => {
                vscodeApi.postMessage({ command: 'jumpToCode', filePath: d.filePath, line: d.line, character: d.character });
            });

        node.append("circle")
            .attr("r", d => d.type === 'DataStore' ? 12 : 9)
            .attr("fill", d => d.type === 'DataStore' ? "var(--vscode-charts-blue)" : "var(--vscode-charts-purple)")
            .attr("stroke", "var(--bg)")
            .attr("stroke-width", 2);

        node.append("text")
            .attr("dy", 20).attr("text-anchor", "middle").attr("font-size", "10px").attr("fill", "var(--fg)")
            .text(d => d.label);

        simulation.on("tick", () => {
            internalLinks.attr("d", d => {
                const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y, dr = Math.sqrt(dx * dx + dy * dy);
                return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
            });

            bundleLinks
                .attr("x1", d => d3.mean(nodes.filter(n => n.filePath === d.fileA), n => n.x))
                .attr("y1", d => d3.mean(nodes.filter(n => n.filePath === d.fileA), n => n.y))
                .attr("x2", d => d3.mean(nodes.filter(n => n.filePath === d.fileB), n => n.x))
                .attr("y2", d => d3.mean(nodes.filter(n => n.filePath === d.fileB), n => n.y));

            node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");

            clusters.each(function(d) {
                const fileNodes = nodes.filter(n => n.filePath === d[0]);
                if (fileNodes.length === 0) return;
                const minX = d3.min(fileNodes, n => n.x) - 30, minY = d3.min(fileNodes, n => n.y) - 40;
                const maxX = d3.max(fileNodes, n => n.x) + 30, maxY = d3.max(fileNodes, n => n.y) + 20;
                d3.select(this).select("rect").attr("x", minX).attr("y", minY).attr("width", Math.max(100, maxX - minX)).attr("height", Math.max(60, maxY - minY));
                d3.select(this).select("text").attr("x", minX + 10).attr("y", minY + 18);
            });
        });

        window.addEventListener('resize', () => {
            svg.attr("viewBox", [0, 0, window.innerWidth, window.innerHeight]);
        });
    </script>
</body>
</html>`;
    }
}
