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
            }
        });

        webviewView.webview.html = this._getEmptyHtml();
    }

    public update(graph: FlowGraph): void {
        if (!this._view) return;
        this._view.webview.html = this._getHtmlForWebview(graph);
        this._view.description = `Scanned ${new Date().toLocaleTimeString()}`;
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
            overflow: hidden;
            width: 100vw;
            height: 100vh;
        }
        #action-bar {
            position: absolute;
            top: 0; left: 0; right: 0;
            padding: 10px;
            background: var(--bg);
            border-bottom: 1px solid var(--border);
            z-index: 10;
            display: flex;
            gap: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        .btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            padding: 6px 14px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        #chart { width: 100%; height: 100%; }
        .cluster-rect {
            fill: var(--container-bg);
            stroke: var(--border);
            stroke-width: 2;
            rx: 12; ry: 12;
            filter: drop-shadow(0 4px 12px rgba(0,0,0,0.25));
        }
        .cluster-header {
            fill: var(--vscode-sideBar-background);
            opacity: 0.5;
            pointer-events: none;
        }
        .cluster-label {
            font-size: 13px;
            font-weight: 800;
            fill: var(--fg);
            pointer-events: none;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .node circle {
            stroke-width: 2.5;
            cursor: pointer;
            transition: r 0.2s, stroke-width 0.2s;
        }
        .node:hover circle { r: 14; stroke-width: 4; }
        .edge {
            fill: none;
            stroke-opacity: 0.4;
            transition: stroke-opacity 0.2s;
        }
        .edge:hover { stroke-opacity: 0.9; }
        .edge-label {
            font-size: 10px;
            font-weight: 600;
            fill: var(--fg);
            pointer-events: none;
            background: var(--bg);
        }
        .legend {
            position: absolute;
            bottom: 16px; right: 16px;
            background: var(--bg);
            padding: 10px 14px;
            border-radius: 8px;
            border: 1px solid var(--border);
            font-size: 11px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            box-shadow: var(--node-shadow);
            backdrop-filter: blur(4px);
        }
        .legend-item { display: flex; align-items: center; gap: 8px; font-weight: 500; }
        .dot { width: 10px; height: 10px; border-radius: 50%; border: 1px solid rgba(255,255,255,0.2); }
    </style>
</head>
<body>
    <div id="action-bar">
        <button class="btn" onclick="scanWorkspace()">🌐 Scan Entire Workspace</button>
        <button class="btn btn-secondary" onclick="resetZoom()">🏠 Reset View</button>
    </div>
    <div id="chart"></div>
    <div class="legend">
        <div class="legend-item"><span class="dot" style="background:var(--tainted)"></span> Tainted Flow (High Risk)</div>
        <div class="legend-item"><span class="dot" style="background:var(--insecure)"></span> Insecure Pattern</div>
        <div class="legend-item"><span class="dot" style="background:var(--secure)"></span> Secure Reference</div>
    </div>

    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
        const vscodeApi = acquireVsCodeApi();
        const rawNodes = ${JSON.stringify(nodes)};
        const rawEdges = ${JSON.stringify(edges)};

        function scanWorkspace() { vscodeApi.postMessage({ command: 'scanWorkspace' }); }
        
        const zoom = d3.zoom().on("zoom", (event) => g.attr("transform", event.transform));
        function resetZoom() {
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity
            );
        }

        // --- D3 Graph Logic ---
        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#chart").append("svg")
            .attr("viewBox", [0, 0, width, height])
            .call(zoom);

        const g = svg.append("g");

        // Group nodes by file
        const files = d3.groups(rawNodes, d => d.filePath);
        
        const nodes = rawNodes.map(d => ({ ...d }));
        
        // Compute bundles for cross-file edges
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
                        id: bundleId,
                        fileA: source.filePath,
                        fileB: target.filePath,
                        count: 0,
                        tainted: false
                    });
                }
                const b = bundles.get(bundleId);
                b.count++;
                if (e.tainted) b.tainted = true;
            }
        });

        // Clustering simulation
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(internalEdges).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-600))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("x", d3.forceX().x(d => {
                const fileIndex = files.findIndex(f => f[0] === d.filePath);
                return (width / (files.length + 1)) * (fileIndex + 1);
            }).strength(1.5))
            .force("y", d3.forceY().y(height / 2).strength(0.3))
            .force("collision", d3.forceCollide().radius(60));

        // Draw cross-file bundle lines
        const bundleLinks = g.append("g")
            .selectAll("line")
            .data(Array.from(bundles.values()))
            .join("line")
            .attr("stroke", d => d.tainted ? "var(--tainted)" : "var(--border)")
            .attr("stroke-width", d => Math.min(10, 3 + d.count))
            .attr("stroke-dasharray", d => d.tainted ? "0" : "6,4")
            .attr("opacity", 0.3)
            .style("cursor", "help");

        const bundleLabels = g.append("g")
            .selectAll("text")
            .data(Array.from(bundles.values()))
            .join("text")
            .attr("font-size", "11px")
            .attr("font-weight", "bold")
            .attr("fill", "var(--fg)")
            .attr("text-anchor", "middle")
            .text(d => d.count + " flows");

        // Draw internal edges
        const internalLinks = g.append("g")
            .selectAll("path")
            .data(internalEdges)
            .join("path")
            .attr("fill", "none")
            .attr("stroke", d => d.tainted ? "var(--tainted)" : (d.secure ? "var(--secure)" : "var(--insecure)"))
            .attr("stroke-width", d => d.tainted ? 4 : 2)
            .attr("opacity", 0.7);

        // Draw containers (files)
        const clusters = g.append("g")
            .selectAll("g")
            .data(files)
            .join("g")
            .style("cursor", "zoom-in")
            .on("dblclick", (event, d) => {
                const fileNodes = nodes.filter(n => n.filePath === d[0]);
                const minX = d3.min(fileNodes, n => n.x);
                const maxX = d3.max(fileNodes, n => n.x);
                const minY = d3.min(fileNodes, n => n.y);
                const maxY = d3.max(fileNodes, n => n.y);
                
                const midX = (minX + maxX) / 2;
                const midY = (minY + maxY) / 2;
                const scale = Math.min(3, 0.7 / Math.max((maxX - minX) / width, (maxY - minY) / height));

                svg.transition().duration(750).call(
                    zoom.transform,
                    d3.zoomIdentity.translate(width/2, height/2).scale(scale).translate(-midX, -midY)
                );
            });

        clusters.append("rect")
            .attr("class", "cluster-rect");

        clusters.append("text")
            .attr("class", "cluster-label")
            .text(d => d[0].split(/[\\\\/]/).pop());

        // Draw nodes
        const node = g.append("g")
            .selectAll("g")
            .data(nodes)
            .join("g")
            .attr("class", "node")
            .on("click", (event, d) => {
                vscodeApi.postMessage({
                    command: 'jumpToCode',
                    filePath: d.filePath,
                    line: d.line,
                    character: d.character
                });
            });

        node.append("circle")
            .attr("r", d => d.type === 'DataStore' ? 14 : 11)
            .attr("fill", d => d.type === 'DataStore' ? "var(--vscode-charts-blue)" : "var(--vscode-charts-purple)")
            .attr("stroke", "var(--bg)")
            .attr("stroke-width", d => d.type === 'DataStore' ? 4 : 2.5);

        node.append("text")
            .attr("dy", d => d.type === 'DataStore' ? 26 : 24)
            .attr("text-anchor", "middle")
            .attr("font-size", "11px")
            .attr("font-weight", 700)
            .attr("fill", "var(--fg)")
            .text(d => d.label);

        simulation.on("tick", () => {
            // Update bundle lines
            bundleLinks
                .attr("x1", d => {
                    const nodesA = nodes.filter(n => n.filePath === d.fileA);
                    return d3.mean(nodesA, n => n.x);
                })
                .attr("y1", d => {
                    const nodesA = nodes.filter(n => n.filePath === d.fileA);
                    return d3.mean(nodesA, n => n.y);
                })
                .attr("x2", d => {
                    const nodesB = nodes.filter(n => n.filePath === d.fileB);
                    return d3.mean(nodesB, n => n.x);
                })
                .attr("y2", d => {
                    const nodesB = nodes.filter(n => n.filePath === d.fileB);
                    return d3.mean(nodesB, n => n.y);
                });

            bundleLabels
                .attr("x", d => {
                    const nodesA = nodes.filter(n => n.filePath === d.fileA);
                    const nodesB = nodes.filter(n => n.filePath === d.fileB);
                    return (d3.mean(nodesA, n => n.x) + d3.mean(nodesB, n => n.x)) / 2;
                })
                .attr("y", d => {
                    const nodesA = nodes.filter(n => n.filePath === d.fileA);
                    const nodesB = nodes.filter(n => n.filePath === d.fileB);
                    return (d3.mean(nodesA, n => n.y) + d3.mean(nodesB, n => n.y)) / 2 - 15;
                });

            // Update internal path edges
            internalLinks.attr("d", d => {
                const dx = d.target.x - d.source.x;
                const dy = d.target.y - d.source.y;
                const dr = Math.sqrt(dx * dx + dy * dy) * 0.8; // Slightly more curved
                return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
            });

            node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");

            clusters.each(function(d) {
                const fileNodes = nodes.filter(n => n.filePath === d[0]);
                if (fileNodes.length === 0) return;
                
                const minX = d3.min(fileNodes, n => n.x) - 40;
                const minY = d3.min(fileNodes, n => n.y) - 60;
                const maxX = d3.max(fileNodes, n => n.x) + 40;
                const maxY = d3.max(fileNodes, n => n.y) + 40;
                
                d3.select(this).select("rect")
                    .attr("x", minX)
                    .attr("y", minY)
                    .attr("width", Math.max(120, maxX - minX))
                    .attr("height", Math.max(80, maxY - minY));
                
                d3.select(this).select("text")
                    .attr("x", minX + 15)
                    .attr("y", minY + 25);
            });
        });

        window.addEventListener('resize', () => {
            const w = window.innerWidth, h = window.innerHeight;
            svg.attr("viewBox", [0, 0, w, h]);
        });
    </script>
</body>
</html>`;
    }
}
