import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { FlowNode, FlowEdge } from '../core/FlowGraph';
import { ThreatEntry, ThreatSeverity } from '../core/ThreatAnalyzer';

/**
 * Resolves the path to a readable d3.min.js file using the extension's URI.
 * Prefers /media/d3.min.js; falls back to node_modules.
 * @param extensionUri - The extension's base URI from context.extensionUri.
 * @returns Absolute path to the d3.min.js file.
 * @throws If neither location contains a readable d3.min.js.
 */
function resolveD3Path(extensionUri: vscode.Uri): string {
    const mediaPath = vscode.Uri.joinPath(extensionUri, 'media', 'd3.min.js').fsPath;
    if (fs.existsSync(mediaPath)) return mediaPath;
    const nmPath = vscode.Uri.joinPath(extensionUri, 'node_modules', 'd3', 'dist', 'd3.min.js').fsPath;
    if (fs.existsSync(nmPath)) return nmPath;
    throw new Error('Cannot locate d3.min.js in /media or node_modules/d3/dist. Run npm install first.');
}

/**
 * Maps a ThreatSeverity enum value to the lowercase string used in CSS badge classes.
 * @param severity - ThreatSeverity enum value from ThreatAnalyzer.
 * @returns Lowercase severity string for badge class suffix.
 */
function severityClass(severity: ThreatSeverity): string {
    switch (severity) {
        case ThreatSeverity.Critical: return 'critical';
        case ThreatSeverity.High: return 'high';
        case ThreatSeverity.Medium: return 'medium';
        case ThreatSeverity.Low: return 'low';
        default: return 'low';
    }
}

/**
 * Builds the <tbody> rows for the Threat Findings table.
 * All values are concatenated as strings — no innerHTML or DOM is used anywhere.
 * @param threats - Array of ThreatEntry objects from ThreatAnalyzer.
 * @returns HTML string of <tr> elements for the threat table.
 */
function buildThreatTableRows(threats: ThreatEntry[]): string {
    if (threats.length === 0) {
        return '<tr><td colspan="7" style="text-align:center;color:#555;padding:24px;">No threat findings.</td></tr>';
    }
    return threats.map(t => {
        const sev = severityClass(t.severity);
        const cweId = t.cweId;
        const cweNum = cweId.replace('CWE-', '');
        const cweName = t.cweName;
        const owaspCat = t.owaspCategory;
        const remediation = t.remediation;
        const basename = path.basename(t.filePath);
        const lineNum = t.line + 1; // convert 0-indexed to 1-indexed for display

        return (
            '<tr>' +
            '<td><span class="badge badge-' + sev + '">' + t.severity.toUpperCase() + '</span></td>' +
            '<td><a class="cwe-link" href="https://cwe.mitre.org/data/definitions/' + cweNum + '.html" target="_blank">' + cweId + '</a></td>' +
            '<td>' + cweName + '</td>' +
            '<td>' + owaspCat + '</td>' +
            '<td class="file-path">' + basename + ':' + lineNum + '</td>' +
            '<td>' + lineNum + '</td>' +
            '<td class="remediation">' + remediation + '</td>' +
            '</tr>'
        );
    }).join('\n');
}

/**
 * Builds collapsible <details> blocks grouping ThreatEntry objects by file path.
 * One <details> block per unique file. All values are string-concatenated — no innerHTML.
 * @param threats - Array of ThreatEntry objects from ThreatAnalyzer.
 * @returns HTML string of <details> elements, one per file.
 */
function buildFindingsByFile(threats: ThreatEntry[]): string {
    if (threats.length === 0) {
        return '<p style="color:#555;font-size:13px;">No findings.</p>';
    }

    const byFile = threats.reduce<Record<string, ThreatEntry[]>>((acc, t) => {
        if (!acc[t.filePath]) acc[t.filePath] = [];
        acc[t.filePath].push(t);
        return acc;
    }, {});

    return Object.entries(byFile).map(([file, entries]) => {
        const count = entries.length;
        const basename = path.basename(file);
        const innerRows = entries.map(e => {
            const cweId = e.cweId;
            const cweName = e.cweName;
            const owasp = e.owaspCategory;
            const rem = e.remediation;
            const lineNum = e.line + 1;
            return (
                '<strong>[' + cweId + '] ' + cweName + '</strong> — Line ' + lineNum + '<br>' +
                'OWASP: ' + owasp + '<br>' +
                'Remediation: ' + rem + '<br><br>'
            );
        }).join('');

        return (
            '<details>' +
            '<summary>' + basename + ' — ' + count + ' finding' + (count > 1 ? 's' : '') + '</summary>' +
            '<div class="finding-detail">' + innerRows + '</div>' +
            '</details>'
        );
    }).join('\n');
}

/**
 * Exports a complete self-contained HTML audit report to the workspace root.
 * Reads the report template from disk, inlines D3.js, replaces all {{PLACEHOLDER}}
 * tokens with live scan data, and writes the file. Shows a VS Code notification on
 * success or failure — never swallows errors silently.
 *
 * @param nodes   - Array of FlowNode objects from graph.getNodes().
 * @param edges   - Array of FlowEdge objects from graph.getEdges().
 * @param threats - Array of ThreatEntry objects from ThreatAnalyzer.analyze().
 */
export async function exportHtmlReport(
    nodes: FlowNode[],
    edges: FlowEdge[],
    threats: ThreatEntry[],
    extensionUri: vscode.Uri
): Promise<void> {
    try {
        // ── Resolve paths ───────────────────────────────────────────────────
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceRoot) {
            vscode.window.showErrorMessage('Ghostflow: Report export failed — no workspace folder is open.');
            return;
        }

        // ── Read template from disk using extensionUri ──────────────────────
        const templatePath = vscode.Uri.joinPath(extensionUri, 'src', 'export', 'reportTemplate.html').fsPath;
        let template: string;
        try {
            template = await fs.promises.readFile(templatePath, 'utf8');
        } catch {
            // Fall back to sibling path if running from out/
            const fallbackPath = path.join(path.dirname(templatePath), '..', '..', 'src', 'export', 'reportTemplate.html');
            template = await fs.promises.readFile(fallbackPath, 'utf8');
        }

        // ── Read D3 from disk for offline embedding ──────────────────────────
        const d3Path = resolveD3Path(extensionUri);
        const d3Library = await fs.promises.readFile(d3Path, 'utf8');

        // ── Compute summary values ──────────────────────────────────────────
        const workspaceName = vscode.workspace.name ?? 'Unknown Workspace';
        const timestamp = new Date().toLocaleString();
        const countCritical = threats.filter(t => t.severity === ThreatSeverity.Critical).length;
        const countHigh = threats.filter(t => t.severity === ThreatSeverity.High).length;
        const countMedium = threats.filter(t => t.severity === ThreatSeverity.Medium).length;
        const countLow = threats.filter(t => t.severity === ThreatSeverity.Low).length;
        const countTainted = edges.filter(e => e.tainted).length;
        const countSanitized = 0; // FlowEdge has no sanitized flag — reserved for future use
        const countFiles = new Set(nodes.map(n => n.filePath)).size;

        // ── Build dynamic HTML sections ────────────────────────────────────
        const tableRows = buildThreatTableRows(threats);
        const byFileBlocks = buildFindingsByFile(threats);

        // ── Transform data for D3 graph compatibility ──────────────────────
        // FlowNode has no riskLevel or nodeType — derive both for D3 symbol rendering.
        const severityRank: Record<string, number> = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
        const severityLabel: Record<number, string> = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' };

        // Pre-compute sets for nodeType derivation
        const sinkNodeIds = new Set(edges.filter(e => e.tainted).map(e => e.to));
        const sourceNodeIds = new Set(edges.filter(e => e.tainted).map(e => e.from));

        /**
         * Derives the semantic nodeType (source/sink/sanitizer/sdk/logic) from a FlowNode.
         * Uses FlowNode.type, label, description, and edge context to classify.
         * @param n - The FlowNode to classify.
         * @returns A nodeType string for D3 symbol rendering.
         */
        function deriveNodeType(n: FlowNode): string {
            const lbl = (n.label + ' ' + n.description).toLowerCase();
            if (lbl.includes('sanitiz')) return 'sanitizer';
            if (lbl.includes('sdk') || lbl.includes('3rd-party') || lbl.includes('third-party')) return 'sdk';
            if (n.type === 'DataStore' || sourceNodeIds.has(n.id)) return 'source';
            if (sinkNodeIds.has(n.id)) return 'sink';
            return 'logic';
        }

        const graphNodes = nodes.map(n => {
            const nodeThreats = threats.filter(t =>
                t.filePath === n.filePath && t.line === n.line
            );
            let maxRank = 0;
            for (const t of nodeThreats) {
                const rank = severityRank[t.severity] ?? 0;
                if (rank > maxRank) maxRank = rank;
            }
            return {
                ...n,
                riskLevel: severityLabel[maxRank] ?? 'safe',
                nodeType: deriveNodeType(n),
            };
        });

        // FlowEdge has from/to — D3 forceLink needs source/target
        const graphEdges = edges.map(e => ({
            ...e,
            source: e.from,
            target: e.to,
        }));

        const nodesJson = JSON.stringify(graphNodes);
        const edgesJson = JSON.stringify(graphEdges);

        // ── Replace all placeholders ───────────────────────────────────────
        // NOTE: Large content replacements (D3 library, JSON, HTML sections) MUST use the
        // function form `() => value` to prevent JavaScript's special replacement patterns
        // ($&, $', $`, $1…) from corrupting the output. d3.min.js contains `$'` sequences.
        const html = template
            .replace(/\{\{WORKSPACE_NAME\}\}/g, workspaceName)
            .replace(/\{\{TIMESTAMP\}\}/g, timestamp)
            .replace(/\{\{COUNT_CRITICAL\}\}/g, String(countCritical))
            .replace(/\{\{COUNT_HIGH\}\}/g, String(countHigh))
            .replace(/\{\{COUNT_MEDIUM\}\}/g, String(countMedium))
            .replace(/\{\{COUNT_LOW\}\}/g, String(countLow))
            .replace(/\{\{COUNT_TAINTED\}\}/g, String(countTainted))
            .replace(/\{\{COUNT_SANITIZED\}\}/g, String(countSanitized))
            .replace(/\{\{COUNT_FILES\}\}/g, String(countFiles))
            .replace(/\{\{THREATS_TABLE_ROWS\}\}/g, () => tableRows)
            .replace(/\{\{FINDINGS_BY_FILE\}\}/g, () => byFileBlocks)
            .replace(/\/\*\{\{NODES_JSON\}\}\*\/ \[\]/g, () => nodesJson)
            .replace(/\/\*\{\{EDGES_JSON\}\}\*\/ \[\]/g, () => edgesJson)
            .replace(/\{\{D3_LIBRARY\}\}/g, () => d3Library);

        // ── Write output file ──────────────────────────────────────────────
        const outputPath = path.join(workspaceRoot, 'ghostflow-report-' + Date.now() + '.html');
        await fs.promises.writeFile(outputPath, html, 'utf8');

        const action = await vscode.window.showInformationMessage(
            'Ghostflow report saved.',
            'Open Report'
        );
        if (action === 'Open Report') {
            vscode.env.openExternal(vscode.Uri.file(outputPath));
        }

    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage('Ghostflow: Report export failed — ' + msg);
        throw err; // Re-throw so callers can also observe the failure
    }
}
