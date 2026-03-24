import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { FlowGraph } from './FlowGraph';
import { Scanner } from './Scanner';
import { DFDWebview } from './DFDWebview';
import { ThreatAnalyzer } from './ThreatAnalyzer';
import { ThreatReportProvider } from './ThreatReportProvider';
import { ReportGenerator } from './ReportGenerator';

let diagnosticCollection: vscode.DiagnosticCollection;
let ghostflowOutputChannel: vscode.OutputChannel;

/**
 * Activates the extension. Called when onStartupFinished is fired.
 */
export function activate(context: vscode.ExtensionContext) {
    ghostflowOutputChannel = vscode.window.createOutputChannel('Ghostflow Logs');
    diagnosticCollection = vscode.languages.createDiagnosticCollection('ghostflow');

    context.subscriptions.push(ghostflowOutputChannel, diagnosticCollection);

    const graph = new FlowGraph();
    const scanner = new Scanner(graph);
    const threatAnalyzer = new ThreatAnalyzer();

    // Register the Threat Report sidebar provider
    const threatReportProvider = new ThreatReportProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            ThreatReportProvider.viewType,
            threatReportProvider
        )
    );

    const reportGenerator = new ReportGenerator();

    // Wire the "Generate PDF Report" button callback
    threatReportProvider.onGenerateReport(async () => {
        const threats = threatAnalyzer.analyze(graph);
        if (threats.length === 0) {
            vscode.window.showWarningMessage('Ghostflow: No threats to report. Scan a file first.');
            return;
        }

        const activeFile = vscode.window.activeTextEditor?.document.fileName ?? 'Unknown';
        const fileName = path.basename(activeFile);

        try {
            const pdfBuffer = reportGenerator.generate(threats, fileName);

            // Determine save path in workspace folder
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            const saveDir = workspaceFolder ?? path.dirname(activeFile);
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
            const pdfFileName = `ghostflow-report-${timestamp}.pdf`;
            const pdfPath = path.join(saveDir, pdfFileName);

            fs.writeFileSync(pdfPath, pdfBuffer);

            const openAction = await vscode.window.showInformationMessage(
                `Ghostflow: Report saved to ${pdfFileName}`,
                'Open File',
                'Open Folder'
            );

            if (openAction === 'Open File') {
                vscode.env.openExternal(vscode.Uri.file(pdfPath));
            } else if (openAction === 'Open Folder') {
                vscode.env.openExternal(vscode.Uri.file(saveDir));
            }

            ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] PDF report saved: ${pdfPath}`);
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Ghostflow Report Generation Failed: ${msg}`);
            ghostflowOutputChannel.appendLine(`Error generating report: ${msg}`);
        }
    });

    // Command to manually perform a scan
    const scanCommand = vscode.commands.registerCommand('ghostflow.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            await performScan(editor.document, scanner, graph, threatAnalyzer, threatReportProvider);
        } else {
            vscode.window.showErrorMessage('Ghostflow: No active text editor found to scan.');
        }
    });

    const showVisualizerCommand = vscode.commands.registerCommand('ghostflow.showVisualizer', () => {
        DFDWebview.createOrShow(context.extensionUri);
        if (graph.getNodes().length > 0 && DFDWebview.currentPanel) {
            DFDWebview.currentPanel.update(graph);
        }
    });

    // Event listener for live sync on save
    const onSaveEvent = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === 'typescript' || document.languageId === 'javascript') {
            await performScan(document, scanner, graph, threatAnalyzer, threatReportProvider);
        }
    });

    context.subscriptions.push(scanCommand, showVisualizerCommand, onSaveEvent);
    
    // Automatically trigger scan on the currently active document if it's TS/JS
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (doc.languageId === 'typescript' || doc.languageId === 'javascript') {
            performScan(doc, scanner, graph, threatAnalyzer, threatReportProvider);
        }
    }
}

/**
 * Performs the actual security scan on a document and updates all UI elements:
 * diagnostics, DFD visualizer, and STRIDE threat report sidebar.
 */
async function performScan(
    document: vscode.TextDocument,
    scanner: Scanner,
    graph: FlowGraph,
    threatAnalyzer: ThreatAnalyzer,
    threatReportProvider: ThreatReportProvider
): Promise<void> {
    ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Scanning ${document.fileName}...`);
    
    try {
        await scanner.scanDocument(document);
        
        const nodes = graph.getNodes();
        const diagnostics: vscode.Diagnostic[] = [];

        nodes.forEach(node => {
            const startPos = new vscode.Position(node.line, node.character);
            const endPos = new vscode.Position(node.line, node.character + 10);
            const range = new vscode.Range(startPos, endPos);

            const diagnostic = new vscode.Diagnostic(
                range,
                `Ghostflow Boundary [${node.type}]: ${node.label} - ${node.description}`,
                vscode.DiagnosticSeverity.Warning
            );
            diagnostics.push(diagnostic);
            ghostflowOutputChannel.appendLine(`Found boundary: ${node.label} at line ${node.line + 1}`);
        });

        diagnosticCollection.set(document.uri, diagnostics);
        ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Scan complete. Found ${nodes.length} trust boundaries / insecure patterns.`);

        // Update DFD Visualizer
        if (DFDWebview.currentPanel) {
            DFDWebview.currentPanel.update(graph);
        }

        // Update STRIDE Threat Report sidebar
        const threats = threatAnalyzer.analyze(graph);
        threatReportProvider.updateThreats(threats);
        ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Threat analysis complete. Found ${threats.length} STRIDE threats.`);
    } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Ghostflow Scan Failed: ${msg}`);
        ghostflowOutputChannel.appendLine(`Error during scan: ${msg}`);
    }
}

/**
 * Deactivates the extension.
 */
export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (ghostflowOutputChannel) {
        ghostflowOutputChannel.dispose();
    }
}
