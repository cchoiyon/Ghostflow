import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { FlowGraph } from './FlowGraph';
import { Scanner } from './Scanner';
import { ProjectScanner } from './ProjectScanner';
import { VisualizerProvider } from './VisualizerProvider';
import { ThreatAnalyzer, ThreatSeverity } from './ThreatAnalyzer';
import { ThreatReportProvider } from './ThreatReportProvider';
import { ReportGenerator } from './ReportGenerator';

let diagnosticCollection: vscode.DiagnosticCollection;
let ghostflowOutputChannel: vscode.OutputChannel;
let healthStatusBar: vscode.StatusBarItem;

/**
 * Activates the extension. Called when onStartupFinished is fired.
 * Registers both sidebar providers, status bar, and global event listeners.
 */
export function activate(context: vscode.ExtensionContext) {
    ghostflowOutputChannel = vscode.window.createOutputChannel('Ghostflow Logs');
    diagnosticCollection = vscode.languages.createDiagnosticCollection('ghostflow');

    context.subscriptions.push(ghostflowOutputChannel, diagnosticCollection);

    const graph = new FlowGraph();
    const projectScanner = new ProjectScanner();
    const scanner = new Scanner(graph, projectScanner);
    const threatAnalyzer = new ThreatAnalyzer();
    const reportGenerator = new ReportGenerator();

    // Scan workspace for cross-file sensitive exports on activation
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceRoot) {
        projectScanner.scanWorkspace(workspaceRoot).then(() => {
            ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Project scan complete. Cross-file taint cache built.`);
        });
    }

    // --- Register Sidebar Providers ---
    const visualizerProvider = new VisualizerProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            VisualizerProvider.viewType,
            visualizerProvider
        )
    );

    const threatReportProvider = new ThreatReportProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            ThreatReportProvider.viewType,
            threatReportProvider
        )
    );

    // --- Status Bar: Security Health Score ---
    healthStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    healthStatusBar.command = 'ghostflow.scan';
    healthStatusBar.text = '$(shield) Ghostflow';
    healthStatusBar.tooltip = 'Ghostflow Security Health — click to scan';
    healthStatusBar.show();
    context.subscriptions.push(healthStatusBar);

    // --- PDF Report Button Callback ---
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

    // --- Manual Scan Commands ---
    const scanCommand = vscode.commands.registerCommand('ghostflow.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            await performScan(editor.document, scanner, graph, threatAnalyzer, visualizerProvider, threatReportProvider);
        } else {
            vscode.window.showErrorMessage('Ghostflow: No active text editor found to scan.');
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('ghostflow.scanWorkspace', async () => {
        await performWorkspaceScan(scanner, graph, threatAnalyzer, visualizerProvider, threatReportProvider);
    });

    // --- Global Auto-Refresh on Save ---
    const onSaveEvent = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === 'typescript' || document.languageId === 'javascript') {
            // Incrementally update the cross-file cache for just the saved file
            await projectScanner.updateFile(document.fileName);
            await performScan(document, scanner, graph, threatAnalyzer, visualizerProvider, threatReportProvider);
        }
    });

    context.subscriptions.push(scanCommand, scanWorkspaceCommand, onSaveEvent);

    // Automatically trigger scan on the currently active document
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (doc.languageId === 'typescript' || doc.languageId === 'javascript') {
            performScan(doc, scanner, graph, threatAnalyzer, visualizerProvider, threatReportProvider);
        }
    }
}

/**
 * Performs the actual security scan on a document and updates all UI elements:
 * diagnostics, sidebar visualizer, STRIDE threat report, and status bar health score.
 */
async function performScan(
    document: vscode.TextDocument,
    scanner: Scanner,
    graph: FlowGraph,
    threatAnalyzer: ThreatAnalyzer,
    visualizerProvider: VisualizerProvider,
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
        ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Scan complete. Found ${nodes.length} trust boundaries.`);

        // Update Sidebar Visualizer
        visualizerProvider.update(graph);

        // Update STRIDE Threat Report
        const threats = threatAnalyzer.analyze(graph);
        threatReportProvider.updateThreats(threats);

        // Update Status Bar Health Score
        const critical = threats.filter(t => t.severity === ThreatSeverity.Critical).length;
        const high = threats.filter(t => t.severity === ThreatSeverity.High).length;
        const riskCount = critical + high;

        if (riskCount > 0) {
            healthStatusBar.text = `$(shield) ${riskCount} High Risk${riskCount > 1 ? 's' : ''}`;
            healthStatusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else if (threats.length > 0) {
            healthStatusBar.text = `$(shield) ${threats.length} Finding${threats.length > 1 ? 's' : ''}`;
            healthStatusBar.backgroundColor = undefined;
        } else {
            healthStatusBar.text = '$(shield) Secure';
            healthStatusBar.backgroundColor = undefined;
        }

        ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Threat analysis complete. ${threats.length} findings, ${riskCount} high-risk.`);
    } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Ghostflow Scan Failed: ${msg}`);
        ghostflowOutputChannel.appendLine(`Error during scan: ${msg}`);
    }
}

/**
 * Performs a massive batch scan across all TypeScript/JavaScript files in the workspace.
 * Uses the VS Code Progress API to display a loading bar and yields execution
 * to avoid blocking the main UI thread.
 */
async function performWorkspaceScan(
    scanner: Scanner,
    graph: FlowGraph,
    threatAnalyzer: ThreatAnalyzer,
    visualizerProvider: VisualizerProvider,
    threatReportProvider: ThreatReportProvider
): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('Ghostflow: No workspace folder open.');
        return;
    }

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Ghostflow",
        cancellable: true
    }, async (progress, token) => {
        progress.report({ message: "Discovering files..." });
        
        // Find all TS/JS files, ignoring node_modules and dist
        const uris = await vscode.workspace.findFiles('**/*.{ts,js}', '{**/node_modules/**,**/dist/**,**/.git/**}');
        
        if (uris.length === 0) {
            vscode.window.showInformationMessage('Ghostflow: No TypeScript or JavaScript files found.');
            return;
        }

        const documents: vscode.TextDocument[] = [];
        
        for (let i = 0; i < uris.length; i++) {
            if (token.isCancellationRequested) {
                ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Workspace scan cancelled by user.`);
                return;
            }

            // Yield to event loop to keep UI responsive while opening documents
            await new Promise(resolve => setImmediate(resolve));
            
            try {
                const doc = await vscode.workspace.openTextDocument(uris[i]);
                documents.push(doc);
                const percent = Math.floor((i / uris.length) * 50);
                progress.report({ increment: percent, message: `Loading ${path.basename(doc.fileName)}...` });
            } catch (err) {
                ghostflowOutputChannel.appendLine(`Failed to open document: ${uris[i].fsPath}`);
            }
        }

        progress.report({ message: "Analyzing ASTs and tracking deep data flows globally...", increment: 50 });
        
        try {
            const startTime = Date.now();
            await scanner.scanDocuments(documents);
            
            progress.report({ message: "Generating global architecture map...", increment: 90 });
            
            const nodes = graph.getNodes();
            const threats = threatAnalyzer.analyze(graph);
            
            // Update Sidebar Visualizer and Report
            visualizerProvider.update(graph);
            threatReportProvider.updateThreats(threats);
            
            const critical = threats.filter(t => t.severity === ThreatSeverity.Critical).length;
            const high = threats.filter(t => t.severity === ThreatSeverity.High).length;
            const riskCount = critical + high;

            if (riskCount > 0) {
                healthStatusBar.text = `$(shield) Global: ${riskCount} High Risk${riskCount > 1 ? 's' : ''}`;
                healthStatusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            } else if (threats.length > 0) {
                healthStatusBar.text = `$(shield) Global: ${threats.length} Finding${threats.length > 1 ? 's' : ''}`;
                healthStatusBar.backgroundColor = undefined;
            } else {
                healthStatusBar.text = '$(shield) Global Secure';
                healthStatusBar.backgroundColor = undefined;
            }

            const timeTaken = ((Date.now() - startTime) / 1000).toFixed(2);
            ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Global workspace scan complete in ${timeTaken}s. Found ${nodes.length} boundaries and ${threats.length} findings across ${documents.length} files.`);
            
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Ghostflow Global Scan Failed: ${msg}`);
            ghostflowOutputChannel.appendLine(`Error during global scan: ${msg}`);
        }
    });
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
