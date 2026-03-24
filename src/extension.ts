import * as vscode from 'vscode';
import { FlowGraph } from './FlowGraph';
import { Scanner } from './Scanner';
import { DFDWebview } from './DFDWebview';

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

    // Command to manually perform a scan
    const scanCommand = vscode.commands.registerCommand('ghostflow.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            await performScan(editor.document, scanner, graph);
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
            await performScan(document, scanner, graph);
        }
    });

    context.subscriptions.push(scanCommand, showVisualizerCommand, onSaveEvent);
    
    // Automatically trigger scan on the currently active document if it's TS/JS
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (doc.languageId === 'typescript' || doc.languageId === 'javascript') {
            performScan(doc, scanner, graph);
        }
    }
}

/**
 * Performs the actual security scan on a document and updates UI elements.
 */
async function performScan(document: vscode.TextDocument, scanner: Scanner, graph: FlowGraph): Promise<void> {
    ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Scanning ${document.fileName}...`);
    
    try {
        await scanner.scanDocument(document);
        
        const nodes = graph.getNodes();
        const diagnostics: vscode.Diagnostic[] = [];

        nodes.forEach(node => {
            // Find the length of the matching text approximately
            const startPos = new vscode.Position(node.line, node.character);
            const endPos = new vscode.Position(node.line, node.character + 10); // Arbitrary reasonable length for AST node

            const range = new vscode.Range(startPos, endPos);

            const diagnostic = new vscode.Diagnostic(
                range,
                `Ghostflow Boundary [${node.type}]: ${node.label} - ${node.description}`,
                vscode.DiagnosticSeverity.Warning
            );
            diagnostics.push(diagnostic);
            ghostflowOutputChannel.appendLine(`Found boundary: ${node.label} at line ${node.line + 1}`);
        });

        // Set diagnostics for the file
        diagnosticCollection.set(document.uri, diagnostics);
        ghostflowOutputChannel.appendLine(`[${new Date().toLocaleTimeString()}] Scan complete. Found ${nodes.length} trust boundaries / insecure patterns.`);

        // Update Webview Graph dynamically
        if (DFDWebview.currentPanel) {
            DFDWebview.currentPanel.update(graph);
        }
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
