import * as ts from 'typescript';
import * as path from 'path';
import * as vscode from 'vscode';
import { FlowGraph, NodeType } from './FlowGraph';
import { ProjectScanner } from './ProjectScanner';

/**
 * Represents a sensitive source variable detected during AST traversal.
 * These are variables whose names suggest they contain secrets, keys, or credentials.
 */
interface SensitiveSource {
    /** The variable name as it appears in the source code. */
    varName: string;
    /** Unique node ID for the FlowGraph. */
    nodeId: string;
    /** Zero-indexed line number of the declaration. */
    line: number;
    /** Zero-indexed character offset. */
    character: number;
    /** If this source was imported from another file, the basename of that file. */
    crossFileSource?: string;
}

/** Case-insensitive patterns that identify sensitive variable names. */
const SENSITIVE_PATTERNS: ReadonlyArray<string> = [
    'key', 'secret', 'pass', 'password', 'token', 'credential', 'auth', 'apikey'
];

/** Function names considered dangerous sinks for taint analysis. */
const DANGEROUS_SINKS: ReadonlyArray<string> = [
    'fetch', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.patch',
    'fs.writeFile', 'fs.writeFileSync', 'fs.appendFile', 'fs.appendFileSync',
    'console.log', 'console.error', 'console.warn',
    'res.send', 'res.json', 'res.write'
];

/**
 * Scans a TypeScript/JavaScript file's AST for security boundaries, insecure patterns,
 * and tainted data flows. Detects HTTP calls, hardcoded localhost, process.env access,
 * database connection strings, and sensitive variable → dangerous sink flows.
 *
 * Security implication: This scanner forms the foundation of Ghostflow's threat
 * detection pipeline. It identifies both structural patterns and data flow taints
 * that indicate potential information disclosure or credential leakage.
 */
export class Scanner {
    private graph: FlowGraph;
    private projectScanner: ProjectScanner | undefined;
    private nodesVisited: number = 0;
    private readonly YIELD_INTERVAL = 500;
    /** Tracks sensitive source variables found during the current scan. */
    private sensitiveSources: SensitiveSource[] = [];

    /**
     * Initializes the Scanner with a reference to a FlowGraph to populate.
     * @param graph The FlowGraph instance to populate with discovered nodes, edges, and tainted flows.
     * @param projectScanner Optional ProjectScanner for cross-file taint resolution.
     */
    constructor(graph: FlowGraph, projectScanner?: ProjectScanner) {
        this.graph = graph;
        this.projectScanner = projectScanner;
    }

    /**
     * Parses the given text document and asynchronously scans its AST.
     * Performs pattern detection, taint source collection, sink analysis,
     * and edge inference in a single traversal with a post-pass for edges.
     * @param document The VS Code text document to scan.
     */
    public async scanDocument(document: vscode.TextDocument): Promise<void> {
        await this.scanDocuments([document]);
    }

    /**
     * Parses an array of text documents and asynchronously scans their ASTs
     * in a single batch. Performs pattern detection and taint source collection
     * across all files, then resolves imports and infers structural edges and
     * tainted flows globally.
     * @param documents Array of VS Code text documents to scan.
     */
    public async scanDocuments(documents: vscode.TextDocument[]): Promise<void> {
        this.graph.clear();
        this.nodesVisited = 0;
        this.sensitiveSources = [];

        const sourceFiles: { sourceFile: ts.SourceFile, document: vscode.TextDocument }[] = [];

        // Parse and visit all documents
        for (const document of documents) {
            const sourceFile = ts.createSourceFile(
                document.fileName,
                document.getText(),
                ts.ScriptTarget.Latest,
                true
            );
            sourceFiles.push({ sourceFile, document });
            await this.visitNodeAsync(sourceFile, document);
        }

        // Resolve cross-file imports for all documents
        for (const { sourceFile, document } of sourceFiles) {
            this.resolveImports(sourceFile, document);
        }

        // After all nodes and imports are discovered globally, infer edges and taints
        this.inferEdges();
        for (const { sourceFile, document } of sourceFiles) {
            this.detectTaintedFlows(sourceFile, document);
        }
    }

    /**
     * Asynchronously visits an AST node and its children, yielding to the event loop
     * periodically via setImmediate to ensure non-blocking execution.
     */
    private async visitNodeAsync(node: ts.Node, document: vscode.TextDocument): Promise<void> {
        this.nodesVisited++;

        if (this.nodesVisited % this.YIELD_INTERVAL === 0) {
            await new Promise(resolve => setImmediate(resolve));
        }

        this.analyzeNode(node, document);
        this.collectSensitiveSources(node, document);

        const children: ts.Node[] = [];
        ts.forEachChild(node, child => {
            children.push(child);
        });

        for (const child of children) {
            await this.visitNodeAsync(child, document);
        }
    }

    /**
     * Analyzes a single AST node for insecure patterns.
     * For HTTP calls, also extracts the URL argument to store as rawValue
     * for downstream http:// vs https:// trust boundary coloring.
     */
    private analyzeNode(node: ts.Node, document: vscode.TextDocument): void {
        // Detect HTTP calls (fetch, axios.get, axios.post)
        if (ts.isCallExpression(node)) {
            const expressionText = node.expression.getText();
            if (expressionText === 'fetch' || expressionText === 'axios.get' || expressionText === 'axios.post') {
                // Extract the first argument as the URL
                let urlValue = '';
                if (node.arguments.length > 0) {
                    const firstArg = node.arguments[0];
                    if (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) {
                        urlValue = firstArg.text;
                    }
                }
                this.addNodeToGraph(node, document, NodeType.ProcessNode, 'HTTP Call', `External network request via ${expressionText}`, urlValue);
            }
        }

        // Detect process.env access
        if (ts.isPropertyAccessExpression(node)) {
            if (node.expression.getText() === 'process' && node.name.getText() === 'env') {
                this.addNodeToGraph(node, document, NodeType.DataStore, 'Environment Variables', 'Accessing process.env which may contain sensitive secrets', 'process.env');
            }
        }

        // Detect string literals for localhost and db connections
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
            const text = node.text;
            if (text.includes('localhost') || text.includes('127.0.0.1')) {
                const parent = node.parent;
                const isHttpArg = parent && ts.isCallExpression(parent) &&
                    (parent.expression.getText() === 'fetch' ||
                     parent.expression.getText() === 'axios.get' ||
                     parent.expression.getText() === 'axios.post');
                if (!isHttpArg) {
                    this.addNodeToGraph(node, document, NodeType.ProcessNode, 'Localhost', 'Hardcoded localhost binding might be insecure in production', text);
                }
            }
            if (text.startsWith('mongodb://') || text.startsWith('postgres://') || text.startsWith('mysql://')) {
                this.addNodeToGraph(node, document, NodeType.DataStore, 'Database Connection', 'Hardcoded database connection string containing potential credentials', text);
            }
        }
    }

    /**
     * Collects sensitive source variables from variable declarations and assignments.
     * A variable is considered a sensitive source if its name contains any of
     * the SENSITIVE_PATTERNS (case-insensitive).
     *
     * Security implication: these variables are tracked for taint analysis
     * to detect when they flow into dangerous sinks.
     */
    private collectSensitiveSources(node: ts.Node, document: vscode.TextDocument): void {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
            const varName = node.name.text;
            const lowerName = varName.toLowerCase();
            const isSensitive = SENSITIVE_PATTERNS.some(pattern => lowerName.includes(pattern));

            if (isSensitive) {
                const { line, character } = document.positionAt(node.getStart());
                const nodeId = `${document.fileName}:${line}:${character}`;

                this.sensitiveSources.push({ varName, nodeId, line, character });

                // Add as a TaintSource node to the graph
                this.graph.addNode({
                    id: nodeId,
                    type: NodeType.DataStore,
                    label: 'Sensitive Source',
                    description: `Variable '${varName}' contains sensitive data (matches pattern: ${SENSITIVE_PATTERNS.find(p => lowerName.includes(p))})`,
                    filePath: document.fileName,
                    line,
                    character,
                    rawValue: varName
                });
            }
        }
    }

    /**
     * Resolves import declarations in the current file and checks the ProjectScanner
     * cache for sensitive exports in the imported modules. Any sensitive exported
     * variable that is imported inherits the 'Tainted' status in this file.
     *
     * Security implication: This enables cross-file taint tracking — a secret
     * defined in config.ts and imported into app.ts is flagged as tainted in app.ts.
     */
    private resolveImports(sourceFile: ts.SourceFile, document: vscode.TextDocument): void {
        if (!this.projectScanner) {
            return;
        }

        const currentDir = path.dirname(document.fileName);

        ts.forEachChild(sourceFile, (node: ts.Node) => {
            if (!ts.isImportDeclaration(node)) {
                return;
            }

            // Get the module specifier (e.g. './config')
            const moduleSpecifier = node.moduleSpecifier;
            if (!ts.isStringLiteral(moduleSpecifier)) {
                return;
            }

            const specifierText = moduleSpecifier.text;

            // Only resolve relative imports (starting with . or ..)
            if (!specifierText.startsWith('.')) {
                return;
            }

            const resolvedPath = path.resolve(currentDir, specifierText);
            const sensitiveExports = this.projectScanner!.getExportsForModule(resolvedPath);

            if (sensitiveExports.length === 0) {
                return;
            }

            // Get the imported names from the import clause
            const importedNames = new Set<string>();
            const importClause = node.importClause;

            if (importClause) {
                // Default import: import apiKey from './config'
                if (importClause.name) {
                    importedNames.add(importClause.name.text);
                }

                // Named imports: import { apiKey, dbSecret } from './config'
                if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
                    for (const element of importClause.namedBindings.elements) {
                        importedNames.add(element.name.text);
                    }
                }
            }

            // Cross-reference imported names with sensitive exports
            for (const exportInfo of sensitiveExports) {
                if (importedNames.has(exportInfo.varName)) {
                    const sourceFileName = path.basename(exportInfo.filePath);
                    const { line: importLine, character: importChar } = document.positionAt(node.getStart());
                    const nodeId = `${document.fileName}:${importLine}:${importChar}:${exportInfo.varName}`;

                    // Add as a cross-file sensitive source
                    this.sensitiveSources.push({
                        varName: exportInfo.varName,
                        nodeId,
                        line: importLine,
                        character: importChar,
                        crossFileSource: sourceFileName
                    });

                    // Add a graph node for the imported taint source
                    this.graph.addNode({
                        id: nodeId,
                        type: NodeType.DataStore,
                        label: 'Sensitive Source',
                        description: `Imported sensitive variable '${exportInfo.varName}' from ${sourceFileName}`,
                        filePath: document.fileName,
                        line: importLine,
                        character: importChar,
                        rawValue: `${exportInfo.varName} (from ${sourceFileName})`
                    });
                }
            }
        });
    }

    /**
     * Performs a second synchronous pass over the AST to detect tainted data flows.
     * For each call to a dangerous sink, checks if any argument references a
     * previously identified sensitive source variable. If so, records a TaintedFlow
     * and creates a tainted edge in the graph.
     *
     * Security implication: this detects concrete data flow paths where secrets
     * or credentials are passed to network calls, file writes, or logging functions.
     */
    private detectTaintedFlows(sourceFile: ts.SourceFile, document: vscode.TextDocument): void {
        if (this.sensitiveSources.length === 0) {
            return;
        }

        const sensitiveNames = new Set(this.sensitiveSources.map(s => s.varName));

        const visit = (node: ts.Node): void => {
            if (ts.isCallExpression(node)) {
                const sinkName = node.expression.getText();
                if (DANGEROUS_SINKS.includes(sinkName)) {
                    // Check all arguments for sensitive variable references
                    this.checkArgumentsForTaint(node, sinkName, sensitiveNames, document);
                }
            }
            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
    }

    /**
     * Recursively inspects call expression arguments for identifiers that
     * reference sensitive source variables. Handles nested object literals
     * and property assignments (e.g. `{ headers: { Authorization: apiKey } }`).
     */
    private checkArgumentsForTaint(
        callNode: ts.CallExpression,
        sinkName: string,
        sensitiveNames: Set<string>,
        document: vscode.TextDocument
    ): void {
        const { line: sinkLine, character: sinkChar } = document.positionAt(callNode.getStart());
        const sinkNodeId = `${document.fileName}:${sinkLine}:${sinkChar}`;

        const checkNode = (node: ts.Node): void => {
            if (ts.isIdentifier(node)) {
                const name = node.text;
                if (sensitiveNames.has(name)) {
                    const source = this.sensitiveSources.find(s => s.varName === name);
                    if (source) {
                        const crossLabel = source.crossFileSource
                            ? `Tainted: ${name} → ${sinkName}  From ${source.crossFileSource}`
                            : `Tainted: ${name} → ${sinkName}`;

                        // Record the tainted flow
                        this.graph.addTaintedFlow({
                            sourceVar: name,
                            sinkName,
                            sinkNodeId,
                            sourceNodeId: source.nodeId,
                            crossFileSource: source.crossFileSource
                        });

                        // Create a tainted edge from source to sink
                        this.graph.addEdge({
                            from: source.nodeId,
                            to: sinkNodeId,
                            label: crossLabel,
                            secure: false,
                            tainted: true
                        });
                    }
                }
            }
            ts.forEachChild(node, checkNode);
        };

        for (const arg of callNode.arguments) {
            checkNode(arg);
        }
    }

    /**
     * Infers directed edges between related nodes after AST traversal is complete.
     *
     * Security implication: edges represent data flow across trust boundaries.
     * - HTTP calls targeting localhost/127.0.0.1 create Process → Localhost edges.
     * - Database connections are linked to Environment Variables (credentials often sourced from env).
     * - Edge `secure` flag is determined by protocol (https:// = true, http:// = false).
     */
    private inferEdges(): void {
        const nodes = this.graph.getNodes();

        const httpNodes = nodes.filter(n => n.label === 'HTTP Call');
        const localhostNodes = nodes.filter(n => n.label === 'Localhost');
        const dbNodes = nodes.filter(n => n.label === 'Database Connection');
        const envNodes = nodes.filter(n => n.label === 'Environment Variables');

        // Connect HTTP calls that target localhost/127.0.0.1 to Localhost nodes
        for (const httpNode of httpNodes) {
            const url = httpNode.rawValue;
            if (url.includes('localhost') || url.includes('127.0.0.1')) {
                const target = this.findClosestNode(httpNode, localhostNodes) ?? localhostNodes[0];
                if (target) {
                    this.graph.addEdge({
                        from: httpNode.id,
                        to: target.id,
                        label: url.startsWith('https://') ? 'HTTPS' : 'HTTP',
                        secure: url.startsWith('https://'),
                        tainted: false
                    });
                }
            } else {
                this.graph.addEdge({
                    from: httpNode.id,
                    to: httpNode.id,
                    label: url.startsWith('https://') ? 'HTTPS (External)' : 'HTTP (External)',
                    secure: url.startsWith('https://'),
                    tainted: false
                });
            }
        }

        // Connect DB connection strings to Environment Variable nodes
        if (envNodes.length > 0) {
            for (const dbNode of dbNodes) {
                const envTarget = envNodes[0];
                this.graph.addEdge({
                    from: envTarget.id,
                    to: dbNode.id,
                    label: 'Credentials',
                    secure: false,
                    tainted: false
                });
            }
        }

        // Connect localhost nodes inside DB strings
        for (const dbNode of dbNodes) {
            if (dbNode.rawValue.includes('localhost') || dbNode.rawValue.includes('127.0.0.1')) {
                for (const lhNode of localhostNodes) {
                    this.graph.addEdge({
                        from: lhNode.id,
                        to: dbNode.id,
                        label: 'Local DB',
                        secure: false,
                        tainted: false
                    });
                }
            }
        }
    }

    /**
     * Finds the node from candidates closest (by line number) to the source node.
     */
    private findClosestNode(source: { line: number }, candidates: Array<{ id: string; line: number }>): { id: string; line: number } | undefined {
        if (candidates.length === 0) { return undefined; }
        let closest = candidates[0];
        let minDist = Math.abs(source.line - closest.line);
        for (const c of candidates) {
            const dist = Math.abs(source.line - c.line);
            if (dist < minDist) {
                minDist = dist;
                closest = c;
            }
        }
        return closest;
    }

    /**
     * Adds an identified pattern to the FlowGraph with its raw value.
     */
    private addNodeToGraph(node: ts.Node, document: vscode.TextDocument, type: NodeType, label: string, description: string, rawValue: string): void {
        const { line, character } = document.positionAt(node.getStart());
        this.graph.addNode({
            id: `${document.fileName}:${line}:${character}`,
            type,
            label,
            description,
            filePath: document.fileName,
            line,
            character,
            rawValue
        });
    }
}
