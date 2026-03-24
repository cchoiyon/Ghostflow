import * as ts from 'typescript';
import * as vscode from 'vscode';
import { FlowGraph, NodeType } from './FlowGraph';

/**
 * Scans a TypeScript/JavaScript file's AST for security boundaries and insecure patterns.
 * Detects HTTP calls, hardcoded localhost, process.env access, and database connection strings.
 * Additionally infers relationships between nodes and creates directed edges
 * to form a connected Data Flow Diagram.
 */
export class Scanner {
    private graph: FlowGraph;
    private nodesVisited: number = 0;
    private readonly YIELD_INTERVAL = 500;

    /**
     * Initializes the Scanner with a reference to a FlowGraph to populate.
     * @param graph The FlowGraph instance to populate with discovered nodes and edges.
     */
    constructor(graph: FlowGraph) {
        this.graph = graph;
    }

    /**
     * Parses the given text document and asynchronously scans its AST.
     * After node detection, infers edges between related nodes.
     * @param document The VS Code text document to scan.
     */
    public async scanDocument(document: vscode.TextDocument): Promise<void> {
        this.graph.clear();
        this.nodesVisited = 0;

        const sourceFile = ts.createSourceFile(
            document.fileName,
            document.getText(),
            ts.ScriptTarget.Latest,
            true
        );

        await this.visitNodeAsync(sourceFile, document);

        // After all nodes discovered, infer edges between related patterns
        this.inferEdges();
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
                // Only add a Localhost node if it's NOT already captured as part of an HTTP call argument
                // (to avoid duplicates from the call expression analysis above)
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
                // Find the best matching localhost node (closest by line)
                const target = this.findClosestNode(httpNode, localhostNodes) ?? localhostNodes[0];
                if (target) {
                    this.graph.addEdge({
                        from: httpNode.id,
                        to: target.id,
                        label: url.startsWith('https://') ? 'HTTPS' : 'HTTP',
                        secure: url.startsWith('https://')
                    });
                }
            } else {
                // External HTTP call — still create an edge to show it exists,
                // self-referencing to indicate outbound traffic
                this.graph.addEdge({
                    from: httpNode.id,
                    to: httpNode.id,
                    label: url.startsWith('https://') ? 'HTTPS (External)' : 'HTTP (External)',
                    secure: url.startsWith('https://')
                });
            }
        }

        // Connect DB connection strings to Environment Variable nodes (credentials source)
        if (envNodes.length > 0) {
            for (const dbNode of dbNodes) {
                const envTarget = envNodes[0];
                this.graph.addEdge({
                    from: envTarget.id,
                    to: dbNode.id,
                    label: 'Credentials',
                    secure: false
                });
            }
        }

        // Connect localhost nodes that appear inside DB strings to the DB node
        for (const dbNode of dbNodes) {
            if (dbNode.rawValue.includes('localhost') || dbNode.rawValue.includes('127.0.0.1')) {
                for (const lhNode of localhostNodes) {
                    this.graph.addEdge({
                        from: lhNode.id,
                        to: dbNode.id,
                        label: 'Local DB',
                        secure: false
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
