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
    /** True if this source passed through a recognized encryption/hashing function. */
    isSanitized?: boolean;
}

import { SENSITIVE_PATTERNS, SANITIZER_PATTERNS } from './constants';

/**
 * HTTP caller function names that represent outbound network requests.
 * Used by analyzeNode to detect HTTP Call patterns and by the localhost
 * deduplication check.
 */
const HTTP_CALLERS: ReadonlySet<string> = new Set([
    // Built-in / standard
    'fetch',
    // Axios
    'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete',
    'axios.patch', 'axios.head', 'axios.options', 'axios.request',
    // Node built-ins
    'http.request', 'http.get', 'https.request', 'https.get',
    // Popular libraries
    'got', 'got.get', 'got.post', 'got.put', 'got.delete', 'got.patch',
    'ky', 'ky.get', 'ky.post', 'ky.put', 'ky.delete', 'ky.patch',
    'superagent.get', 'superagent.post', 'superagent.put', 'superagent.delete', 'superagent.patch',
    'request', 'request.get', 'request.post', 'request.put', 'request.delete',
    'undici.fetch', 'undici.request',
    // XMLHttpRequest (browser/legacy)
    'XMLHttpRequest'
]);

/** Database connection string URL prefixes. */
const DB_URL_PREFIXES: ReadonlyArray<string> = [
    'mongodb://', 'mongodb+srv://',
    'postgres://', 'postgresql://',
    'mysql://',
    'redis://', 'rediss://',
    'sqlite://',
    'mssql://',
    'amqp://', 'amqps://'
];

/**
 * ORM / database client call patterns.
 * When the expression text starts with one of these prefixes and appears
 * as a call expression, it is flagged as a database operation.
 */
const DB_CALL_PREFIXES: ReadonlyArray<string> = [
    'prisma.', 'mongoose.connect', 'mongoose.createConnection',
    'sequelize.query', 'sequelize.authenticate',
    'knex(', 'knex.raw',
    'typeorm.createConnection',
    'pool.query', 'client.query', 'connection.query', 'connection.execute',
    'db.collection', 'db.command'
];

/** Function names considered dangerous sinks for taint analysis. */
const DANGEROUS_SINKS: ReadonlyArray<string> = [
    // HTTP clients (all callers are also sinks for taint purposes)
    ...HTTP_CALLERS,
    // File system writes
    'fs.writeFile', 'fs.writeFileSync', 'fs.appendFile', 'fs.appendFileSync',
    'fs.createWriteStream', 'fsPromises.writeFile', 'fsPromises.appendFile',
    // Logging / output
    'console.log', 'console.error', 'console.warn', 'console.info', 'console.debug',
    'logger.info', 'logger.warn', 'logger.error', 'logger.debug', 'logger.log',
    // HTTP response (Express / Koa / Fastify)
    'res.send', 'res.json', 'res.write', 'res.end', 'res.redirect', 'res.render',
    'reply.send', 'reply.code',
    // Code execution
    'eval', 'Function', 'setTimeout', 'setInterval',
    // Child process
    'child_process.exec', 'child_process.execSync',
    'child_process.spawn', 'child_process.spawnSync',
    'execSync', 'exec', 'spawn', 'spawnSync',
    // Database operations (taint reaching a query is critical)
    ...DB_CALL_PREFIXES,
    // DOM (client-side)
    'document.write', 'document.writeln',
    // Storage
    'localStorage.setItem', 'sessionStorage.setItem',
    // Serialization
    'JSON.stringify'
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
    /** Tracks imported third-party modules per file (localName -> moduleSpecifier) */
    private thirdPartyImportsByFile: Map<string, Map<string, string>> = new Map();

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
        this.graph.clearForFile(document.fileName);
        this.nodesVisited = 0;

        if (this.shouldSkipFile(document.fileName)) {
            return;
        }

        const filePrefix = document.fileName + ':';
        this.sensitiveSources = this.sensitiveSources.filter(s => !s.nodeId.startsWith(filePrefix));
        this.thirdPartyImportsByFile.delete(document.fileName);

        const sourceFile = ts.createSourceFile(
            document.fileName,
            document.getText(),
            ts.ScriptTarget.Latest,
            true
        );

        await this.visitNodeAsync(sourceFile, document);
        
        // Post-passes for the single file
        this.resolveImports(sourceFile, document);
        this.detectTaintedFlows(sourceFile, document);
        
        // Re-infer structural edges. (Safe because FlowGraph now drops duplicates)
        this.inferEdges();
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
            if (this.shouldSkipFile(document.fileName)) {
                continue;
            }

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
     * Determines whether a file should be skipped during AST traversal to avoid 
     * false positives in minified or third-party library files.
     */
    private shouldSkipFile(fileName: string): boolean {
        // Skip minified files
        if (fileName.endsWith('.min.js') || fileName.endsWith('.min.ts')) {
            return true;
        }
        
        // Skip common third-party or compiled output directories
        const normalizedPath = fileName.replace(/\\/g, '/');
        if (normalizedPath.includes('/node_modules/') || 
            normalizedPath.includes('/wwwroot/lib/') || 
            normalizedPath.includes('/dist/') ||
            normalizedPath.includes('/build/')) {
            return true;
        }

        return false;
    }

    /**
     * Asynchronously visits an AST node and its children, yielding to the event loop
     * periodically via setImmediate to ensure non-blocking execution.
     */
    private async visitNodeAsync(rootNode: ts.Node, document: vscode.TextDocument): Promise<void> {
        const stack: ts.Node[] = [rootNode];

        while (stack.length > 0) {
            const node = stack.pop()!;
            
            this.nodesVisited++;

            if (this.nodesVisited % this.YIELD_INTERVAL === 0) {
                await new Promise(resolve => setImmediate(resolve));
            }

            this.analyzeNode(node, document);
            this.collectSensitiveSources(node, document);

            // Push children in reverse order to maintain left-to-right DFS traversal
            const children: ts.Node[] = [];
            ts.forEachChild(node, child => {
                children.push(child);
            });
            
            for (let i = children.length - 1; i >= 0; i--) {
                stack.push(children[i]);
            }
        }
    }

    /**
     * Analyzes a single AST node for insecure patterns.
     * For HTTP calls, also extracts the URL argument to store as rawValue
     * for downstream http:// vs https:// trust boundary coloring.
     */
    private analyzeNode(node: ts.Node, document: vscode.TextDocument): void {
        // Detect HTTP calls via the shared HTTP_CALLERS set
        if (ts.isCallExpression(node)) {
            const expressionText = node.expression.getText();

            if (HTTP_CALLERS.has(expressionText)) {
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

            // Detect ORM / database client calls
            if (DB_CALL_PREFIXES.some(prefix => expressionText.startsWith(prefix))) {
                this.addNodeToGraph(node, document, NodeType.DataStore, 'Database Operation', `Database operation via ${expressionText}`, expressionText);
            }

            // Detect code execution sinks (eval, exec, spawn)
            if (expressionText === 'eval' || expressionText === 'Function') {
                this.addNodeToGraph(node, document, NodeType.ProcessNode, 'Code Execution', `Dynamic code execution via ${expressionText} — potential injection risk`, expressionText);
            }
            if (expressionText === 'child_process.exec' || expressionText === 'child_process.execSync' ||
                expressionText === 'child_process.spawn' || expressionText === 'child_process.spawnSync' ||
                expressionText === 'exec' || expressionText === 'execSync' ||
                expressionText === 'spawn' || expressionText === 'spawnSync') {
                this.addNodeToGraph(node, document, NodeType.ProcessNode, 'Shell Execution', `Shell command execution via ${expressionText} — command injection risk`, expressionText);
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
                // Use the shared HTTP_CALLERS set for deduplication
                const isHttpArg = parent && ts.isCallExpression(parent) &&
                    HTTP_CALLERS.has(parent.expression.getText());
                if (!isHttpArg) {
                    this.addNodeToGraph(node, document, NodeType.ProcessNode, 'Localhost', 'Hardcoded localhost binding might be insecure in production', text);
                }
            }
            if (DB_URL_PREFIXES.some(prefix => text.startsWith(prefix))) {
                this.addNodeToGraph(node, document, NodeType.DataStore, 'Database Connection', 'Hardcoded database connection string containing potential credentials', text);
            }
        }
    }

    /**
     * Collects sensitive source variables from variable declarations and assignments.
     * A variable is considered a sensitive source if:
     * 1. Its name contains any of the SENSITIVE_PATTERNS (case-insensitive)
     * 2. It is assigned the value of an already known sensitive source (Taint Aliasing)
     *
     * Security implication: these variables are tracked for taint analysis
     * to detect when they flow into dangerous sinks.
     */
    private collectSensitiveSources(node: ts.Node, document: vscode.TextDocument): void {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
            const varName = node.name.text;
            const lowerName = varName.toLowerCase();
            
            // 1. Check for semantic naming (hardcoded secret / credential patterns)
            let isSensitive = SENSITIVE_PATTERNS.some(pattern => lowerName.includes(pattern));
            let aliasSource: SensitiveSource | undefined = undefined;
            let isSanitizedFlow = false;

            // 2. Check for Taint Aliasing and Sanitization
            if (node.initializer) {
                // Direct assignment (const a = b)
                if (ts.isIdentifier(node.initializer)) {
                    const initName = node.initializer.text;
                    aliasSource = this.sensitiveSources.find(s => s.varName === initName && s.nodeId.startsWith(document.fileName + ':'));
                    if (aliasSource) {
                        isSensitive = true;
                        isSanitizedFlow = aliasSource.isSanitized || false;
                    }
                }
                // Call expression (const a = encrypt(b))
                else if (ts.isCallExpression(node.initializer)) {
                    const callName = node.initializer.expression.getText().toLowerCase();
                    const isSanitizer = SANITIZER_PATTERNS.some(p => callName.includes(p));
                    
                    for (const arg of node.initializer.arguments) {
                        // Extract base identifier from nested call/property expressions (e.g. rawToken.trim())
                        let baseArg: ts.Expression = arg;
                        if (ts.isCallExpression(baseArg) && ts.isPropertyAccessExpression(baseArg.expression)) {
                            baseArg = baseArg.expression.expression;
                        }

                        if (ts.isIdentifier(baseArg)) {
                            aliasSource = this.sensitiveSources.find(s => s.varName === baseArg.text && s.nodeId.startsWith(document.fileName + ':'));
                            if (aliasSource) {
                                isSensitive = true;
                                if (isSanitizer || aliasSource.isSanitized) {
                                    isSanitizedFlow = true;
                                }
                                break;
                            }
                        }
                    }
                }
                // Property access (const a = req.body.token) - check every segment in the chain
                else if (ts.isPropertyAccessExpression(node.initializer)) {
                    let current: ts.Expression = node.initializer;
                    
                    while (current && !isSensitive) {
                        if (ts.isPropertyAccessExpression(current)) {
                            // Check the property name at this level (e.g. 'token')
                            const propName = current.name.text;
                            aliasSource = this.sensitiveSources.find(s => s.varName === propName && s.nodeId.startsWith(document.fileName + ':'));
                            if (aliasSource) {
                                isSensitive = true;
                                isSanitizedFlow = aliasSource.isSanitized || false;
                                break;
                            }
                            current = current.expression;
                        } else if (ts.isElementAccessExpression(current)) {
                            current = current.expression;
                        } else if (ts.isIdentifier(current)) {
                            // Check the root identifier (e.g. 'req')
                            const rootName = (current as ts.Identifier).text;
                            aliasSource = this.sensitiveSources.find(s => s.varName === rootName && s.nodeId.startsWith(document.fileName + ':'));
                            if (aliasSource) {
                                isSensitive = true;
                                isSanitizedFlow = aliasSource.isSanitized || false;
                            }
                            break;
                        } else {
                            break;
                        }
                    }
                    
                    // Fallback semantic check on the entire string structure
                    if (!isSensitive && node.initializer?.getText() && SENSITIVE_PATTERNS.some(pattern => node.initializer!.getText().toLowerCase().includes(pattern))) {
                        isSensitive = true;
                    }
                }
            }

            if (isSensitive) {
                const { line, character } = document.positionAt(node.getStart());
                const nodeId = `${document.fileName}:${line}:${character}`;

                this.sensitiveSources.push({ 
                    varName, 
                    nodeId, 
                    line, 
                    character,
                    // If this was an alias, propagate the original crossFileSource if it exists
                    crossFileSource: aliasSource?.crossFileSource,
                    isSanitized: isSanitizedFlow
                });

                const patternMatch = SENSITIVE_PATTERNS.find(p => lowerName.includes(p));
                const reason = aliasSource 
                    ? `Variable '${varName}' is an alias of tainted source '${aliasSource.varName}'`
                    : `Variable '${varName}' contains sensitive data (matches pattern: ${patternMatch})`;

                // Add as a TaintSource node to the graph
                this.graph.addNode({
                    id: nodeId,
                    type: NodeType.DataStore,
                    label: isSanitizedFlow ? 'Sanitized Alias' : (aliasSource ? 'Tainted Alias' : 'Sensitive Source'),
                    description: reason + (isSanitizedFlow ? ' (Secured via Sanitizer)' : ''),
                    filePath: document.fileName,
                    line,
                    character,
                    rawValue: varName
                });
                
                // If it's an alias, draw an edge from the original source to this new alias
                if (aliasSource) {
                    this.graph.addEdge({
                        from: aliasSource.nodeId,
                        to: nodeId,
                        label: isSanitizedFlow ? 'Sanitized' : 'Aliased',
                        secure: isSanitizedFlow,
                        tainted: !isSanitizedFlow
                    });
                }
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

            // Track third-party imports (anything not starting with . or /)
            if (!specifierText.startsWith('.') && !specifierText.startsWith('/')) {
                let fileMap = this.thirdPartyImportsByFile.get(document.fileName);
                if (!fileMap) {
                    fileMap = new Map();
                    this.thirdPartyImportsByFile.set(document.fileName, fileMap);
                }
                for (const name of importedNames) {
                    fileMap.set(name, specifierText);
                }
                return; // Normal taint propagation runs on relative bounds
            }

            const resolvedPath = path.resolve(currentDir, specifierText);
            const sensitiveExports = this.projectScanner!.getExportsForModule(resolvedPath);

            if (sensitiveExports.length === 0) {
                return;
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
        // Scope taint tracking ONLY to variables defined or imported in this specific file
        const localSources = this.sensitiveSources.filter(s => s.nodeId.startsWith(document.fileName));
        if (localSources.length === 0) {
            return;
        }

        const sensitiveNames = new Set(localSources.map(s => s.varName));
        const thirdPartyMap = this.thirdPartyImportsByFile.get(document.fileName) || new Map<string, string>();

        const visit = (node: ts.Node): void => {
            if (ts.isCallExpression(node)) {
                const sinkName = node.expression.getText();
                
                let isThirdPartyCall = false;
                let moduleName = '';
                
                // Extract root identifier of property chain (e.g. AWS from AWS.S3.upload)
                let rootIdentifier = node.expression;
                while (ts.isPropertyAccessExpression(rootIdentifier) || ts.isElementAccessExpression(rootIdentifier)) {
                    rootIdentifier = rootIdentifier.expression;
                }
                
                if (ts.isIdentifier(rootIdentifier) && thirdPartyMap.has(rootIdentifier.text)) {
                    isThirdPartyCall = true;
                    moduleName = thirdPartyMap.get(rootIdentifier.text)!;
                }

                if (DANGEROUS_SINKS.includes(sinkName) || isThirdPartyCall) {
                    // Check all arguments for sensitive variable references
                    this.checkArgumentsForTaint(node, sinkName, sensitiveNames, localSources, document, isThirdPartyCall ? moduleName : undefined);
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
        localSources: SensitiveSource[],
        document: vscode.TextDocument,
        thirdPartyModule?: string
    ): void {
        const { line: sinkLine, character: sinkChar } = document.positionAt(callNode.getStart());
        const sinkNodeId = `${document.fileName}:${sinkLine}:${sinkChar}`;

        const checkNode = (node: ts.Node, currentlySanitized: boolean, sanitizerName?: string): void => {
            let nextSanitized = currentlySanitized;
            let nextSanitizerName = sanitizerName;

            if (ts.isCallExpression(node)) {
                const callName = node.expression.getText();
                if (SANITIZER_PATTERNS.some(p => callName.toLowerCase().includes(p))) {
                    nextSanitized = true;
                    nextSanitizerName = callName;
                }
            }

            if (ts.isIdentifier(node)) {
                const name = node.text;
                if (sensitiveNames.has(name)) {
                    const source = localSources.find(s => s.varName === name);
                    if (source) {
                        const isSecureFlow = nextSanitized || source.isSanitized || false;
                        const appliedSanitizer = nextSanitizerName || (source.isSanitized ? 'aliased sanitizer' : '');

                        const crossLabel = thirdPartyModule
                            ? `SDK Handoff: ${name}`
                            : (isSecureFlow
                                ? `Sanitized: ${name} via ${appliedSanitizer} → ${sinkName}`
                                : (source.crossFileSource
                                    ? `Tainted: ${name} → ${sinkName}  From ${source.crossFileSource}`
                                    : `Tainted: ${name} → ${sinkName}`));

                        // Ensure target node physically exists on graph so Phase 3 isolation logic doesn't delete it
                        if (!this.graph.getNodes().find(n => n.id === sinkNodeId)) {
                            this.graph.addNode({
                                id: sinkNodeId,
                                type: NodeType.ProcessNode,
                                label: thirdPartyModule ? `3rd-Party SDK (${thirdPartyModule})` : 'Dangerous Sink',
                                description: thirdPartyModule ? `Sensitive data passed to external dependency API` : `Sensitive data passed to ${sinkName} sink`,
                                filePath: document.fileName,
                                line: sinkLine,
                                character: sinkChar,
                                rawValue: sinkName
                            });
                        }

                        // Record the tainted flow ONLY if it is insecure
                        if (!thirdPartyModule && !isSecureFlow) {
                            this.graph.addTaintedFlow({
                                sourceVar: name,
                                sinkName,
                                sinkNodeId,
                                sourceNodeId: source.nodeId,
                                crossFileSource: source.crossFileSource
                            });
                        }

                        // Create an edge from source to sink
                        this.graph.addEdge({
                            from: source.nodeId,
                            to: sinkNodeId,
                            label: crossLabel,
                            secure: isSecureFlow,
                            tainted: !thirdPartyModule && !isSecureFlow // Green if sanitized!
                        });
                    }
                }
            }
            ts.forEachChild(node, child => checkNode(child, nextSanitized, nextSanitizerName));
        };

        for (const arg of callNode.arguments) {
            checkNode(arg, false);
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
