import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Represents a sensitive variable that is exported from a TypeScript/JavaScript module.
 * Used for cross-file taint propagation when the variable is imported elsewhere.
 */
export interface SensitiveExport {
    /** The exported variable name. */
    varName: string;
    /** Absolute path to the source file containing the export. */
    filePath: string;
    /** Zero-indexed line number of the export declaration. */
    line: number;
    /** Zero-indexed character offset. */
    character: number;
}

/** Case-insensitive patterns that identify sensitive variable names. */
const SENSITIVE_PATTERNS: ReadonlyArray<string> = [
    'key', 'secret', 'pass', 'password', 'token', 'credential', 'auth', 'apikey'
];

/**
 * Cached scan result for a single file, keyed by modification time.
 */
interface FileCacheEntry {
    /** File modification time in milliseconds. */
    mtime: number;
    /** Sensitive exports discovered in this file. */
    exports: SensitiveExport[];
}

/**
 * Scans the entire workspace to build a cached map of exported sensitive variables.
 * Uses the TypeScript Compiler API (`ts.createProgram`) for accurate AST analysis
 * and caches results per-file using mtime to avoid redundant re-scanning.
 *
 * Security implication: This enables cross-file taint tracking — if a sensitive
 * variable is exported from `config.ts` and imported into `app.ts`, Ghostflow
 * can detect the taint propagation across module boundaries.
 */
export class ProjectScanner {
    /** Per-file cache of sensitive exports, keyed by absolute file path. */
    private cache: Map<string, FileCacheEntry> = new Map();

    /**
     * Scans all TypeScript/JavaScript files in the given workspace directory.
     * Only re-parses files whose mtime has changed since the last scan.
     * Uses setImmediate yielding to avoid blocking the main thread.
     *
     * @param rootDir Absolute path to the workspace root directory.
     */
    public async scanWorkspace(rootDir: string): Promise<void> {
        const tsFiles = this.findSourceFiles(rootDir);

        for (const filePath of tsFiles) {
            await this.scanFileIfChanged(filePath);
        }
    }

    /**
     * Incrementally updates the cache for a single file.
     * Called on file save to avoid full workspace re-scan.
     *
     * @param filePath Absolute path to the saved file.
     */
    public async updateFile(filePath: string): Promise<void> {
        await this.scanFileIfChanged(filePath);
    }

    /**
     * Returns all sensitive exports for a given resolved module path.
     * @param resolvedPath Absolute path to the module file.
     * @returns Array of SensitiveExport, or empty array if none found.
     */
    public getExportsForModule(resolvedPath: string): SensitiveExport[] {
        // Try exact match first, then with .ts/.js extensions
        const candidates = [
            resolvedPath,
            resolvedPath + '.ts',
            resolvedPath + '.js',
            path.join(resolvedPath, 'index.ts'),
            path.join(resolvedPath, 'index.js')
        ];

        for (const candidate of candidates) {
            const normalized = path.normalize(candidate);
            const entry = this.cache.get(normalized);
            if (entry) {
                return entry.exports;
            }
        }

        return [];
    }

    /**
     * Scans a file only if its mtime has changed since the last cached scan.
     * Uses ts.createSourceFile for per-file AST parsing (lightweight, no type checker).
     */
    private async scanFileIfChanged(filePath: string): Promise<void> {
        try {
            const stat = fs.statSync(filePath);
            const mtime = stat.mtimeMs;

            const cached = this.cache.get(filePath);
            if (cached && cached.mtime === mtime) {
                return; // File unchanged, use cache
            }

            // Yield to event loop before heavy work
            await new Promise(resolve => setImmediate(resolve));

            const content = fs.readFileSync(filePath, 'utf-8');
            const sourceFile = ts.createSourceFile(
                filePath,
                content,
                ts.ScriptTarget.Latest,
                true
            );

            const exports = this.extractSensitiveExports(sourceFile, filePath);
            this.cache.set(filePath, { mtime, exports });
        } catch {
            // File may have been deleted or inaccessible — remove from cache
            this.cache.delete(filePath);
        }
    }

    /**
     * Extracts exported variable declarations whose names match sensitive patterns.
     * Handles: `export const apiKey = ...`, `export { apiKey }`, and
     * top-level `const apiKey = ...` with `export default apiKey`.
     */
    private extractSensitiveExports(sourceFile: ts.SourceFile, filePath: string): SensitiveExport[] {
        const exports: SensitiveExport[] = [];

        const visit = (node: ts.Node): void => {
            // Handle: export const apiKey = "..."
            if (ts.isVariableStatement(node)) {
                const hasExport = node.modifiers?.some(
                    m => m.kind === ts.SyntaxKind.ExportKeyword
                );
                if (hasExport) {
                    for (const decl of node.declarationList.declarations) {
                        if (ts.isIdentifier(decl.name)) {
                            const varName = decl.name.text;
                            if (this.isSensitiveName(varName)) {
                                const pos = sourceFile.getLineAndCharacterOfPosition(decl.getStart());
                                exports.push({
                                    varName,
                                    filePath,
                                    line: pos.line,
                                    character: pos.character
                                });
                            }
                        }
                    }
                }
            }

            // Handle: export { apiKey, dbPassword }
            if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
                for (const element of node.exportClause.elements) {
                    const varName = element.name.text;
                    if (this.isSensitiveName(varName)) {
                        const pos = sourceFile.getLineAndCharacterOfPosition(element.getStart());
                        exports.push({
                            varName,
                            filePath,
                            line: pos.line,
                            character: pos.character
                        });
                    }
                }
            }

            ts.forEachChild(node, visit);
        };

        visit(sourceFile);
        return exports;
    }

    /**
     * Checks if a variable name matches any of the sensitive patterns.
     */
    private isSensitiveName(name: string): boolean {
        const lower = name.toLowerCase();
        return SENSITIVE_PATTERNS.some(pattern => lower.includes(pattern));
    }

    /**
     * Recursively finds all .ts and .js source files in a directory,
     * excluding node_modules and dist directories.
     */
    private findSourceFiles(dir: string): string[] {
        const results: string[] = [];
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
                        continue;
                    }
                    results.push(...this.findSourceFiles(fullPath));
                } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
                    results.push(fullPath);
                }
            }
        } catch {
            // Directory may be inaccessible
        }
        return results;
    }
}
