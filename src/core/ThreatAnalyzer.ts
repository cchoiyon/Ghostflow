import { FlowGraph, FlowNode, FlowEdge, TaintedFlow, NodeType } from './FlowGraph';

/**
 * STRIDE threat modeling categories as defined by Microsoft's threat classification framework.
 * Each category represents a distinct class of security threat.
 */
export enum StrideCategory {
    Spoofing = 'Spoofing',
    Tampering = 'Tampering',
    Repudiation = 'Repudiation',
    InformationDisclosure = 'Information Disclosure',
    DenialOfService = 'Denial of Service',
    ElevationOfPrivilege = 'Elevation of Privilege'
}

/**
 * Severity levels for threat entries, used to prioritize remediation efforts.
 */
export enum ThreatSeverity {
    Critical = 'Critical',
    High = 'High',
    Medium = 'Medium',
    Low = 'Low'
}

/**
 * Represents a single STRIDE-based threat finding derived from a FlowGraph node or edge.
 * Each entry maps to a specific location in the source code for click-to-jump support.
 */
export interface ThreatEntry {
    /** The STRIDE category this threat falls under. */
    category: StrideCategory;
    /** Severity level for prioritization. */
    severity: ThreatSeverity;
    /** Human-readable explanation of the threat and its security implication. */
    message: string;
    /** The label of the source node/pattern that triggered this threat. */
    sourceLabel: string;
    /** Absolute path to the source file. */
    filePath: string;
    /** Zero-indexed line number. */
    line: number;
    /** Zero-indexed character offset. */
    character: number;
    /** ID of the source node associated with this threat. */
    sourceNodeId?: string;
    /** ID of the sink node associated with this threat. */
    sinkNodeId?: string;
    /** CWE identifier (e.g. "CWE-319") for this threat. */
    cweId: string;
    /** Human-readable CWE weakness name. */
    cweName: string;
    /** OWASP Top 10 category this threat maps to. */
    owaspCategory: string;
    /** Recommended remediation action for the developer. */
    remediation: string;
}

/**
 * Lookup table mapping each STRIDE category to its primary CWE, CWE name, and OWASP category.
 * Used as a default fallback when a more specific mapping is not provided per-threat.
 */
const STRIDE_DEFAULTS: Record<StrideCategory, { cweId: string; cweName: string; owaspCategory: string }> = {
    [StrideCategory.Spoofing]:              { cweId: 'CWE-287', cweName: 'Improper Authentication',             owaspCategory: 'A07:2021 – Identification and Authentication Failures' },
    [StrideCategory.Tampering]:             { cweId: 'CWE-345', cweName: 'Insufficient Verification of Data Authenticity', owaspCategory: 'A08:2021 – Software and Data Integrity Failures' },
    [StrideCategory.Repudiation]:           { cweId: 'CWE-778', cweName: 'Insufficient Logging',                owaspCategory: 'A09:2021 – Security Logging and Monitoring Failures' },
    [StrideCategory.InformationDisclosure]: { cweId: 'CWE-200', cweName: 'Exposure of Sensitive Information',   owaspCategory: 'A02:2021 – Cryptographic Failures' },
    [StrideCategory.DenialOfService]:       { cweId: 'CWE-400', cweName: 'Uncontrolled Resource Consumption',   owaspCategory: 'A05:2021 – Security Misconfiguration' },
    [StrideCategory.ElevationOfPrivilege]:  { cweId: 'CWE-269', cweName: 'Improper Privilege Management',       owaspCategory: 'A01:2021 – Broken Access Control' },
};

/**
 * Analyzes a FlowGraph and produces STRIDE-based threat entries for every
 * insecure pattern or red-flagged edge. This forms the intelligence layer
 * of the Ghostflow security pipeline.
 *
 * Security implication: This module translates raw AST findings into
 * actionable, categorized threat intelligence that developers can
 * understand and remediate without external security tooling.
 */
export class ThreatAnalyzer {

    /**
     * Analyzes the FlowGraph and returns an array of STRIDE-categorized threat entries.
     * Examines both nodes (patterns) and edges (data flows) for insecure indicators.
     * @param graph The FlowGraph populated by the Scanner.
     * @returns Array of ThreatEntry objects sorted by severity.
     */
    public analyze(graph: FlowGraph): ThreatEntry[] {
        const threats: ThreatEntry[] = [];
        const nodes = graph.getNodes();
        const edges = graph.getEdges();

        for (const node of nodes) {
            this.analyzeNode(node, threats);
        }

        for (const edge of edges) {
            this.analyzeEdge(edge, nodes, threats);
        }

        // Analyze tainted data flows
        const taintedFlows = graph.getTaintedFlows();
        for (const flow of taintedFlows) {
            this.analyzeTaintedFlow(flow, nodes, threats);
        }

        // Sort by severity: Critical > High > Medium > Low
        const severityOrder: Record<ThreatSeverity, number> = {
            [ThreatSeverity.Critical]: 0,
            [ThreatSeverity.High]: 1,
            [ThreatSeverity.Medium]: 2,
            [ThreatSeverity.Low]: 3
        };
        threats.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return threats;
    }

    /**
     * Builds a complete ThreatEntry by merging base fields with STRIDE-specific defaults
     * for CWE/OWASP, then applying any per-threat overrides.
     */
    private makeThreat(
        base: { sourceLabel: string; filePath: string; line: number; character: number; sourceNodeId?: string; sinkNodeId?: string },
        category: StrideCategory,
        severity: ThreatSeverity,
        message: string,
        remediation: string,
        overrides?: Partial<Pick<ThreatEntry, 'cweId' | 'cweName' | 'owaspCategory'>>
    ): ThreatEntry {
        const defaults = STRIDE_DEFAULTS[category];
        return {
            ...base,
            category,
            severity,
            message,
            remediation,
            cweId:        overrides?.cweId        ?? defaults.cweId,
            cweName:      overrides?.cweName      ?? defaults.cweName,
            owaspCategory: overrides?.owaspCategory ?? defaults.owaspCategory,
        };
    }

    /**
     * Maps a single FlowNode to zero or more STRIDE threat entries
     * based on its type, label, and raw value.
     */
    private analyzeNode(node: FlowNode, threats: ThreatEntry[]): void {
        const base = {
            sourceLabel: node.label,
            filePath: node.filePath,
            line: node.line,
            character: node.character,
            sourceNodeId: node.id
        };

        // HTTP Call nodes
        if (node.label === 'HTTP Call') {
            const isInsecure = node.rawValue.startsWith('http://');
            if (isInsecure) {
                threats.push(this.makeThreat(base,
                    StrideCategory.InformationDisclosure, ThreatSeverity.High,
                    'Information Disclosure: Data is sent over unencrypted HTTP. An attacker on the network can intercept sensitive data in transit.',
                    'Replace http:// with https:// and enforce TLS. Use HSTS headers to prevent protocol downgrade.',
                    { cweId: 'CWE-319', cweName: 'Cleartext Transmission of Sensitive Information', owaspCategory: 'A02:2021 – Cryptographic Failures' }
                ));
                threats.push(this.makeThreat(base,
                    StrideCategory.Tampering, ThreatSeverity.High,
                    'Tampering: Unencrypted HTTP allows man-in-the-middle attacks. Response data could be modified before reaching the application.',
                    'Enforce HTTPS for all outbound requests. Validate TLS certificates and reject self-signed certs in production.',
                    { cweId: 'CWE-319', cweName: 'Cleartext Transmission of Sensitive Information', owaspCategory: 'A02:2021 – Cryptographic Failures' }
                ));
            }
        }

        // Database connection strings with hardcoded credentials
        if (node.label === 'Database Connection') {
            threats.push(this.makeThreat(base,
                StrideCategory.ElevationOfPrivilege, ThreatSeverity.Critical,
                'Elevation of Privilege: Hardcoded credentials detected in database connection string. An attacker gaining access to source code obtains direct database access.',
                'Move connection strings to environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). Never commit credentials to source control.',
                { cweId: 'CWE-798', cweName: 'Use of Hard-coded Credentials', owaspCategory: 'A07:2021 – Identification and Authentication Failures' }
            ));
            threats.push(this.makeThreat(base,
                StrideCategory.InformationDisclosure, ThreatSeverity.High,
                'Information Disclosure: Database connection string is visible in source code. Credentials should be stored in a secrets manager, not in code.',
                'Use process.env or a dedicated secrets management solution. Add .env to .gitignore and rotate any exposed credentials immediately.',
                { cweId: 'CWE-312', cweName: 'Cleartext Storage of Sensitive Information', owaspCategory: 'A02:2021 – Cryptographic Failures' }
            ));
        }

        // Environment variable access
        if (node.label === 'Environment Variables') {
            threats.push(this.makeThreat(base,
                StrideCategory.InformationDisclosure, ThreatSeverity.Medium,
                'Information Disclosure: Environment variables may expose API keys, tokens, or secrets if the runtime environment is compromised or logged.',
                'Avoid logging process.env values. Validate required env vars at startup and fail-fast if missing. Use a secrets management service in production.',
                { cweId: 'CWE-526', cweName: 'Cleartext Storage of Sensitive Information in an Environment Variable', owaspCategory: 'A02:2021 – Cryptographic Failures' }
            ));
        }

        // Hardcoded localhost
        if (node.label === 'Localhost') {
            threats.push(this.makeThreat(base,
                StrideCategory.Tampering, ThreatSeverity.Medium,
                'Tampering: Hardcoded localhost binding may be bypassed in production. Services should bind to configurable addresses validated at deployment.',
                'Replace hardcoded localhost strings with configurable environment variables (e.g. process.env.HOST). Validate addresses at startup.',
                { cweId: 'CWE-1188', cweName: 'Insecure Default Initialization of Resource', owaspCategory: 'A05:2021 – Security Misconfiguration' }
            ));
            threats.push(this.makeThreat(base,
                StrideCategory.DenialOfService, ThreatSeverity.Low,
                'Denial of Service: Localhost-only bindings in production may cause service unavailability when deployed to non-local environments.',
                'Make all host/port bindings configurable via environment variables. Add infrastructure validation to confirm correct network binding at deploy time.',
                { cweId: 'CWE-400', cweName: 'Uncontrolled Resource Consumption', owaspCategory: 'A05:2021 – Security Misconfiguration' }
            ));
        }

        // Database operation nodes (ORM calls, pool.query, etc.)
        if (node.label === 'Database Operation') {
            threats.push(this.makeThreat(base,
                StrideCategory.InformationDisclosure, ThreatSeverity.Medium,
                `Information Disclosure: Database operation detected (${node.rawValue}). Ensure queries are parameterized and results are not inadvertently leaked.`,
                'Use parameterized queries or prepared statements. Never interpolate user input directly into query strings. Limit result set fields returned to clients.',
                { cweId: 'CWE-89', cweName: 'SQL Injection', owaspCategory: 'A03:2021 – Injection' }
            ));
            threats.push(this.makeThreat(base,
                StrideCategory.Tampering, ThreatSeverity.Medium,
                `Tampering: Database operation (${node.rawValue}) may be vulnerable to SQL/NoSQL injection if inputs are not properly validated.`,
                'Use an ORM with built-in parameterization. Apply strict input validation and allowlist accepted characters. Enable query logging for anomaly detection.',
                { cweId: 'CWE-89', cweName: 'SQL Injection', owaspCategory: 'A03:2021 – Injection' }
            ));
        }

        // Code execution nodes (eval, Function)
        if (node.label === 'Code Execution') {
            threats.push(this.makeThreat(base,
                StrideCategory.ElevationOfPrivilege, ThreatSeverity.Critical,
                `Elevation of Privilege: Dynamic code execution via ${node.rawValue}(). An attacker providing controlled input can execute arbitrary code in the runtime.`,
                `Remove or replace ${node.rawValue}() entirely. Use safe alternatives: JSON.parse() for data, dedicated template engines for rendering, or allowlisted function lookups.`,
                { cweId: 'CWE-95', cweName: 'Improper Neutralization of Directives in Dynamically Evaluated Code', owaspCategory: 'A03:2021 – Injection' }
            ));
            threats.push(this.makeThreat(base,
                StrideCategory.Tampering, ThreatSeverity.Critical,
                `Tampering: ${node.rawValue}() allows arbitrary code injection. Remove or replace with safe alternatives.`,
                'Refactor to eliminate dynamic code evaluation. If unavoidable, run in a sandboxed VM context (vm.runInNewContext) with strict resource limits.',
                { cweId: 'CWE-95', cweName: 'Improper Neutralization of Directives in Dynamically Evaluated Code', owaspCategory: 'A03:2021 – Injection' }
            ));
        }

        // Shell execution nodes (child_process.exec, spawn, etc.)
        if (node.label === 'Shell Execution') {
            threats.push(this.makeThreat(base,
                StrideCategory.ElevationOfPrivilege, ThreatSeverity.Critical,
                `Elevation of Privilege: Shell command execution via ${node.rawValue}(). Command injection can grant full system-level access.`,
                `Use execFile() or spawn() with argument arrays instead of string interpolation. Validate and allowlist all inputs. Avoid passing user data to shell commands.`,
                { cweId: 'CWE-78', cweName: 'OS Command Injection', owaspCategory: 'A03:2021 – Injection' }
            ));
            threats.push(this.makeThreat(base,
                StrideCategory.Tampering, ThreatSeverity.High,
                `Tampering: Shell execution (${node.rawValue}) may allow an attacker to modify files, install malware, or escalate privileges on the host.`,
                'Run shell commands with least-privilege OS users. Use argument arrays (not shell strings). Apply input sanitization and consider dropping to a sandboxed subprocess.',
                { cweId: 'CWE-78', cweName: 'OS Command Injection', owaspCategory: 'A03:2021 – Injection' }
            ));
        }
    }

    /**
     * Maps a FlowEdge to STRIDE threat entries based on its secure/insecure status.
     * Only insecure edges (red lines in the DFD) produce threat entries.
     */
    private analyzeEdge(edge: FlowEdge, nodes: FlowNode[], threats: ThreatEntry[]): void {
        if (edge.secure) {
            return; // Green edges are secure, no threat to report
        }

        const sourceNode = nodes.find(n => n.id === edge.from);
        if (!sourceNode) {
            return;
        }

        const isDbRelated = sourceNode.label === 'Database Operation' || sourceNode.type === NodeType.DataStore;
        const base = {
            sourceLabel: edge.label,
            filePath: sourceNode.filePath,
            line: sourceNode.line,
            character: sourceNode.character,
            sourceNodeId: edge.from,
            sinkNodeId: edge.to
        };

        if (isDbRelated) {
            threats.push(this.makeThreat(base,
                StrideCategory.ElevationOfPrivilege, ThreatSeverity.High,
                `Elevation of Privilege: Insecure data flow detected (${edge.label}). Data crosses a trust boundary without encryption.`,
                'Encrypt data in transit using TLS. Enforce authentication at the trust boundary. Avoid transmitting raw credentials across network boundaries.',
                { cweId: 'CWE-311', cweName: 'Missing Encryption of Sensitive Data', owaspCategory: 'A02:2021 – Cryptographic Failures' }
            ));
        } else {
            threats.push(this.makeThreat(base,
                StrideCategory.InformationDisclosure, ThreatSeverity.High,
                `Information Disclosure: Insecure data flow detected (${edge.label}). Data crosses a trust boundary without encryption.`,
                'Enforce TLS/HTTPS on all outbound connections. Add a trust boundary check at the sink to verify the connection is encrypted before transmitting data.',
                { cweId: 'CWE-319', cweName: 'Cleartext Transmission of Sensitive Information', owaspCategory: 'A02:2021 – Cryptographic Failures' }
            ));
        }
    }

    /**
     * Maps a TaintedFlow to a Critical severity threat entry.
     * Produces the message format: "Tainted Data Flow: Sensitive variable [X]
     * reached network sink [Y] on Line [Z]."
     */
    private analyzeTaintedFlow(flow: TaintedFlow, nodes: FlowNode[], threats: ThreatEntry[]): void {
        const sinkNode = nodes.find(n => n.id === flow.sinkNodeId);
        const sourceNode = nodes.find(n => n.id === flow.sourceNodeId);
        const targetNode = sinkNode ?? sourceNode;

        if (!targetNode) {
            return;
        }

        const crossFileNote = flow.crossFileSource
            ? ` (imported from ${flow.crossFileSource})`
            : '';

        const base = {
            sourceLabel: `${flow.sourceVar} → ${flow.sinkName}`,
            filePath: targetNode.filePath,
            line: targetNode.line,
            character: targetNode.character,
            sourceNodeId: flow.sourceNodeId,
            sinkNodeId: flow.sinkNodeId
        };

        threats.push(this.makeThreat(base,
            StrideCategory.InformationDisclosure, ThreatSeverity.Critical,
            `Tainted Data Flow: Sensitive variable '${flow.sourceVar}' reached network sink '${flow.sinkName}' on Line ${targetNode.line + 1}${crossFileNote}.`,
            `Sanitize or redact '${flow.sourceVar}' before passing it to '${flow.sinkName}'. Use environment-specific secrets, avoid logging sensitive values, and validate data at trust boundaries.`,
            { cweId: 'CWE-200', cweName: 'Exposure of Sensitive Information to an Unauthorized Actor', owaspCategory: 'A02:2021 – Cryptographic Failures' }
        ));
    }
}
