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
}

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
     * Maps a single FlowNode to zero or more STRIDE threat entries
     * based on its type, label, and raw value.
     */
    private analyzeNode(node: FlowNode, threats: ThreatEntry[]): void {
        const base = {
            sourceLabel: node.label,
            filePath: node.filePath,
            line: node.line,
            character: node.character
        };

        // HTTP Call nodes
        if (node.label === 'HTTP Call') {
            const isInsecure = node.rawValue.startsWith('http://');
            if (isInsecure) {
                threats.push({
                    ...base,
                    category: StrideCategory.InformationDisclosure,
                    severity: ThreatSeverity.High,
                    message: 'Information Disclosure: Data is sent over unencrypted HTTP. An attacker on the network can intercept sensitive data in transit.'
                });
                threats.push({
                    ...base,
                    category: StrideCategory.Tampering,
                    severity: ThreatSeverity.High,
                    message: 'Tampering: Unencrypted HTTP allows man-in-the-middle attacks. Response data could be modified before reaching the application.'
                });
            }
        }

        // Database connection strings with hardcoded credentials
        if (node.label === 'Database Connection') {
            threats.push({
                ...base,
                category: StrideCategory.ElevationOfPrivilege,
                severity: ThreatSeverity.Critical,
                message: 'Elevation of Privilege: Hardcoded credentials detected in database connection string. An attacker gaining access to source code obtains direct database access.'
            });
            threats.push({
                ...base,
                category: StrideCategory.InformationDisclosure,
                severity: ThreatSeverity.High,
                message: 'Information Disclosure: Database connection string is visible in source code. Credentials should be stored in a secrets manager, not in code.'
            });
        }

        // Environment variable access
        if (node.label === 'Environment Variables') {
            threats.push({
                ...base,
                category: StrideCategory.InformationDisclosure,
                severity: ThreatSeverity.Medium,
                message: 'Information Disclosure: Environment variables may expose API keys, tokens, or secrets if the runtime environment is compromised or logged.'
            });
        }

        // Hardcoded localhost
        if (node.label === 'Localhost') {
            threats.push({
                ...base,
                category: StrideCategory.Tampering,
                severity: ThreatSeverity.Medium,
                message: 'Tampering: Hardcoded localhost binding may be bypassed in production. Services should bind to configurable addresses validated at deployment.'
            });
            threats.push({
                ...base,
                category: StrideCategory.DenialOfService,
                severity: ThreatSeverity.Low,
                message: 'Denial of Service: Localhost-only bindings in production may cause service unavailability when deployed to non-local environments.'
            });
        }

        // Database operation nodes (ORM calls, pool.query, etc.)
        if (node.label === 'Database Operation') {
            threats.push({
                ...base,
                category: StrideCategory.InformationDisclosure,
                severity: ThreatSeverity.Medium,
                message: `Information Disclosure: Database operation detected (${node.rawValue}). Ensure queries are parameterized and results are not inadvertently leaked.`
            });
            threats.push({
                ...base,
                category: StrideCategory.Tampering,
                severity: ThreatSeverity.Medium,
                message: `Tampering: Database operation (${node.rawValue}) may be vulnerable to SQL/NoSQL injection if inputs are not properly validated.`
            });
        }

        // Code execution nodes (eval, Function)
        if (node.label === 'Code Execution') {
            threats.push({
                ...base,
                category: StrideCategory.ElevationOfPrivilege,
                severity: ThreatSeverity.Critical,
                message: `Elevation of Privilege: Dynamic code execution via ${node.rawValue}(). An attacker providing controlled input can execute arbitrary code in the runtime.`
            });
            threats.push({
                ...base,
                category: StrideCategory.Tampering,
                severity: ThreatSeverity.Critical,
                message: `Tampering: ${node.rawValue}() allows arbitrary code injection. Remove or replace with safe alternatives.`
            });
        }

        // Shell execution nodes (child_process.exec, spawn, etc.)
        if (node.label === 'Shell Execution') {
            threats.push({
                ...base,
                category: StrideCategory.ElevationOfPrivilege,
                severity: ThreatSeverity.Critical,
                message: `Elevation of Privilege: Shell command execution via ${node.rawValue}(). Command injection can grant full system-level access.`
            });
            threats.push({
                ...base,
                category: StrideCategory.Tampering,
                severity: ThreatSeverity.High,
                message: `Tampering: Shell execution (${node.rawValue}) may allow an attacker to modify files, install malware, or escalate privileges on the host.`
            });
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
        
        threats.push({
            category: isDbRelated ? StrideCategory.ElevationOfPrivilege : StrideCategory.InformationDisclosure,
            severity: ThreatSeverity.High,
            message: `${isDbRelated ? 'Elevation of Privilege' : 'Information Disclosure'}: Insecure data flow detected (${edge.label}). Data crosses a trust boundary without encryption.`,
            sourceLabel: edge.label,
            filePath: sourceNode.filePath,
            line: sourceNode.line,
            character: sourceNode.character
        });
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

        threats.push({
            category: StrideCategory.InformationDisclosure,
            severity: ThreatSeverity.Critical,
            message: `Tainted Data Flow: Sensitive variable '${flow.sourceVar}' reached network sink '${flow.sinkName}' on Line ${targetNode.line + 1}${crossFileNote}.`,
            sourceLabel: `${flow.sourceVar} → ${flow.sinkName}`,
            filePath: targetNode.filePath,
            line: targetNode.line,
            character: targetNode.character
        });
    }
}
