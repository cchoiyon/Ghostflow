/**
 * Represents the type of a node in the FlowGraph.
 */
export enum NodeType {
    ProcessNode = 'ProcessNode',
    DataStore = 'DataStore'
}

/**
 * Represents a node within the Data Flow Diagram (DFD).
 * Each node maps to a detected security pattern in the source code.
 */
export interface FlowNode {
    /** Unique identifier combining file path, line, and character. */
    id: string;
    /** Whether this is a ProcessNode or DataStore. */
    type: NodeType;
    /** Human-readable label displayed in the DFD. */
    label: string;
    /** TSDoc-style description of the security implication. */
    description: string;
    /** Absolute path to the source file containing this pattern. */
    filePath: string;
    /** Zero-indexed line number in the source file. */
    line: number;
    /** Zero-indexed character offset on the line. */
    character: number;
    /**
     * The raw string value extracted from the AST (e.g. the URL or connection string).
     * Used to determine http:// vs https:// for trust boundary coloring.
     */
    rawValue: string;
}

/**
 * Represents a directed edge between two FlowNodes in the DFD.
 * Security implication: edges crossing trust boundaries indicate data flow
 * that must be validated and secured at transit.
 */
export interface FlowEdge {
    /** ID of the source FlowNode. */
    from: string;
    /** ID of the target FlowNode. */
    to: string;
    /** Label displayed on the edge arrow in the DFD. */
    label: string;
    /** Whether the connection uses a secure protocol (https vs http). */
    secure: boolean;
}

/**
 * Manages the collection of Process Nodes, Data Stores, and edges
 * identified during AST scanning. Forms the core data structure
 * for the DFD visualization.
 */
export class FlowGraph {
    private nodes: Map<string, FlowNode> = new Map();
    private edges: FlowEdge[] = [];

    /**
     * Adds a new node to the graph representing an identified security pattern or boundary.
     * @param node The FlowNode to add.
     */
    public addNode(node: FlowNode): void {
        this.nodes.set(node.id, node);
    }

    /**
     * Adds a directed edge between two nodes, representing a data flow relationship.
     * @param edge The FlowEdge to add.
     */
    public addEdge(edge: FlowEdge): void {
        this.edges.push(edge);
    }

    /**
     * Retrieves all recorded nodes.
     * @returns Array of FlowNodes.
     */
    public getNodes(): FlowNode[] {
        return Array.from(this.nodes.values());
    }

    /**
     * Retrieves all recorded edges.
     * @returns Array of FlowEdges.
     */
    public getEdges(): FlowEdge[] {
        return [...this.edges];
    }

    /**
     * Clears all nodes and edges from the graph. Useful for re-scanning a file.
     */
    public clear(): void {
        this.nodes.clear();
        this.edges = [];
    }
}
