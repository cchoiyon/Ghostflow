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
    /**
     * Whether this node is an intermediate alias (e.g. const x = y).
     * Internal nodes are hidden in the "Compressed View" to reduce clutter.
     */
    isInternal?: boolean;
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
    /** Whether this edge represents a tainted data flow (sensitive source → dangerous sink). */
    tainted: boolean;
}

/**
 * Represents a detected tainted data flow where a sensitive source variable
 * is passed as an argument to a dangerous sink function.
 *
 * Security implication: tainted flows indicate that secrets, keys, or credentials
 * may be leaked via network calls, file writes, or logging.
 */
export interface TaintedFlow {
    /** Name of the sensitive source variable (e.g. 'apiKey', 'dbPassword'). */
    sourceVar: string;
    /** Name of the dangerous sink function (e.g. 'fetch', 'console.log'). */
    sinkName: string;
    /** FlowNode ID of the sink call site. */
    sinkNodeId: string;
    /** FlowNode ID of the source variable declaration. */
    sourceNodeId: string;
    /** If the taint originated from another file, the basename of that file. */
    crossFileSource?: string;
}

/**
 * Manages the collection of Process Nodes, Data Stores, and edges
 * identified during AST scanning. Forms the core data structure
 * for the DFD visualization.
 */
export class FlowGraph {
    private nodes: Map<string, FlowNode> = new Map();
    private edges: FlowEdge[] = [];
    private taintedFlows: TaintedFlow[] = [];
    private _edgeKeys: Set<string> = new Set();

    /**
     * Adds a new node to the graph representing an identified security pattern or boundary.
     * @param node The FlowNode to add.
     */
    public addNode(node: FlowNode): void {
        this.nodes.set(node.id, node);
    }

    /**
     * Adds a directed edge between two nodes, representing a data flow relationship.
     * Prevents duplicate edges from being added to the graph.
     * @param edge The FlowEdge to add.
     */
    public addEdge(edge: FlowEdge): void {
        const key = `${edge.from}→${edge.to}:${edge.label}`;
        if (!this._edgeKeys.has(key)) {
            this._edgeKeys.add(key);
            this.edges.push(edge);
        }
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
     * Returns a compressed version of the graph's edges by bypassing intermediate "isInternal" nodes.
     * For any chain A -> B1 -> B2 -> C, if all B nodes are isInternal, it returns A -> C.
     * Security flags (tainted, secure) are preserved across the chain.
     */
    public getCompressedEdges(): FlowEdge[] {
        const compressed: FlowEdge[] = [];
        const internalNodeIds = new Set(
            this.getNodes().filter(n => n.isInternal).map(n => n.id)
        );

        // Build adjacency map for internal traversal
        const adj = new Map<string, FlowEdge[]>();
        for (const edge of this.edges) {
            if (!adj.has(edge.from)) adj.set(edge.from, []);
            adj.get(edge.from)!.push(edge);
        }

        // Process edges starting from non-internal nodes
        for (const startNode of this.getNodes()) {
            if (startNode.isInternal) continue;

            const edgesFromStart = adj.get(startNode.id) || [];
            for (const rootEdge of edgesFromStart) {
                this.tracePath(rootEdge, internalNodeIds, adj, compressed);
            }
        }

        return compressed;
    }

    /**
     * Recursively traces a path through internal nodes to find the next meaningful sink/process.
     */
    private tracePath(
        currentEdge: FlowEdge, 
        internalNodeIds: Set<string>, 
        adj: Map<string, FlowEdge[]>, 
        results: FlowEdge[]
    ): void {
        if (!internalNodeIds.has(currentEdge.to)) {
            // Reached a non-internal node, add the compressed edge
            results.push(currentEdge);
            return;
        }

        // currentEdge.to is an internal node, recurse into its children
        const children = adj.get(currentEdge.to) || [];
        for (const child of children) {
            const mergedEdge: FlowEdge = {
                from: currentEdge.from,
                to: child.to,
                label: currentEdge.label === child.label ? currentEdge.label : `${currentEdge.label} → ${child.label}`,
                secure: currentEdge.secure && child.secure,
                tainted: currentEdge.tainted || child.tainted
            };
            this.tracePath(mergedEdge, internalNodeIds, adj, results);
        }
    }

    /**
     * Adds a tainted data flow record.
     * @param flow The TaintedFlow to record.
     */
    public addTaintedFlow(flow: TaintedFlow): void {
        this.taintedFlows.push(flow);
    }

    /**
     * Retrieves all recorded tainted flows.
     * @returns Array of TaintedFlow records.
     */
    public getTaintedFlows(): TaintedFlow[] {
        return [...this.taintedFlows];
    }

    /**
     * Clears all nodes, edges, and tainted flows from the graph.
     */
    public clear(): void {
        this.nodes.clear();
        this.edges = [];
        this.taintedFlows = [];
        this._edgeKeys.clear();
    }

    /**
     * Clears all nodes, edges, and tainted flows associated with a specific file.
     * This allows for incremental, single-file updates without wiping the workspace graph.
     * @param filePath Absolute path of the file to clear.
     */
    public clearForFile(filePath: string): void {
        const filePrefix = filePath + ':';
        
        // Remove nodes belonging to this file
        for (const [id, node] of this.nodes.entries()) {
            if (node.filePath === filePath) {
                this.nodes.delete(id);
            }
        }
        
        // Remove edges where either the source or target node belongs to this file
        this.edges = this.edges.filter(e => {
            const keep = !e.from.startsWith(filePrefix) && !e.to.startsWith(filePrefix);
            if (!keep) {
                this._edgeKeys.delete(`${e.from}→${e.to}:${e.label}`);
            }
            return keep;
        });
        
        // Remove tainted flows originating from or sinking into this file
        this.taintedFlows = this.taintedFlows.filter(f => !f.sourceNodeId.startsWith(filePrefix) && !f.sinkNodeId.startsWith(filePrefix));
    }
}
