// Package graph implements an in-memory streaming causal graph for process provenance tracking.
package graph

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// NodeType represents the type of a node in the causal graph.
type NodeType int

const (
	NodeProcess NodeType = iota
	NodeFile
	NodeSocket
)

func (t NodeType) String() string {
	switch t {
	case NodeProcess:
		return "process"
	case NodeFile:
		return "file"
	case NodeSocket:
		return "socket"
	default:
		return "unknown"
	}
}

func (t NodeType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// EdgeType represents the type of a causal edge.
type EdgeType int

const (
	EdgeExec      EdgeType = iota
	EdgeOpenRead
	EdgeOpenWrite
	EdgeConnect
	EdgeFork
)

func (t EdgeType) String() string {
	switch t {
	case EdgeExec:
		return "exec"
	case EdgeOpenRead:
		return "open_read"
	case EdgeOpenWrite:
		return "open_write"
	case EdgeConnect:
		return "connect"
	case EdgeFork:
		return "fork"
	default:
		return "unknown"
	}
}

func (t EdgeType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Node represents a vertex in the causal graph.
type Node struct {
	ID       string   `json:"id"`
	Type     NodeType `json:"type"`
	Label    string   `json:"label"`
	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Path     string   `json:"path,omitempty"`
	Addr     string   `json:"addr,omitempty"`
	Port     uint16   `json:"port,omitempty"`
	Trust    float64  `json:"trust"`
	FirstSeen time.Time `json:"first_seen"`
}

// Edge represents a causal relationship between two nodes.
type Edge struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Type      EdgeType  `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CausalGraph is a thread-safe in-memory directed graph for process provenance.
type CausalGraph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges []*Edge
	// Adjacency lists
	outEdges map[string][]*Edge // from -> edges
	inEdges  map[string][]*Edge // to -> edges
	// Process tree
	children map[uint32][]uint32 // ppid -> [child pids]
	pidNode  map[uint32]*Node   // pid -> process node
	// Edge counter for unique IDs
	edgeCounter int
	// Listeners for streaming
	listeners []chan<- GraphEvent
	listenerMu sync.RWMutex
}

// GraphEvent is emitted when the graph changes.
type GraphEvent struct {
	Type    string      `json:"type"` // "node_added", "edge_added"
	Payload interface{} `json:"payload"`
}

// New creates a new empty causal graph.
func New() *CausalGraph {
	return &CausalGraph{
		nodes:    make(map[string]*Node),
		outEdges: make(map[string][]*Edge),
		inEdges:  make(map[string][]*Edge),
		children: make(map[uint32][]uint32),
		pidNode:  make(map[uint32]*Node),
	}
}

// AddProcessNode adds or updates a process node.
func (g *CausalGraph) AddProcessNode(pid, ppid uint32, comm string) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := fmt.Sprintf("proc:%d", pid)
	if existing, ok := g.nodes[id]; ok {
		return existing
	}

	node := &Node{
		ID:        id,
		Type:      NodeProcess,
		Label:     fmt.Sprintf("%s [%d]", comm, pid),
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		Trust:     100.0, // Initial trust
		FirstSeen: time.Now(),
	}
	g.nodes[id] = node
	g.pidNode[pid] = node

	// Track parent-child relationship
	if ppid > 0 {
		g.children[ppid] = append(g.children[ppid], pid)
		// Inherit trust from parent (preserve full trust for benign trees)
		if parent, ok := g.pidNode[ppid]; ok {
			if parent.Trust >= 70.0 {
				node.Trust = parent.Trust // Benign parent keeps full trust for child
			} else {
				node.Trust = parent.Trust * 0.90 // Only decay if parent is already degraded
			}
		}
	}

	g.emit(GraphEvent{Type: "node_added", Payload: node})
	return node
}

// SetProcessTrust explicitly updates the trust score of a process and its graph node.
func (g *CausalGraph) SetProcessTrust(pid uint32, trust float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := fmt.Sprintf("proc:%d", pid)
	if node, ok := g.nodes[id]; ok {
		node.Trust = trust
	}
	if pNode, ok := g.pidNode[pid]; ok {
		pNode.Trust = trust
	}
}

// GetProcessContext extracts rich causal provenance details for a specific PID for AI analysis.
func (g *CausalGraph) GetProcessContext(pid uint32) map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()

	procID := fmt.Sprintf("proc:%d", pid)
	node, ok := g.nodes[procID]
	if !ok {
		return map[string]interface{}{"pid": pid, "found": false}
	}

	var parentComm string
	if parentNode, ok := g.pidNode[node.PPID]; ok {
		parentComm = parentNode.Comm
	}

	var files []string
	var sockets []string
	var children []uint32

	// Outgoing edges
	for _, edge := range g.outEdges[procID] {
		if target, ok := g.nodes[edge.To]; ok {
			switch target.Type {
			case NodeFile:
				files = append(files, target.Path)
			case NodeSocket:
				sockets = append(sockets, fmt.Sprintf("%s:%d", target.Addr, target.Port))
			}
		}
	}

	if childList, ok := g.children[pid]; ok {
		children = childList
	}

	return map[string]interface{}{
		"found":       true,
		"pid":         pid,
		"ppid":        node.PPID,
		"parent_comm": parentComm,
		"comm":        node.Comm,
		"trust":       node.Trust,
		"first_seen":  node.FirstSeen.Format(time.RFC3339),
		"files":       files,
		"sockets":     sockets,
		"children":    children,
	}
}


// AddFileNode adds or retrieves a file node.
func (g *CausalGraph) AddFileNode(path string) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := fmt.Sprintf("file:%s", path)
	if existing, ok := g.nodes[id]; ok {
		return existing
	}

	node := &Node{
		ID:        id,
		Type:      NodeFile,
		Label:     path,
		Path:      path,
		Trust:     100.0,
		FirstSeen: time.Now(),
	}
	g.nodes[id] = node
	g.emit(GraphEvent{Type: "node_added", Payload: node})
	return node
}

// AddSocketNode adds or retrieves a socket node.
func (g *CausalGraph) AddSocketNode(addr string, port uint16) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := fmt.Sprintf("sock:%s:%d", addr, port)
	if existing, ok := g.nodes[id]; ok {
		return existing
	}

	node := &Node{
		ID:        id,
		Type:      NodeSocket,
		Label:     fmt.Sprintf("%s:%d", addr, port),
		Addr:      addr,
		Port:      port,
		Trust:     100.0,
		FirstSeen: time.Now(),
	}
	g.nodes[id] = node
	g.emit(GraphEvent{Type: "node_added", Payload: node})
	return node
}

// AddEdge adds a causal edge between two nodes.
func (g *CausalGraph) AddEdge(fromID, toID string, edgeType EdgeType, metadata map[string]interface{}) *Edge {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.edgeCounter++
	edge := &Edge{
		ID:        fmt.Sprintf("e%d", g.edgeCounter),
		From:      fromID,
		To:        toID,
		Type:      edgeType,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
	g.edges = append(g.edges, edge)
	g.outEdges[fromID] = append(g.outEdges[fromID], edge)
	g.inEdges[toID] = append(g.inEdges[toID], edge)
	g.emit(GraphEvent{Type: "edge_added", Payload: edge})
	return edge
}

// GetNode returns a node by ID.
func (g *CausalGraph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// GetProcessNode returns the process node for a given PID.
func (g *CausalGraph) GetProcessNode(pid uint32) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.pidNode[pid]
	return n, ok
}

// OutEdges returns all outgoing edges from a node.
func (g *CausalGraph) OutEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.outEdges[nodeID]
}

// InEdges returns all incoming edges to a node.
func (g *CausalGraph) InEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.inEdges[nodeID]
}

// AncestryDepth returns the depth of a process in the process tree (distance to PID 1 or root).
func (g *CausalGraph) AncestryDepth(pid uint32) int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	depth := 0
	current := pid
	seen := make(map[uint32]bool)
	for {
		node, ok := g.pidNode[current]
		if !ok || current <= 1 || seen[current] {
			break
		}
		seen[current] = true
		current = node.PPID
		depth++
	}
	return depth
}

// Subgraph extracts the causal subgraph rooted at a given node ID.
func (g *CausalGraph) Subgraph(rootID string) (*SubgraphResult, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	root, ok := g.nodes[rootID]
	if !ok {
		return nil, false
	}

	result := &SubgraphResult{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}

	// BFS from root
	queue := []string{root.ID}
	visited := map[string]bool{root.ID: true}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result.Nodes[current] = g.nodes[current]

		for _, edge := range g.outEdges[current] {
			result.Edges = append(result.Edges, edge)
			if !visited[edge.To] {
				visited[edge.To] = true
				queue = append(queue, edge.To)
			}
		}
	}

	return result, true
}

// SubgraphResult contains the nodes and edges of an extracted subgraph.
type SubgraphResult struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []*Edge          `json:"edges"`
}

// Snapshot returns a serializable snapshot of the entire graph.
// Deep-copies nodes to avoid races with concurrent UpdateTrust() calls.
func (g *CausalGraph) Snapshot() *SubgraphResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make(map[string]*Node, len(g.nodes))
	for k, v := range g.nodes {
		nodeCopy := *v // copy by value
		nodes[k] = &nodeCopy
	}
	edges := make([]*Edge, len(g.edges))
	copy(edges, g.edges)

	return &SubgraphResult{Nodes: nodes, Edges: edges}
}

// Stats returns graph statistics.
func (g *CausalGraph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	procCount, fileCount, sockCount := 0, 0, 0
	for _, n := range g.nodes {
		switch n.Type {
		case NodeProcess:
			procCount++
		case NodeFile:
			fileCount++
		case NodeSocket:
			sockCount++
		}
	}

	return map[string]int{
		"nodes_total":   len(g.nodes),
		"nodes_process": procCount,
		"nodes_file":    fileCount,
		"nodes_socket":  sockCount,
		"edges_total":   len(g.edges),
	}
}

// UpdateTrust updates the trust score for a node.
func (g *CausalGraph) UpdateTrust(nodeID string, trust float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if node, ok := g.nodes[nodeID]; ok {
		node.Trust = trust
		// Propagate decayed trust to children if it's a process
		if node.Type == NodeProcess {
			g.propagateTrust(node.PID, trust)
		}
	}
}

func (g *CausalGraph) propagateTrust(pid uint32, parentTrust float64) {
	childPIDs := g.children[pid]
	for _, childPID := range childPIDs {
		if childNode, ok := g.pidNode[childPID]; ok {
			childNode.Trust = parentTrust * 0.85
			g.propagateTrust(childPID, childNode.Trust)
		}
	}
}

// Subscribe adds a listener for graph events.
func (g *CausalGraph) Subscribe() <-chan GraphEvent {
	ch := make(chan GraphEvent, 128)
	g.listenerMu.Lock()
	g.listeners = append(g.listeners, ch)
	g.listenerMu.Unlock()
	return ch
}

func (g *CausalGraph) emit(event GraphEvent) {
	g.listenerMu.RLock()
	defer g.listenerMu.RUnlock()
	for _, l := range g.listeners {
		select {
		case l <- event:
		default: // Drop if listener is slow
		}
	}
}
