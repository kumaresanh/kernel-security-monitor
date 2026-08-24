package graph

import (
	"encoding/json"
	"math"
	"os"
	"sync"
)

// FeatureVector holds the curated feature set for Isolation Forest scoring.
// No raw event counts — only structural and behavioral features.
type FeatureVector struct {
	FanOutDegree    float64 `json:"fan_out_degree"`
	EdgeTypeEntropy float64 `json:"edge_type_entropy"`
	NgramRarity     float64 `json:"ngram_rarity"`
	AncestryDepth   float64 `json:"ancestry_depth"`
}

// ToSlice returns the feature vector as a float64 slice for the Python sidecar.
func (f FeatureVector) ToSlice() []float64 {
	return []float64{f.FanOutDegree, f.EdgeTypeEntropy, f.NgramRarity, f.AncestryDepth}
}

// NgramBaseline holds precomputed trigram frequencies from a benign corpus.
type NgramBaseline struct {
	mu       sync.RWMutex
	trigrams map[string]float64 // trigram string -> frequency
}

// LoadNgramBaseline loads the n-gram baseline from a JSON file.
func LoadNgramBaseline(path string) (*NgramBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Return empty baseline if file doesn't exist (will treat all trigrams as rare)
		if os.IsNotExist(err) {
			return &NgramBaseline{trigrams: make(map[string]float64)}, nil
		}
		return nil, err
	}
	var trigrams map[string]float64
	if err := json.Unmarshal(data, &trigrams); err != nil {
		return nil, err
	}
	return &NgramBaseline{trigrams: trigrams}, nil
}

// FeatureExtractor computes feature vectors from the causal graph.
type FeatureExtractor struct {
	graph    *CausalGraph
	baseline *NgramBaseline
	// Sliding window of recent syscall types per PID for n-gram computation
	mu       sync.Mutex
	windows  map[uint32][]string // pid -> recent syscall types (sliding window)
}

const ngramWindowSize = 50

// NewFeatureExtractor creates a feature extractor bound to a graph.
func NewFeatureExtractor(g *CausalGraph, baseline *NgramBaseline) *FeatureExtractor {
	return &FeatureExtractor{
		graph:    g,
		baseline: baseline,
		windows:  make(map[uint32][]string),
	}
}

// RecordSyscall adds a syscall type to the sliding window for n-gram computation.
func (fe *FeatureExtractor) RecordSyscall(pid uint32, syscallType string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	w := fe.windows[pid]
	w = append(w, syscallType)
	if len(w) > ngramWindowSize {
		w = w[len(w)-ngramWindowSize:]
	}
	fe.windows[pid] = w
}

// Extract computes the feature vector for a given process node.
func (fe *FeatureExtractor) Extract(pid uint32) FeatureVector {
	nodeID := processNodeID(pid)

	return FeatureVector{
		FanOutDegree:    fe.fanOutDegree(nodeID),
		EdgeTypeEntropy: fe.edgeTypeEntropy(nodeID),
		NgramRarity:     fe.ngramRarity(pid),
		AncestryDepth:   float64(fe.graph.AncestryDepth(pid)),
	}
}

// fanOutDegree returns the number of distinct outgoing edges from a process node.
func (fe *FeatureExtractor) fanOutDegree(nodeID string) float64 {
	edges := fe.graph.OutEdges(nodeID)
	return float64(len(edges))
}

// edgeTypeEntropy returns Shannon entropy over edge type distribution.
func (fe *FeatureExtractor) edgeTypeEntropy(nodeID string) float64 {
	edges := fe.graph.OutEdges(nodeID)
	if len(edges) == 0 {
		return 0
	}

	counts := make(map[EdgeType]int)
	for _, e := range edges {
		counts[e.Type]++
	}

	total := float64(len(edges))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ngramRarity returns the average rarity of syscall trigrams vs. the offline baseline.
// Higher values = more unusual behavior.
func (fe *FeatureExtractor) ngramRarity(pid uint32) float64 {
	fe.mu.Lock()
	window := make([]string, len(fe.windows[pid]))
	copy(window, fe.windows[pid])
	fe.mu.Unlock()

	if len(window) < 3 {
		return 0 // Not enough data for trigrams
	}

	fe.baseline.mu.RLock()
	defer fe.baseline.mu.RUnlock()

	totalRarity := 0.0
	count := 0
	for i := 0; i <= len(window)-3; i++ {
		trigram := window[i] + "," + window[i+1] + "," + window[i+2]
		freq, ok := fe.baseline.trigrams[trigram]
		if !ok {
			// Unseen trigram — maximum rarity
			totalRarity += 1.0
		} else {
			// Rarity = 1 - frequency (normalized)
			totalRarity += (1.0 - freq)
		}
		count++
	}

	if count == 0 {
		return 0
	}
	return totalRarity / float64(count)
}

func processNodeID(pid uint32) string {
	return "proc:" + uitoa(pid)
}

func uitoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for u > 0 {
		buf = append(buf, byte('0'+u%10))
		u /= 10
	}
	// Reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
