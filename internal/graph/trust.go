package graph

import (
	"math"
)

// TrustConfig controls trust scoring parameters.
type TrustConfig struct {
	DecayFactor         float64 // Fraction inherited by children (default 0.85)
	InitialTrust        float64 // Starting trust for new processes (default 100)
	ConformalWeight      float64 // Weight for conformal p-value (default 0.5)
	AncestryWeight       float64 // Weight for ancestry trust (default 0.3)
	SeverityWeight       float64 // Weight for technique severity (default 0.2)
}

// DefaultTrustConfig returns the default trust configuration.
func DefaultTrustConfig() TrustConfig {
	return TrustConfig{
		DecayFactor:     0.85,
		InitialTrust:    100.0,
		ConformalWeight: 0.5,
		AncestryWeight:  0.3,
		SeverityWeight:  0.2,
	}
}

// TrustScorer computes and manages trust scores for process nodes.
type TrustScorer struct {
	graph  *CausalGraph
	config TrustConfig
}

// NewTrustScorer creates a trust scorer bound to a causal graph.
func NewTrustScorer(g *CausalGraph, cfg TrustConfig) *TrustScorer {
	return &TrustScorer{graph: g, config: cfg}
}

// ScoringInput holds the inputs needed to compute a trust score.
type ScoringInput struct {
	ConformalPValue         float64 // From conformal calibration layer
	ParentTrust             float64 // Trust of parent process
	MatchedTechniqueSeverity float64 // Severity of matched ATT&CK technique (0-10)
}

// ComputeTrust computes trust(process) = f(conformal_p_value, ancestry_trust_inheritance, matched_technique_severity).
//
// The formula blends three signals:
//   - Conformal p-value: higher p = more normal → higher trust
//   - Ancestry trust: children inherit decayed parent trust
//   - Technique severity: matched ATT&CK severity reduces trust
func (ts *TrustScorer) ComputeTrust(input ScoringInput) float64 {
	cfg := ts.config

	// Conformal component: p-value directly maps to trust contribution
	// p=1.0 → full trust, p=0.0 → zero trust from this component
	conformalTrust := input.ConformalPValue * cfg.InitialTrust

	// Ancestry component: decayed parent trust
	ancestryTrust := input.ParentTrust * cfg.DecayFactor

	// Severity component: severity inversely maps to trust
	// severity=0 → no reduction, severity=10 → maximum reduction
	severityPenalty := (input.MatchedTechniqueSeverity / 10.0) * cfg.InitialTrust

	trust := (cfg.ConformalWeight * conformalTrust) +
		(cfg.AncestryWeight * ancestryTrust) -
		(cfg.SeverityWeight * severityPenalty)

	// Clamp to [0, 100]
	trust = math.Max(0, math.Min(cfg.InitialTrust, trust))

	return math.Round(trust*100) / 100
}

// UpdateProcessTrust computes and applies a new trust score for a process.
func (ts *TrustScorer) UpdateProcessTrust(pid uint32, input ScoringInput) float64 {
	// Get parent trust if not provided
	if input.ParentTrust == 0 {
		node, ok := ts.graph.GetProcessNode(pid)
		if ok && node.PPID > 0 {
			parent, parentOK := ts.graph.GetProcessNode(node.PPID)
			if parentOK {
				input.ParentTrust = parent.Trust
			} else {
				input.ParentTrust = ts.config.InitialTrust
			}
		} else {
			input.ParentTrust = ts.config.InitialTrust
		}
	}

	trust := ts.ComputeTrust(input)
	nodeID := processNodeID(pid)
	ts.graph.UpdateTrust(nodeID, trust)
	return trust
}

// TrustTier returns a human-readable tier for a trust score.
func TrustTier(trust float64) string {
	switch {
	case trust >= 70:
		return "trusted"
	case trust >= 30:
		return "suspicious"
	default:
		return "hostile"
	}
}

// TrustColor returns a CSS-friendly color for the trust tier (matches ZTNA dashboard).
func TrustColor(trust float64) string {
	switch {
	case trust >= 70:
		return "#10b981" // Green
	case trust >= 30:
		return "#f59e0b" // Amber
	default:
		return "#ef4444" // Red
	}
}
