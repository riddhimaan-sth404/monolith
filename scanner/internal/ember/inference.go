package ember

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/edr/scanner/internal/parser"
)

// Model represents a LightGBM tree ensemble model serialized as JSON.
type Model struct {
	Name        string             `json:"name"`
	Task        string             `json:"task"`
	NumClasses  int                `json:"num_classes"`
	NumFeatures int                `json:"num_features"`
	Trees       []json.RawMessage  `json:"trees"`
	parsedTrees []*TreeNode
}

// Threshold holds either a numeric split value or a categorical category set.
type Threshold struct {
	FloatVal *float64
	CatSet   map[int]struct{}
}

func (t *Threshold) UnmarshalJSON(data []byte) error {
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		t.FloatVal = &f
		t.CatSet = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("threshold must be float64 or string, got %s", string(data))
	}
	t.CatSet = make(map[int]struct{})
	for _, p := range strings.Split(s, "||") {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			continue
		}
		t.CatSet[v] = struct{}{}
	}
	return nil
}

// TreeNode represents a node in a decision tree.
type TreeNode struct {
	SplitFeature   *int       `json:"split_feature,omitempty"`
	SplitThreshold *Threshold `json:"split_threshold,omitempty"`
	DefaultLeft    *bool      `json:"default_left,omitempty"`
	LeafValue      *float64   `json:"leaf_value,omitempty"`
	Left           *TreeNode  `json:"left,omitempty"`
	Right          *TreeNode  `json:"right,omitempty"`
}

// LoadModel reads a JSON model file and returns a parsed Model.
func LoadModel(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read model file: %w", err)
	}
	return ParseModel(data)
}

// ParseModel parses JSON model data into a Model.
func ParseModel(data []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse model json: %w", err)
	}
	m.parsedTrees = make([]*TreeNode, len(m.Trees))
	for i, raw := range m.Trees {
		var node TreeNode
		if err := json.Unmarshal(raw, &node); err != nil {
			return nil, fmt.Errorf("parse tree %d: %w", i, err)
		}
		m.parsedTrees[i] = &node
	}
	return &m, nil
}

// Predict runs inference on a feature vector and returns a score in [0, 1].
func (m *Model) Predict(features []float32) float64 {
	if len(m.parsedTrees) == 0 {
		return 0.0
	}
	var sum float64
	for _, tree := range m.parsedTrees {
		sum += evaluateTree(tree, features)
	}
	// Average and apply sigmoid for binary classification
	avg := sum / float64(len(m.parsedTrees))
	return sigmoid(avg)
}

// evaluateTree traverses a tree for the given features and returns the leaf value.
func evaluateTree(node *TreeNode, features []float32) float64 {
	if node == nil {
		return 0
	}
	if node.LeafValue != nil {
		return *node.LeafValue
	}
	if node.SplitFeature == nil || node.SplitThreshold == nil {
		return 0
	}

	idx := *node.SplitFeature
	var featureVal float64
	if idx >= 0 && idx < len(features) {
		featureVal = float64(features[idx])
	}

	var goLeft bool
	if node.SplitThreshold.CatSet != nil {
		intVal := int(featureVal)
		_, goLeft = node.SplitThreshold.CatSet[intVal]
		if math.IsNaN(featureVal) {
			goLeft = node.DefaultLeft != nil && *node.DefaultLeft
		}
	} else if node.SplitThreshold.FloatVal != nil {
		thresh := *node.SplitThreshold.FloatVal
		if node.DefaultLeft != nil && *node.DefaultLeft {
			goLeft = featureVal <= thresh || math.IsNaN(featureVal)
		} else {
			goLeft = featureVal <= thresh
		}
	}

	if goLeft {
		return evaluateTree(node.Left, features)
	}
	return evaluateTree(node.Right, features)
}

// sigmoid converts raw score to probability in [0, 1].
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// PredictFromBytes is a convenience: extracts features and runs inference in one call.
func PredictFromBytes(data []byte, peInfo *parser.PEInfo, model *Model) ([]float32, float64, error) {
	if model == nil {
		return nil, 0.5, fmt.Errorf("model is nil")
	}
	features := Extract(data, peInfo)
	score := model.Predict(features)
	return features, score, nil
}
