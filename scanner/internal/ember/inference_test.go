package ember

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/edr/scanner/internal/parser"
)

func TestParseModel(t *testing.T) {
	modelJSON := `{
		"name": "test",
		"task": "binary",
		"num_classes": 1,
		"num_features": 2381,
		"trees": [
			{
				"split_feature": 0,
				"split_threshold": 0.5,
				"default_left": true,
				"left": {"leaf_value": -0.5},
				"right": {"leaf_value": 0.5}
			}
		]
	}`

	model, err := ParseModel([]byte(modelJSON))
	if err != nil {
		t.Fatalf("ParseModel failed: %v", err)
	}
	if model.Name != "test" {
		t.Fatalf("expected name 'test', got '%s'", model.Name)
	}
	if len(model.parsedTrees) != 1 {
		t.Fatalf("expected 1 tree, got %d", len(model.parsedTrees))
	}
}

func TestParseModelComplex(t *testing.T) {
	modelJSON := `{
		"name": "complex",
		"task": "binary",
		"num_classes": 1,
		"num_features": 2381,
		"trees": [
			{
				"split_feature": 0,
				"split_threshold": 0.5,
				"default_left": true,
				"left": {
					"split_feature": 1,
					"split_threshold": 0.3,
					"default_left": false,
					"left": {"leaf_value": -1.0},
					"right": {"leaf_value": -0.3}
				},
				"right": {
					"split_feature": 2,
					"split_threshold": 0.7,
					"default_left": true,
					"left": {"leaf_value": 0.2},
					"right": {"leaf_value": 1.5}
				}
			}
		]
	}`

	model, err := ParseModel([]byte(modelJSON))
	if err != nil {
		t.Fatalf("ParseModel failed: %v", err)
	}
	if len(model.parsedTrees) != 1 {
		t.Fatalf("expected 1 tree, got %d", len(model.parsedTrees))
	}
}

func TestPredictLowScore(t *testing.T) {
	// Tree: if feature[0] <= 0.5 → leaf -0.5 (low score) else → leaf 0.5
	model := &Model{
		parsedTrees: []*TreeNode{
			{
				SplitFeature:   intPtr(0),
				SplitThreshold: thresholdPtr(0.5),
				DefaultLeft:    boolPtr(true),
				Left:           &TreeNode{LeafValue: float64Ptr(-0.5)},
				Right:          &TreeNode{LeafValue: float64Ptr(0.5)},
			},
		},
	}

	features := make([]float32, 2381)
	features[0] = 0.2 // <= 0.5 → goes left → leaf -0.5

	score := model.Predict(features)
	expected := sigmoid(-0.5)
	if math.Abs(score-expected) > 0.01 {
		t.Fatalf("expected score %f, got %f", expected, score)
	}
}

func TestPredictHighScore(t *testing.T) {
	model := &Model{
		parsedTrees: []*TreeNode{
			{
				SplitFeature:   intPtr(0),
				SplitThreshold: thresholdPtr(0.5),
				DefaultLeft:    boolPtr(true),
				Left:           &TreeNode{LeafValue: float64Ptr(-0.5)},
				Right:          &TreeNode{LeafValue: float64Ptr(0.5)},
			},
		},
	}

	features := make([]float32, 2381)
	features[0] = 0.8 // > 0.5 → goes right → leaf 0.5

	score := model.Predict(features)
	expected := sigmoid(0.5)
	if math.Abs(score-expected) > 0.01 {
		t.Fatalf("expected score %f, got %f", expected, score)
	}
}

func TestPredictMultipleTrees(t *testing.T) {
	model := &Model{
		parsedTrees: []*TreeNode{
			{
				SplitFeature:   intPtr(0),
				SplitThreshold: thresholdPtr(0.5),
				DefaultLeft:    boolPtr(true),
				Left:           &TreeNode{LeafValue: float64Ptr(-0.3)},
				Right:          &TreeNode{LeafValue: float64Ptr(0.3)},
			},
			{
				SplitFeature:   intPtr(0),
				SplitThreshold: thresholdPtr(0.5),
				DefaultLeft:    boolPtr(true),
				Left:           &TreeNode{LeafValue: float64Ptr(-0.2)},
				Right:          &TreeNode{LeafValue: float64Ptr(0.2)},
			},
		},
	}

	features := make([]float32, 2381)
	features[0] = 0.8

	score := model.Predict(features)
	// avg = (0.3 + 0.2) / 2 = 0.25
	expected := sigmoid(0.25)
	if math.Abs(score-expected) > 0.01 {
		t.Fatalf("expected score %f, got %f", expected, score)
	}
}

func TestPredictDefaultLeft(t *testing.T) {
	model := &Model{
		parsedTrees: []*TreeNode{
			{
				SplitFeature:   intPtr(0),
				SplitThreshold: thresholdPtr(0.5),
				DefaultLeft:    boolPtr(false),
				Left:           &TreeNode{LeafValue: float64Ptr(-0.5)},
				Right:          &TreeNode{LeafValue: float64Ptr(0.5)},
			},
		},
	}

	// With default_left=false: goLeft = featureVal <= threshold
	// NaN goes right, but 0.2 is not NaN, so 0.2 <= 0.5 = true → goes left → leaf -0.5
	features := make([]float32, 2381)
	features[0] = 0.2

	score := model.Predict(features)
	expected := sigmoid(-0.5)
	if math.Abs(score-expected) > 0.01 {
		t.Fatalf("expected score %f for default_left=false, got %f", expected, score)
	}
}

func TestPredictNilModel(t *testing.T) {
	features := make([]float32, 2381)
	// Predict on nil model should not panic
	score := (&Model{}).Predict(features)
	if score != 0.0 {
		t.Fatalf("expected default 0.0 for empty model, got %f", score)
	}
}

func TestPredictFromBytes(t *testing.T) {
	model := &Model{
		parsedTrees: []*TreeNode{
			{
				Left:  &TreeNode{LeafValue: float64Ptr(0.0)},
				Right: &TreeNode{LeafValue: float64Ptr(0.5)},
			},
		},
	}

	data := []byte{0x01, 0x02, 0x03}
	peInfo := &parser.PEInfo{
		NumberOfSections: 1,
		SectionNames:     []string{".text"},
		Sections: []parser.SectionDetail{
			{Name: ".text", VirtualSize: 4096, RawDataSize: 2048, Entropy: 5.0},
		},
		ImportedDLLs: []string{"kernel32.dll"},
	}

	features, score, err := PredictFromBytes(data, peInfo, model)
	if err != nil {
		t.Fatalf("PredictFromBytes failed: %v", err)
	}
	if len(features) != FeatureCount {
		t.Fatalf("expected %d features, got %d", FeatureCount, len(features))
	}
	if score <= 0 || score >= 1 {
		t.Fatalf("expected score in (0,1), got %f", score)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	modelJSON := `{
		"name": "roundtrip",
		"task": "binary",
		"num_classes": 1,
		"num_features": 2381,
		"trees": [
			{
				"split_feature": 0,
				"split_threshold": 0.5,
				"default_left": true,
				"left": {"leaf_value": -0.3},
				"right": {"leaf_value": 0.3}
			}
		]
	}`

	var raw interface{}
	if err := json.Unmarshal([]byte(modelJSON), &raw); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	reJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	model, err := ParseModel(reJSON)
	if err != nil {
		t.Fatalf("ParseModel failed after round-trip: %v", err)
	}
	if len(model.parsedTrees) != 1 {
		t.Fatalf("expected 1 tree after round-trip, got %d", len(model.parsedTrees))
	}
}

// --- helpers ---

func intPtr(i int) *int { return &i }

func float64Ptr(f float64) *float64 { return &f }

func boolPtr(b bool) *bool { return &b }

func thresholdPtr(f float64) *Threshold { return &Threshold{FloatVal: &f} }
