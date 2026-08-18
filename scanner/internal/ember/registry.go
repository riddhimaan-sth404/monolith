package ember

import (
	"fmt"
	"log/slog"
	"path/filepath"
)

// ModelType identifies the scan model and its file-type target.
type ModelType string

const (
	ModelPE     ModelType = "pe"
	ModelPDF    ModelType = "pdf"
	ModelDotNet ModelType = "dotnet"
	ModelExploit ModelType = "exploit"
	ModelPacker ModelType = "packer"
)

// modelDef maps a ModelType to its filename pattern.
var modelDefs = map[ModelType]string{
	ModelPE:      "EMBER2024_PE_converted.json",
	ModelPDF:     "EMBER2024_PDF_converted.json",
	ModelDotNet:  "EMBER2024_Dot_Net_converted.json",
	ModelExploit: "EMBER2024_exploit_converted.json",
	ModelPacker:  "EMBER2024_packer_converted.json",
}

// ModelRegistry holds all loaded models, keyed by type.
type ModelRegistry struct {
	models map[ModelType]*Model
}

// NewModelRegistry loads all model files from a directory.
func NewModelRegistry(modelsDir string) (*ModelRegistry, error) {
	reg := &ModelRegistry{models: make(map[ModelType]*Model, len(modelDefs))}

	for mt, filename := range modelDefs {
		path := filepath.Join(modelsDir, filename)
		m, err := LoadModel(path)
		if err != nil {
			slog.Warn("failed to load model, skipping", "model", mt, "path", path, "error", err)
			continue
		}
		reg.models[mt] = m
		slog.Info("loaded model", "model", mt, "trees", len(m.Trees), "features", m.NumFeatures)
	}

	if len(reg.models) == 0 {
		return nil, fmt.Errorf("no models loaded from %s", modelsDir)
	}
	return reg, nil
}

// Get returns a single model by type, or nil.
func (r *ModelRegistry) Get(mt ModelType) *Model {
	return r.models[mt]
}

// ModelsForPE returns the models that should run on a PE file.
func (r *ModelRegistry) ModelsForPE() []*Model {
	var out []*Model
	for _, mt := range []ModelType{ModelPE, ModelExploit, ModelPacker} {
		if m := r.models[mt]; m != nil {
			out = append(out, m)
		}
	}
	return out
}

// ModelsForPDF returns the models for a PDF file.
func (r *ModelRegistry) ModelsForPDF() []*Model {
	if m := r.models[ModelPDF]; m != nil {
		return []*Model{m}
	}
	return nil
}

// ModelsForDotNet returns the models for a .NET file.
func (r *ModelRegistry) ModelsForDotNet() []*Model {
	var out []*Model
	for _, mt := range []ModelType{ModelDotNet, ModelPacker} {
		if m := r.models[mt]; m != nil {
			out = append(out, m)
		}
	}
	return out
}
