package api

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIVoHiveYAMLValid(t *testing.T) {
	data, err := os.ReadFile("openapi.vohive.yaml")
	if err != nil {
		t.Fatalf("read openapi.vohive.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("openapi.vohive.yaml is invalid YAML: %v", err)
	}
	if doc["openapi"] == "" {
		t.Fatalf("openapi.vohive.yaml missing openapi version")
	}
}
