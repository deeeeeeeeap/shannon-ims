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

func TestOpenAPIProxyQuerySchemasExposeOnlyPasswordState(t *testing.T) {
	data, err := os.ReadFile("openapi.vohive.yaml")
	if err != nil {
		t.Fatalf("read openapi.vohive.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("openapi.vohive.yaml is invalid YAML: %v", err)
	}

	for _, schemaName := range []string{"ProxyInstanceDTO", "UpstreamProxyDTO"} {
		properties := openAPISchemaProperties(t, doc, schemaName)
		if _, exists := properties["password"]; exists {
			t.Fatalf("%s query schema exposes password", schemaName)
		}
		if _, exists := properties["password_set"]; !exists {
			t.Fatalf("%s query schema omits password_set", schemaName)
		}
	}
}

func TestOpenAPIProxyWriteSchemasRetainPasswordInput(t *testing.T) {
	data, err := os.ReadFile("openapi.vohive.yaml")
	if err != nil {
		t.Fatalf("read openapi.vohive.yaml: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("openapi.vohive.yaml is invalid YAML: %v", err)
	}

	for _, schemaName := range []string{"ProxyInstanceInput", "UpstreamProxy"} {
		properties := openAPISchemaProperties(t, doc, schemaName)
		if _, exists := properties["password"]; !exists {
			t.Fatalf("%s write schema omits password input", schemaName)
		}
	}
}

func openAPISchemaProperties(t *testing.T, doc map[string]any, schemaName string) map[string]any {
	t.Helper()
	components, ok := doc["components"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI components missing")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI schemas missing")
	}
	schema, ok := schemas[schemaName].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI schema %s missing", schemaName)
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("OpenAPI schema %s properties missing", schemaName)
	}
	return properties
}
