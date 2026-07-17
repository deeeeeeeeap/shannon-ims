package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGitHubWorkflowsAreValidYAML(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))

	for _, relative := range []string{
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "binary-release.yml"),
	} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(repositoryRoot, relative))
			if err != nil {
				t.Fatalf("read workflow: %v", err)
			}
			var document yaml.Node
			if err := yaml.Unmarshal(content, &document); err != nil {
				t.Fatalf("parse workflow YAML: %v", err)
			}
			if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
				t.Fatal("workflow root must be a YAML mapping")
			}
		})
	}
}
