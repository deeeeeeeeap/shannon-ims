package e911

import (
	"os"
	"testing"
)

func TestE911BranchHasNoTmpATTArtifacts(t *testing.T) {
	for _, path := range []string{
		"../../tmp/test_att.go",
		"../../tmp/vohive",
	} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("remove local artifact from branch: %s", path)
		}
	}
}
