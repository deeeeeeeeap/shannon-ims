package device

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPoolDoesNotOwnVoWiFiStateStorage(t *testing.T) {
	poolType := reflect.TypeOf(Pool{})
	forbiddenFields := []string{
		"vowifiRuntime",
		"vowifiStateSubs",
		"vowifiNextSubID",
		"vowifiMu",
		"vowifiRecoverMu",
		"vowifiRecoveries",
		"vowifiLifecycle",
	}

	for _, field := range forbiddenFields {
		if _, ok := poolType.FieldByName(field); ok {
			t.Fatalf("Pool still owns VoWiFi state field %q; move it behind vowifihost.Manager", field)
		}
	}

	if _, ok := poolType.FieldByName("vowifiHost"); !ok {
		t.Fatal("Pool should keep a single vowifihost.Manager field")
	}
}

func TestPoolDoesNotOwnVoWiFiLifecycleController(t *testing.T) {
	poolType := reflect.TypeOf(Pool{})
	if _, ok := poolType.FieldByName("vowifiLifecycle"); ok {
		t.Fatal("Pool should not own VoWiFi lifecycle controller; keep it behind vowifihost.Manager")
	}
}

func TestPoolTeardownDelegatesRuntimeMutationToHost(t *testing.T) {
	srcBytes, err := os.ReadFile("vowifi_teardown.go")
	if err != nil {
		t.Fatalf("read vowifi_teardown.go: %v", err)
	}
	src := string(srcBytes)

	requiredSnippets := []string{
		".StopInstanceForTeardown(",
		".TeardownForReconnect(",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(src, snippet) {
			t.Fatalf("vowifi_teardown.go should delegate runtime teardown via host manager; missing %q", snippet)
		}
	}

	forbiddenSnippets := []string{
		".DeleteInstance(",
		".Invalidate(",
		".Stop(stopCtx)",
		".Stop(ctx)",
	}
	for _, snippet := range forbiddenSnippets {
		if strings.Contains(src, snippet) {
			t.Fatalf("vowifi_teardown.go still mutates runtime teardown directly via %q", snippet)
		}
	}
}

func TestPoolDoesNotOwnVoWiFiStartRuntimeOrchestration(t *testing.T) {
	srcBytes, err := os.ReadFile("pool_vowifi_runtime.go")
	if err != nil {
		t.Fatalf("read pool_vowifi_runtime.go: %v", err)
	}
	src := string(srcBytes)

	if !strings.Contains(src, ".Enable(") {
		t.Fatalf("pool_vowifi_runtime.go should submit enable through vowifihost.Manager")
	}

	forbiddenSnippets := []string{
		".BeginStart(",
		".FailStart(",
		".PrepareStart(",
		".StartRuntime(",
		"vowifihost.RuntimeStartRequest",
		"voWiFiRuntimeStore().BeginStart(",
		"voWiFiRuntimeStore().FailStart(",
		"voWiFiRuntimeStore().ClaimStarted(",
		"voWiFiRuntimeStore().CurrentEpoch(",
		"voWiFiRuntimeStore().Instance(deviceID) == inst",
		"prepareVoWiFiStartContext(",
		"beforeVoWiFiStart(",
	}
	for _, snippet := range forbiddenSnippets {
		if strings.Contains(src, snippet) {
			t.Fatalf("pool_vowifi_runtime.go still mutates startup runtime directly via %q", snippet)
		}
	}
}

func TestProductionPoolDoesNotOwnVoWiFiLifecycleExecutor(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob production files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		srcBytes, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(srcBytes)
		forbiddenSnippets := []string{
			"runVoWiFiLifecycleCommand",
			"enableVoWiFiWithRuntimeEPDGOverrideAndGeneration",
			"enableVoWiFiWhenReadyDirect",
			"disableVoWiFiDirect",
			"restartVoWiFiDirect",
			"recoverVoWiFiDirect",
		}
		for _, snippet := range forbiddenSnippets {
			if strings.Contains(src, snippet) {
				t.Fatalf("%s still owns VoWiFi lifecycle executor detail %q; move lifecycle orchestration into vowifihost.Manager", file, snippet)
			}
		}
	}
}

func TestProductionPoolDoesNotExposeVoWiFiRuntimeStoreAccessor(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob production files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		srcBytes, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(srcBytes), "func (p *Pool) voWiFiRuntimeStore()") {
			t.Fatalf("%s exposes voWiFiRuntimeStore in production; keep runtime store behind vowifihost.Manager", file)
		}
	}
}
