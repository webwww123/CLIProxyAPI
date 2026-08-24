package cliproxy

import (
	"fmt"
	"testing"

	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestRegisterExecutorsForAuthSnapshotsDeduplicatesEquivalentCredentials(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	service := &Service{cfg: &config.Config{}, coreManager: manager}
	snapshots := make([]coreauth.ExecutorRegistrationAuthSnapshot, 10_000)
	for i := range snapshots {
		snapshots[i] = coreauth.ExecutorRegistrationAuthSnapshot{
			ID:                fmt.Sprintf("nvidia-%05d", i),
			Provider:          "openai-compatibility",
			Label:             "nvidia",
			BaseURL:           "https://integrate.api.nvidia.com/v1",
			CompatibilityName: "nvidia",
			ProviderKey:       "nvidia",
		}
	}

	stats := service.registerExecutorsForAuthSnapshots(snapshots, true)
	if stats.authCount != 10_000 || stats.providerCount != 1 || stats.registrationCount != 1 || stats.duplicateCount != 9_999 || stats.disabledCount != 0 {
		t.Fatalf("registration stats = %+v", stats)
	}
	registered, ok := manager.Executor("openai-compatible-nvidia")
	if !ok || registered == nil {
		t.Fatal("nvidia executor was not registered")
	}
	if _, okCompat := registered.(*runtimeexecutor.OpenAICompatExecutor); !okCompat {
		t.Fatalf("nvidia executor type = %T, want *executor.OpenAICompatExecutor", registered)
	}
}

func TestRegisterExecutorsForAuthSnapshotsSkipsDisabledBeforeDeduplication(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	service := &Service{cfg: &config.Config{}, coreManager: manager}
	snapshots := []coreauth.ExecutorRegistrationAuthSnapshot{
		{ID: "disabled", Provider: "claude", Disabled: true},
		{ID: "active-a", Provider: "claude"},
		{ID: "active-b", Provider: "CLAUDE"},
	}

	stats := service.registerExecutorsForAuthSnapshots(snapshots, true)
	if stats.authCount != 3 || stats.providerCount != 1 || stats.registrationCount != 1 || stats.duplicateCount != 1 || stats.disabledCount != 1 {
		t.Fatalf("registration stats = %+v", stats)
	}
	if registered, ok := manager.Executor("claude"); !ok || registered == nil {
		t.Fatal("active claude executor was not registered")
	}
}

func TestExecutorRegistrationSnapshotKeyPreservesDistinctBindingInputs(t *testing.T) {
	equivalentA := coreauth.ExecutorRegistrationAuthSnapshot{
		ID:                "key-a",
		Provider:          "OpenAI-Compatibility",
		Label:             "nvidia",
		BaseURL:           "https://integrate.api.nvidia.com/v1",
		CompatibilityName: "nvidia",
		ProviderKey:       "nvidia",
	}
	equivalentB := equivalentA
	equivalentB.ID = "key-b"
	if gotA, gotB := executorRegistrationKeyForSnapshot(equivalentA), executorRegistrationKeyForSnapshot(equivalentB); gotA != gotB {
		t.Fatalf("equivalent snapshots produced different keys: %+v != %+v", gotA, gotB)
	}

	differentBaseURL := equivalentA
	differentBaseURL.BaseURL = "https://other.invalid/v1"
	if executorRegistrationKeyForSnapshot(equivalentA) == executorRegistrationKeyForSnapshot(differentBaseURL) {
		t.Fatal("different base URLs were deduplicated")
	}

	aistudioA := coreauth.ExecutorRegistrationAuthSnapshot{ID: "aistudio-a", Provider: "aistudio"}
	aistudioB := coreauth.ExecutorRegistrationAuthSnapshot{ID: "aistudio-b", Provider: "aistudio"}
	if executorRegistrationKeyForSnapshot(aistudioA) == executorRegistrationKeyForSnapshot(aistudioB) {
		t.Fatal("distinct AI Studio auth IDs were deduplicated")
	}
}

func TestExecutorRegistrationAuthFromSnapshotCopiesOnlyBindingAttributes(t *testing.T) {
	snapshot := coreauth.ExecutorRegistrationAuthSnapshot{
		ID:                "auth-1",
		Provider:          "openai-compatibility",
		Label:             "nvidia",
		Disabled:          true,
		BaseURL:           "https://integrate.api.nvidia.com/v1",
		CompatibilityName: "nvidia",
		ProviderKey:       "nvidia",
	}
	auth := executorRegistrationAuthFromSnapshot(snapshot)
	if auth.ID != snapshot.ID || auth.Provider != snapshot.Provider || auth.Label != snapshot.Label || auth.Disabled != snapshot.Disabled {
		t.Fatalf("auth identity = %+v", auth)
	}
	if len(auth.Attributes) != 3 || auth.Attributes["base_url"] != snapshot.BaseURL || auth.Attributes["compat_name"] != snapshot.CompatibilityName || auth.Attributes["provider_key"] != snapshot.ProviderKey {
		t.Fatalf("auth attributes = %v", auth.Attributes)
	}
}
