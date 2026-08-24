package auth

import (
	"fmt"
	"sync"
	"testing"
)

var (
	executorRegistrationSnapshotSink []ExecutorRegistrationAuthSnapshot
	modelRegistrationSnapshotSink    []*Auth
	registrationListSnapshotSink     []*Auth
)

func TestRegistrationSnapshotsPreserveRequiredFields(t *testing.T) {
	runtimeMarker := &struct{ name string }{name: "runtime"}
	manager := NewManager(nil, nil, nil)
	manager.mu.Lock()
	manager.auths = map[string]*Auth{
		"auth-1": {
			ID:       "auth-1",
			Provider: "openai-compatibility",
			Label:    "nvidia",
			Prefix:   "team-a",
			Disabled: true,
			ProxyURL: "http://proxy.invalid",
			Attributes: map[string]string{
				"base_url":     "https://integrate.api.nvidia.com/v1",
				"compat_name":  "nvidia",
				"provider_key": "nvidia",
				"api_key":      "test-only-key",
				"extra":        "preserved-for-model-registration",
			},
			Metadata: map[string]any{
				"auth_kind": "apikey",
				"nested":    map[string]any{"value": "kept"},
			},
			ModelStates: map[string]*ModelState{
				"model-a": {Status: StatusError},
			},
			Runtime: runtimeMarker,
		},
	}
	manager.mu.Unlock()

	executorSnapshots := manager.ExecutorRegistrationSnapshot()
	if len(executorSnapshots) != 1 {
		t.Fatalf("executor snapshot length = %d, want 1", len(executorSnapshots))
	}
	executorSnapshot := executorSnapshots[0]
	if executorSnapshot.ID != "auth-1" || executorSnapshot.Provider != "openai-compatibility" || executorSnapshot.Label != "nvidia" || !executorSnapshot.Disabled {
		t.Fatalf("executor snapshot identity = %+v", executorSnapshot)
	}
	if executorSnapshot.BaseURL != "https://integrate.api.nvidia.com/v1" || executorSnapshot.CompatibilityName != "nvidia" || executorSnapshot.ProviderKey != "nvidia" {
		t.Fatalf("executor snapshot routing fields = %+v", executorSnapshot)
	}

	modelSnapshots := manager.ModelRegistrationSnapshot()
	if len(modelSnapshots) != 1 {
		t.Fatalf("model snapshot length = %d, want 1", len(modelSnapshots))
	}
	modelSnapshot := modelSnapshots[0]
	if modelSnapshot.ID != "auth-1" || modelSnapshot.Prefix != "team-a" || modelSnapshot.ProxyURL != "http://proxy.invalid" || modelSnapshot.Runtime != runtimeMarker {
		t.Fatalf("model snapshot fields = %+v", modelSnapshot)
	}
	if len(modelSnapshot.ModelStates) != 0 {
		t.Fatalf("model snapshot copied %d model states, want 0", len(modelSnapshot.ModelStates))
	}
	if modelSnapshot.Attributes["extra"] != "preserved-for-model-registration" || modelSnapshot.Metadata["auth_kind"] != "apikey" {
		t.Fatalf("model snapshot maps = attributes:%v metadata:%v", modelSnapshot.Attributes, modelSnapshot.Metadata)
	}

	modelSnapshot.Attributes["extra"] = "mutated"
	modelSnapshot.Metadata["auth_kind"] = "mutated"
	live, ok := manager.GetByID("auth-1")
	if !ok || live == nil {
		t.Fatal("live auth missing")
	}
	if live.Attributes["extra"] != "preserved-for-model-registration" || live.Metadata["auth_kind"] != "apikey" {
		t.Fatalf("snapshot mutation changed live auth: attributes:%v metadata:%v", live.Attributes, live.Metadata)
	}
}

func TestRegistrationSnapshotsConcurrent(t *testing.T) {
	const authCount = 1000
	manager := newRegistrationSnapshotTestManager(authCount, 2)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for reader := 0; reader < 6; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				if got := len(manager.ExecutorRegistrationSnapshot()); got != authCount {
					t.Errorf("executor snapshot length = %d, want %d", got, authCount)
					return
				}
				if got := len(manager.ModelRegistrationSnapshot()); got != authCount {
					t.Errorf("model snapshot length = %d, want %d", got, authCount)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for iteration := 0; iteration < 1000; iteration++ {
			id := fmt.Sprintf("auth-%05d", iteration%authCount)
			manager.mu.Lock()
			current := manager.auths[id].Clone()
			current.Label = fmt.Sprintf("provider-%04d", iteration)
			current.Metadata["iteration"] = iteration
			manager.auths[id] = current
			manager.mu.Unlock()
		}
	}()

	close(start)
	wg.Wait()
}

func TestRegistrationSnapshotsLargePoolAllocations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10,000-auth allocation comparison in short mode")
	}

	manager := newRegistrationSnapshotTestManager(10_000, 20)
	executorAllocs := testing.AllocsPerRun(3, func() {
		executorRegistrationSnapshotSink = manager.ExecutorRegistrationSnapshot()
	})
	modelAllocs := testing.AllocsPerRun(1, func() {
		modelRegistrationSnapshotSink = manager.ModelRegistrationSnapshot()
	})
	listAllocs := testing.AllocsPerRun(1, func() {
		registrationListSnapshotSink = manager.List()
	})
	t.Logf("10,000 auths: executor snapshot %.0f allocs/run, model snapshot %.0f, List %.0f", executorAllocs, modelAllocs, listAllocs)

	if len(executorRegistrationSnapshotSink) != 10_000 || len(modelRegistrationSnapshotSink) != 10_000 {
		t.Fatalf("snapshot lengths = executor:%d model:%d, want 10000 each", len(executorRegistrationSnapshotSink), len(modelRegistrationSnapshotSink))
	}
	if executorAllocs*100 >= listAllocs {
		t.Fatalf("executor snapshot allocations = %.0f, List allocations = %.0f; want at least 100x fewer", executorAllocs, listAllocs)
	}
	if modelAllocs*5 >= listAllocs {
		t.Fatalf("model snapshot allocations = %.0f, List allocations = %.0f; want at least 5x fewer", modelAllocs, listAllocs)
	}
}

func newRegistrationSnapshotTestManager(authCount, modelCount int) *Manager {
	manager := NewManager(nil, nil, nil)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.auths = make(map[string]*Auth, authCount)
	for i := 0; i < authCount; i++ {
		id := fmt.Sprintf("auth-%05d", i)
		modelStates := make(map[string]*ModelState, modelCount)
		for model := 0; model < modelCount; model++ {
			modelStates[fmt.Sprintf("model-%03d", model)] = &ModelState{Status: StatusActive}
		}
		manager.auths[id] = &Auth{
			ID:       id,
			Provider: "openai-compatibility",
			Label:    "nvidia",
			Attributes: map[string]string{
				"base_url":     "https://integrate.api.nvidia.com/v1",
				"compat_name":  "nvidia",
				"provider_key": "nvidia",
				"api_key":      fmt.Sprintf("test-key-%05d", i),
			},
			Metadata: map[string]any{
				"auth_kind": "apikey",
				"ordinal":   i,
			},
			ModelStates: modelStates,
		}
	}
	return manager
}
