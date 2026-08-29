package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

var (
	providerScopedCredentialAuthSink []*coreauth.Auth
	fullCredentialAuthSink           []*coreauth.Auth
)

func TestBuildOpenAICompatCredentialReloadPlan(t *testing.T) {
	base := credentialReloadTestConfig()
	tests := []struct {
		name        string
		mutate      func(*config.Config)
		wantNarrow  bool
		wantIndexes []int
	}{
		{
			name: "proxy only",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[1].APIKeyEntries[0].ProxyURL = "http://proxy-b-new"
			},
			wantNarrow:  true,
			wantIndexes: []int{1},
		},
		{
			name: "disabled only",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[0].APIKeyEntries[0].Disabled = true
			},
			wantNarrow:  true,
			wantIndexes: []int{0},
		},
		{
			name: "multiple providers",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[0].APIKeyEntries = append(cfg.OpenAICompatibility[0].APIKeyEntries, config.OpenAICompatibilityAPIKey{APIKey: "key-a-2"})
				cfg.OpenAICompatibility[1].APIKeyEntries[0].ProxyURL = "http://proxy-b-new"
			},
			wantNarrow:  true,
			wantIndexes: []int{0, 1},
		},
		{
			name: "base URL",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[0].BaseURL = "https://changed.example.com/v1"
			},
		},
		{
			name: "models",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[0].Models[0].Alias = "changed-model"
			},
		},
		{
			name: "provider policy",
			mutate: func(cfg *config.Config) {
				cfg.OpenAICompatibility[0].CredentialPolicy = &config.OpenAICompatibilityCredentialPolicy{ScopeStatuses: []int{401}}
			},
		},
		{
			name: "global retry",
			mutate: func(cfg *config.Config) {
				cfg.RequestRetry++
			},
		},
		{
			name:   "unchanged",
			mutate: func(*config.Config) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := base.CloneForRuntime()
			tt.mutate(changed)
			plan, ok := buildOpenAICompatCredentialReloadPlan(base, changed)
			if ok != tt.wantNarrow {
				t.Fatalf("credential-only classification = %v, want %v", ok, tt.wantNarrow)
			}
			if !tt.wantNarrow {
				return
			}
			if fmt.Sprint(plan.providerIndexes) != fmt.Sprint(tt.wantIndexes) {
				t.Fatalf("provider indexes = %v, want %v", plan.providerIndexes, tt.wantIndexes)
			}
		})
	}
}

func TestReloadConfigUsesProviderScopedCredentialPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	oldCfg := credentialReloadTestConfig()
	oldCfg.AuthDir = tmpDir
	writeWatcherConfig(t, configPath, oldCfg)
	loadedOld, errLoadOld := config.LoadConfig(configPath)
	if errLoadOld != nil {
		t.Fatalf("load old config: %v", errLoadOld)
	}

	initialAuths, errSynthesize := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config:      loadedOld,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil {
		t.Fatalf("synthesize old auths: %v", errSynthesize)
	}
	currentAuths := make(map[string]*coreauth.Auth, len(initialAuths))
	for _, auth := range initialAuths {
		currentAuths[auth.ID] = auth.Clone()
	}
	initialAuthCount := len(currentAuths)

	fullCalls := 0
	narrowCalls := 0
	queue := make(chan AuthUpdate, 8)
	w := &Watcher{
		configPath:     configPath,
		authDir:        tmpDir,
		currentAuths:   currentAuths,
		lastAuthHashes: make(map[string]string),
		reloadCallback: func(*config.Config) { fullCalls++ },
	}
	w.SetCredentialReloadCallback(func(*config.Config) bool {
		narrowCalls++
		return true
	})
	w.SetAuthUpdateQueue(queue)
	t.Cleanup(w.stopDispatch)
	w.SetConfig(loadedOld)

	newCfg := loadedOld.CloneForRuntime()
	newCfg.OpenAICompatibility[0].APIKeyEntries[0].ProxyURL = "http://proxy-a-new"
	writeWatcherConfig(t, configPath, newCfg)
	if ok := w.reloadConfig(); !ok {
		t.Fatal("reloadConfig failed")
	}
	if narrowCalls != 1 || fullCalls != 0 {
		t.Fatalf("callback calls = narrow:%d full:%d, want 1/0", narrowCalls, fullCalls)
	}

	updates := receiveAuthUpdates(t, queue, 2)
	counts := map[AuthUpdateAction]int{}
	for _, update := range updates {
		counts[update.Action]++
	}
	if counts[AuthUpdateActionAdd] != 1 || counts[AuthUpdateActionDelete] != 1 || counts[AuthUpdateActionModify] != 0 {
		t.Fatalf("updates = %+v, want one add and one delete", updates)
	}

	w.clientsMutex.RLock()
	defer w.clientsMutex.RUnlock()
	if len(w.currentAuths) != initialAuthCount {
		t.Fatalf("current auth count = %d, want %d", len(w.currentAuths), initialAuthCount)
	}
	providerBCount := 0
	for _, auth := range w.currentAuths {
		if auth != nil && auth.Attributes["compat_name"] == "provider-b" {
			providerBCount++
		}
	}
	if providerBCount != 1 {
		t.Fatalf("provider-b auth count = %d, want 1", providerBCount)
	}
}

func TestReloadConfigFallsBackForStructuralChange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	oldCfg := credentialReloadTestConfig()
	oldCfg.AuthDir = tmpDir
	writeWatcherConfig(t, configPath, oldCfg)
	loadedOld, errLoadOld := config.LoadConfig(configPath)
	if errLoadOld != nil {
		t.Fatalf("load old config: %v", errLoadOld)
	}

	fullCalls := 0
	narrowCalls := 0
	w := &Watcher{
		configPath:     configPath,
		authDir:        tmpDir,
		currentAuths:   make(map[string]*coreauth.Auth),
		lastAuthHashes: make(map[string]string),
		reloadCallback: func(*config.Config) { fullCalls++ },
	}
	w.SetCredentialReloadCallback(func(*config.Config) bool {
		narrowCalls++
		return true
	})
	w.SetAuthUpdateQueue(make(chan AuthUpdate, 8))
	t.Cleanup(w.stopDispatch)
	w.SetConfig(loadedOld)

	newCfg := loadedOld.CloneForRuntime()
	newCfg.OpenAICompatibility[0].BaseURL = "https://changed.example.com/v1"
	writeWatcherConfig(t, configPath, newCfg)
	if ok := w.reloadConfig(); !ok {
		t.Fatal("reloadConfig failed")
	}
	if narrowCalls != 0 || fullCalls != 1 {
		t.Fatalf("callback calls = narrow:%d full:%d, want 0/1", narrowCalls, fullCalls)
	}
}

func TestReloadConfigFallsBackWhenCredentialCallbackRejects(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	oldCfg := credentialReloadTestConfig()
	oldCfg.AuthDir = tmpDir
	writeWatcherConfig(t, configPath, oldCfg)
	loadedOld, errLoadOld := config.LoadConfig(configPath)
	if errLoadOld != nil {
		t.Fatalf("load old config: %v", errLoadOld)
	}

	fullCalls := 0
	narrowCalls := 0
	w := &Watcher{
		configPath:     configPath,
		authDir:        tmpDir,
		currentAuths:   make(map[string]*coreauth.Auth),
		lastAuthHashes: make(map[string]string),
		reloadCallback: func(*config.Config) { fullCalls++ },
	}
	w.SetCredentialReloadCallback(func(*config.Config) bool {
		narrowCalls++
		return false
	})
	w.SetAuthUpdateQueue(make(chan AuthUpdate, 8))
	t.Cleanup(w.stopDispatch)
	w.SetConfig(loadedOld)

	newCfg := loadedOld.CloneForRuntime()
	newCfg.OpenAICompatibility[0].APIKeyEntries[0].ProxyURL = "http://proxy-a-new"
	writeWatcherConfig(t, configPath, newCfg)
	if ok := w.reloadConfig(); !ok {
		t.Fatal("reloadConfig failed")
	}
	if narrowCalls != 1 || fullCalls != 1 {
		t.Fatalf("callback calls = narrow:%d full:%d, want 1/1", narrowCalls, fullCalls)
	}
}

func TestPrepareOpenAICompatCredentialUpdatesDisablesKeyInPlace(t *testing.T) {
	oldCfg := credentialReloadTestConfig()
	oldAuths := synthesizeOpenAICompatCredentials(t, oldCfg, []int{0, 1})
	currentAuths := make(map[string]*coreauth.Auth, len(oldAuths))
	var targetID string
	var unrelatedID string
	for _, auth := range oldAuths {
		currentAuths[auth.ID] = auth.Clone()
		switch auth.Attributes["compat_name"] {
		case "provider-a":
			targetID = auth.ID
		case "provider-b":
			unrelatedID = auth.ID
		}
	}
	if targetID == "" || unrelatedID == "" {
		t.Fatalf("missing synthesized auth IDs: target=%q unrelated=%q", targetID, unrelatedID)
	}
	unrelatedBefore := currentAuths[unrelatedID]

	newCfg := oldCfg.CloneForRuntime()
	newCfg.OpenAICompatibility[0].APIKeyEntries[0].Disabled = true
	newAuths := synthesizeOpenAICompatCredentials(t, newCfg, []int{0})
	w := &Watcher{currentAuths: currentAuths}
	updates, stats, ok := w.prepareOpenAICompatCredentialUpdates(newAuths, []int{0})
	if !ok {
		t.Fatal("provider-scoped credential update preparation failed")
	}
	if len(updates) != 1 || updates[0].Action != AuthUpdateActionModify || updates[0].ID != targetID {
		t.Fatalf("updates = %+v, want one in-place modify for %q", updates, targetID)
	}
	if stats.added != 0 || stats.modified != 1 || stats.deleted != 0 {
		t.Fatalf("stats = %+v, want 0 add / 1 modify / 0 delete", stats)
	}
	updated := w.currentAuths[targetID]
	if updated == nil || !updated.Disabled || updated.Status != coreauth.StatusDisabled {
		t.Fatalf("updated auth = %+v, want disabled status", updated)
	}
	if w.currentAuths[unrelatedID] != unrelatedBefore {
		t.Fatal("unrelated provider auth was replaced")
	}
}

func TestPrepareOpenAICompatCredentialUpdatesLargePoolIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10,000-credential provider isolation test in short mode")
	}
	oldCfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{
		credentialReloadProvider("target", 150),
		credentialReloadProvider("unrelated", 9_850),
	}}
	oldAuths := synthesizeOpenAICompatCredentials(t, oldCfg, []int{0, 1})
	currentAuths := make(map[string]*coreauth.Auth, len(oldAuths))
	oldTargetIDs := make(map[string]struct{}, 150)
	var unrelatedID string
	for _, auth := range oldAuths {
		currentAuths[auth.ID] = auth.Clone()
		switch auth.Attributes["compat_name"] {
		case "target":
			oldTargetIDs[auth.ID] = struct{}{}
		case "unrelated":
			if unrelatedID == "" {
				unrelatedID = auth.ID
			}
		}
	}
	if len(currentAuths) != 10_000 || len(oldTargetIDs) != 150 || unrelatedID == "" {
		t.Fatalf("unexpected initial state: total=%d target=%d unrelated_sample=%q", len(currentAuths), len(oldTargetIDs), unrelatedID)
	}
	unrelatedBefore := currentAuths[unrelatedID]

	newCfg := oldCfg.CloneForRuntime()
	for index := range newCfg.OpenAICompatibility[0].APIKeyEntries {
		newCfg.OpenAICompatibility[0].APIKeyEntries[index].ProxyURL = fmt.Sprintf("http://proxy-%03d-new", index)
	}
	newAuths := synthesizeOpenAICompatCredentials(t, newCfg, []int{0})
	w := &Watcher{currentAuths: currentAuths}
	updates, stats, ok := w.prepareOpenAICompatCredentialUpdates(newAuths, []int{0})
	if !ok {
		t.Fatal("provider-scoped large-pool update preparation failed")
	}
	if len(updates) != 300 || stats.added != 150 || stats.modified != 0 || stats.deleted != 150 {
		t.Fatalf("updates=%d stats=%+v, want 150 add / 0 modify / 150 delete", len(updates), stats)
	}
	if len(w.currentAuths) != 10_000 {
		t.Fatalf("current auth count = %d, want 10000", len(w.currentAuths))
	}
	if w.currentAuths[unrelatedID] != unrelatedBefore {
		t.Fatal("unrelated provider auth was replaced during target-provider update")
	}
	for id := range oldTargetIDs {
		if _, exists := w.currentAuths[id]; exists {
			t.Fatalf("old target auth %q remained after proxy reassignment", id)
		}
	}
}

func TestProviderScopedCredentialSynthesisAllocations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10,000-credential allocation comparison in short mode")
	}
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{
		credentialReloadProvider("target", 150),
		credentialReloadProvider("unrelated", 9_850),
	}}
	synth := synthesizer.NewConfigSynthesizer()
	targetedAllocs := testing.AllocsPerRun(3, func() {
		providerScopedCredentialAuthSink, _ = synth.SynthesizeOpenAICompatIndexes(&synthesizer.SynthesisContext{
			Config:      cfg,
			Now:         time.Now(),
			IDGenerator: synthesizer.NewStableIDGenerator(),
		}, []int{0})
	})
	fullAllocs := testing.AllocsPerRun(1, func() {
		fullCredentialAuthSink, _ = synth.Synthesize(&synthesizer.SynthesisContext{
			Config:      cfg,
			Now:         time.Now(),
			IDGenerator: synthesizer.NewStableIDGenerator(),
		})
	})
	t.Logf("10,000 credentials: provider-scoped %.0f allocs/run, full %.0f", targetedAllocs, fullAllocs)
	if len(providerScopedCredentialAuthSink) != 150 || len(fullCredentialAuthSink) != 10_000 {
		t.Fatalf("auth counts = targeted:%d full:%d, want 150/10000", len(providerScopedCredentialAuthSink), len(fullCredentialAuthSink))
	}
	if targetedAllocs*10 >= fullAllocs {
		t.Fatalf("provider-scoped allocations = %.0f, full = %.0f; want at least 10x fewer", targetedAllocs, fullAllocs)
	}
}

func credentialReloadTestConfig() *config.Config {
	return &config.Config{
		RequestRetry:       2,
		CredentialInFlight: config.DefaultCredentialInFlightConfig(),
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:          "provider-a",
				BaseURL:       "https://a.example.com/v1",
				Models:        []config.OpenAICompatibilityModel{{Name: "model-a", Alias: "model-a"}},
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-a", ProxyURL: "http://proxy-a"}},
			},
			{
				Name:          "provider-b",
				BaseURL:       "https://b.example.com/v1",
				Models:        []config.OpenAICompatibilityModel{{Name: "model-b", Alias: "model-b"}},
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "key-b", ProxyURL: "http://proxy-b"}},
			},
		},
	}
}

func credentialReloadProvider(name string, count int) config.OpenAICompatibility {
	provider := config.OpenAICompatibility{
		Name:          name,
		BaseURL:       "https://example.com/v1",
		Models:        []config.OpenAICompatibilityModel{{Name: "model", Alias: "model"}},
		APIKeyEntries: make([]config.OpenAICompatibilityAPIKey, count),
	}
	for index := range provider.APIKeyEntries {
		provider.APIKeyEntries[index].APIKey = fmt.Sprintf("%s-key-%05d", name, index)
	}
	return provider
}

func synthesizeOpenAICompatCredentials(t *testing.T, cfg *config.Config, indexes []int) []*coreauth.Auth {
	t.Helper()
	auths, errSynthesize := synthesizer.NewConfigSynthesizer().SynthesizeOpenAICompatIndexes(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	}, indexes)
	if errSynthesize != nil {
		t.Fatalf("synthesize OpenAI-compatible credentials: %v", errSynthesize)
	}
	return auths
}

func writeWatcherConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, errMarshal := yaml.Marshal(cfg)
	if errMarshal != nil {
		t.Fatalf("marshal config: %v", errMarshal)
	}
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
}

func receiveAuthUpdates(t *testing.T, queue <-chan AuthUpdate, count int) []AuthUpdate {
	t.Helper()
	updates := make([]AuthUpdate, 0, count)
	for len(updates) < count {
		select {
		case update := <-queue:
			updates = append(updates, update)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for auth update %d/%d", len(updates)+1, count)
		}
	}
	return updates
}
