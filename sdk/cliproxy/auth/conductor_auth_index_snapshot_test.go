package auth

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	authIndexSnapshotSink map[string]string
	authListSnapshotSink  []*Auth
)

func authIndexByIDFromList(auths []*Auth) map[string]string {
	out := make(map[string]string, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		id := strings.TrimSpace(auth.ID)
		if id == "" {
			continue
		}
		index := strings.TrimSpace(auth.Index)
		if index == "" {
			index = auth.EnsureIndex()
		}
		if index == "" {
			continue
		}
		out[id] = index
	}
	return out
}

func TestAuthIndexByIDSnapshotMatchesListBehavior(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.mu.Lock()
	manager.auths = map[string]*Auth{
		"explicit": {
			ID:    " explicit-id ",
			Index: " explicit-index ",
		},
		"derived": {
			ID:       "derived-id",
			Provider: "openai-compatibility",
			Attributes: map[string]string{
				"compat_name": "example",
				"base_url":    "https://example.invalid/v1",
				"api_key":     "test-key",
			},
		},
		"missing-id": {
			Index: "ignored-index",
		},
		"nil": nil,
	}
	manager.mu.Unlock()

	want := authIndexByIDFromList(manager.List())
	got := manager.AuthIndexByIDSnapshot()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AuthIndexByIDSnapshot() = %#v, want %#v", got, want)
	}

	got["explicit-id"] = "mutated"
	if next := manager.AuthIndexByIDSnapshot()["explicit-id"]; next != "explicit-index" {
		t.Fatalf("snapshot mutation changed manager state: got %q", next)
	}

	var nilManager *Manager
	if snapshot := nilManager.AuthIndexByIDSnapshot(); len(snapshot) != 0 {
		t.Fatalf("nil manager snapshot length = %d, want 0", len(snapshot))
	}
}

func TestAuthIndexByIDSnapshotConcurrent(t *testing.T) {
	const authCount = 1000
	manager := newAuthIndexSnapshotTestManager(authCount)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < 200; iteration++ {
				snapshot := manager.AuthIndexByIDSnapshot()
				if len(snapshot) != authCount {
					t.Errorf("snapshot length = %d, want %d", len(snapshot), authCount)
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
			current.Index = fmt.Sprintf("index-%05d-%04d", iteration%authCount, iteration)
			manager.auths[id] = current
			manager.mu.Unlock()
		}
	}()

	close(start)
	wg.Wait()
}

func TestAuthIndexByIDSnapshotLargePoolAllocations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10,000-auth allocation comparison in short mode")
	}

	manager := newAuthIndexSnapshotTestManager(10_000)
	snapshotAllocs := testing.AllocsPerRun(3, func() {
		authIndexSnapshotSink = manager.AuthIndexByIDSnapshot()
	})
	listAllocs := testing.AllocsPerRun(1, func() {
		authListSnapshotSink = manager.List()
	})
	t.Logf("10,000 auths: AuthIndexByIDSnapshot %.0f allocs/run, List %.0f allocs/run", snapshotAllocs, listAllocs)

	if len(authIndexSnapshotSink) != 10_000 {
		t.Fatalf("snapshot length = %d, want 10000", len(authIndexSnapshotSink))
	}
	if snapshotAllocs*100 >= listAllocs {
		t.Fatalf("snapshot allocations = %.0f, List allocations = %.0f; want at least 100x fewer", snapshotAllocs, listAllocs)
	}
}

func newAuthIndexSnapshotTestManager(count int) *Manager {
	manager := NewManager(nil, nil, nil)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.auths = make(map[string]*Auth, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("auth-%05d", i)
		manager.auths[id] = &Auth{
			ID:    id,
			Index: fmt.Sprintf("index-%05d", i),
			ModelStates: map[string]*ModelState{
				"model-a": {Status: StatusActive},
				"model-b": {Status: StatusError},
			},
		}
	}
	return manager
}
