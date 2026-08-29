package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestManagerResultObserverReceivesLocalResultsAndCanBeRemoved(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "observer-auth",
		Provider: "openai-compatible-test",
		Status:   StatusActive,
		Attributes: map[string]string{
			"api_key": "observer-key",
			"source":  "config:test[observer]",
		},
	}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	results := make(chan Result, 3)
	removeObserver := manager.AddResultObserver(func(_ context.Context, result Result, snapshot *Auth) {
		if snapshot == nil || snapshot.ID != auth.ID {
			t.Errorf("observer snapshot = %#v, want auth %q", snapshot, auth.ID)
			return
		}
		results <- result
	})

	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "test-model",
		Error:    &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"},
	})
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "test-model",
		Success:  true,
	})

	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if i == 0 && got.Success {
				t.Fatalf("first observed result = success, want failure")
			}
			if i == 1 && !got.Success {
				t.Fatalf("second observed result = failure, want success")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for result observer")
		}
	}

	removeObserver()
	removeObserver()
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    "test-model",
		Success:  true,
	})
	select {
	case got := <-results:
		t.Fatalf("observer received result after removal: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestManagerResultObserverDoesNotReceiveEphemeralHomeResults(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	called := make(chan struct{}, 1)
	removeObserver := manager.AddResultObserver(func(context.Context, Result, *Auth) {
		called <- struct{}{}
	})
	defer removeObserver()

	manager.reportHomeResult(context.Background(), Result{
		AuthID: "home-auth",
		Error:  &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"},
	}, &Auth{ID: "home-auth"})

	select {
	case <-called:
		t.Fatal("observer received an ephemeral Home result")
	case <-time.After(50 * time.Millisecond):
	}
}
