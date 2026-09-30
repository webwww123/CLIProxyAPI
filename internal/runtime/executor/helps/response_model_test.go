package helps

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestResponseModelPreservesRequestedIdentity(t *testing.T) {
	r := NewUsageReporter(usage.WithRequestedModelAlias(context.Background(), "public-alias"), "compat-provider", "requested-model", nil)
	r.ObserveResponseModel([]byte(`{"object":"chat.completion","model":"actual-model"}`))
	record := r.buildRecord(usage.Detail{TotalTokens: 1}, false)
	if record.Model != "requested-model" || record.Alias != "public-alias" || record.ResponseModel != "actual-model" {
		t.Fatalf("unexpected model identity: model=%q alias=%q response=%q", record.Model, record.Alias, record.ResponseModel)
	}
}

func TestResponseModelFinalEventAndUnknown(t *testing.T) {
	r := NewUsageReporter(context.Background(), "compat-provider", "requested-model", nil)
	r.ObserveResponseModel([]byte(`data: {"model":"preliminary"}`))
	r.ObserveResponseModel([]byte(`{"type":"response.completed","response":{"model":"actual-model"}}`))
	r.ObserveResponseModel([]byte(`{"model":"later-noise"}`))
	if r.ResponseModel() != "actual-model" || !r.IsResponseModelFinal() {
		t.Fatalf("final response model = %q, final=%v", r.ResponseModel(), r.IsResponseModelFinal())
	}
	unknown := NewUsageReporter(context.Background(), "compat-provider", "requested-model", nil)
	unknown.ObserveResponseModel([]byte(`{"object":"chat.completion","choices":[]}`))
	if got := unknown.buildRecord(usage.Detail{}, false).ResponseModel; got != "" {
		t.Fatalf("missing model must remain unknown, got %q", got)
	}
}

func TestResponseModelRejectsUntrustedMetadata(t *testing.T) {
	for _, candidate := range []string{strings.Repeat("x", maxResponseModelLength+1), "model\nspoof", "model\x00spoof"} {
		payload, _ := json.Marshal(map[string]string{"model": candidate})
		r := NewUsageReporter(context.Background(), "compat-provider", "requested-model", nil)
		r.ObserveResponseModel(payload)
		if got := r.ResponseModel(); got != "" {
			t.Fatalf("unsafe model was recorded: %q", got)
		}
	}
	for _, payload := range []string{`{"model":42}`, `{"model":"unfinished`, `data: [DONE]`} {
		r := NewUsageReporter(context.Background(), "compat-provider", "requested-model", nil)
		r.ObserveResponseModel([]byte(payload))
		if r.ResponseModel() != "" {
			t.Fatalf("invalid metadata was recorded")
		}
	}
}

func TestResponseModelConcurrentObservation(t *testing.T) {
	r := NewUsageReporter(context.Background(), "compat-provider", "requested-model", nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				r.ObserveResponseModel([]byte(`{"model":"actual-model"}`))
				_ = r.buildRecord(usage.Detail{}, false)
				_ = r.IsResponseModelFinal()
			}
		})
	}
	wg.Wait()
	if r.ResponseModel() != "actual-model" {
		t.Fatal("concurrent observations lost the model")
	}
}
