package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestOpenAICompatResponseModelUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Stream bool `json:"stream"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"model\":\"actual-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n"))
			_, _ = w.Write([]byte("data: {\"model\":\"actual-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\ndata: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"chat.completion","model":"actual-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(server.Close)
	plugin := &captureAIStudioUsagePlugin{records: make(chan usage.Record, 32)}
	usage.RegisterNamedPlugin("compat-response-model-test", plugin)
	e := NewOpenAICompatExecutor("compat-response-model-test", &config.Config{})
	auth := &cliproxyauth.Auth{ID: "compat-response-model-auth", Attributes: map[string]string{"base_url": server.URL + "/v1", "api_key": "synthetic-test-key"}}
	for _, mode := range []string{"chat", "chat-stream", "image", "image-stream"} {
		t.Run(mode, func(t *testing.T) {
			model := "requested-" + mode
			ctx := usage.WithRequestedModelAlias(context.Background(), "public-alias")
			req := cliproxyexecutor.Request{Model: model, Payload: []byte(`{"messages":[{"role":"user","content":"hi"}],"prompt":"test"}`)}
			if mode == "chat-stream" {
				req.Payload = []byte(`{"messages":[{"role":"user","content":"hi"}],"stream":true}`)
			}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}
			var err error
			var stream *cliproxyexecutor.StreamResult
			switch mode {
			case "chat":
				_, err = e.Execute(ctx, auth, req, opts)
			case "image":
				_, err = e.executeImages(ctx, auth, req, opts, openAICompatImagesGenerationsPath)
			case "chat-stream":
				opts.Stream = true
				stream, err = e.ExecuteStream(ctx, auth, req, opts)
			case "image-stream":
				stream, err = e.executeImagesStream(ctx, auth, req, opts, openAICompatImagesGenerationsPath)
			}
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if stream != nil {
				for chunk := range stream.Chunks {
					if chunk.Err != nil {
						t.Fatalf("stream: %v", chunk.Err)
					}
				}
			}
			var record usage.Record
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
		waitUsage:
			for {
				select {
				case record = <-plugin.records:
					if record.Provider == e.Identifier() && record.Model == model {
						break waitUsage
					}
				case <-timer.C:
					t.Fatal("timed out waiting for compatibility usage record")
				}
			}
			if record.Model != model || record.Alias != "public-alias" || record.ResponseModel != "actual-model" || record.Failed {
				t.Fatalf("identity or outcome changed: model=%q alias=%q response=%q failed=%v", record.Model, record.Alias, record.ResponseModel, record.Failed)
			}
		})
	}
}
