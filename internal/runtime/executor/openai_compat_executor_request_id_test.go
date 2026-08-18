package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
)

func TestForwardInternalRequestIDOnlyToLocalMistralGateway(t *testing.T) {
	ctx := logging.WithRequestID(context.Background(), "request-safe_123")

	for _, target := range []string{
		"http://172.17.0.1:18318/v1/chat/completions",
		"http://127.0.0.1:18318/v1/chat/completions",
		"http://localhost:18318/v1/chat/completions",
	} {
		headers := make(http.Header)
		forwardInternalRequestID(ctx, target, headers)
		if got := headers.Get(logging.InternalRequestIDHeader); got != "request-safe_123" {
			t.Fatalf("target %q request ID = %q", target, got)
		}
	}

	for _, target := range []string{
		"https://172.17.0.1:18318/v1/chat/completions",
		"http://user@172.17.0.1:18318/v1/chat/completions",
		"http://172.17.0.1:18319/v1/chat/completions",
		"http://172.17.0.10:18318/v1/chat/completions",
		"https://provider.example/v1/chat/completions",
	} {
		headers := make(http.Header)
		forwardInternalRequestID(ctx, target, headers)
		if got := headers.Get(logging.InternalRequestIDHeader); got != "" {
			t.Fatalf("target %q unexpectedly received request ID %q", target, got)
		}
	}
}

func TestForwardInternalRequestIDRejectsUnsafeValue(t *testing.T) {
	ctx := logging.WithRequestID(context.Background(), "unsafe request id")
	headers := make(http.Header)
	forwardInternalRequestID(ctx, "http://172.17.0.1:18318/v1/chat/completions", headers)
	if got := headers.Get(logging.InternalRequestIDHeader); got != "" {
		t.Fatalf("unsafe request ID was forwarded: %q", got)
	}
}
