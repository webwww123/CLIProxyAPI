package claude

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestStreamingTool_RunningUsagePreservesLaterArguments(t *testing.T) {
	chunks := []string{
		`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Read","arguments":""}}]},"finish_reason":null}],"usage":{"prompt_tokens":100,"completion_tokens":4,"prompt_tokens_details":{"cached_tokens":40}}}`,
		`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"file_path\":"}}]},"finish_reason":null}],"usage":{"prompt_tokens":100,"completion_tokens":6}}`,
		`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"/project/src/main.py\"}"}}]},"finish_reason":null}],"usage":{"prompt_tokens":100,"completion_tokens":12}}`,
	}
	var state any
	for index, chunk := range chunks {
		out := ConvertOpenAIResponseToClaude(context.Background(), "", []byte(streamReq), nil, []byte("data: "+chunk), &state)
		for _, event := range out {
			if strings.Contains(string(event), "event: message_stop\n") || strings.Contains(string(event), "event: content_block_stop\n") {
				t.Fatalf("running usage ended the tool before finish at chunk %d: %s", index, event)
			}
		}
	}
	chunks = append(chunks, `{"id":"c1","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":100,"completion_tokens":13,"prompt_tokens_details":{"cached_tokens":40}}}`)
	events := runStream(t, streamReq, chunks...)
	assertRunningUsageToolResult(t, events, 60, 13, 40)
}

func TestStreamingTool_RunningUsageWithoutFinishPreservedOnDone(t *testing.T) {
	events := runStream(t, streamReq,
		`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Read","arguments":""}}]}}],"usage":{"prompt_tokens":100,"completion_tokens":4,"prompt_tokens_details":{"cached_tokens":40}}}`,
		`{"id":"c1","model":"m","choices":[],"usage":{"completion_tokens":5}}`,
		`{"id":"c1","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"file_path\":\"/project/src/main.py\"}"}}]}}],"usage":{"completion_tokens":13}}`,
	)
	assertRunningUsageToolResult(t, events, 60, 13, 40)
}

func assertRunningUsageToolResult(t *testing.T, events []sseEvent, input, output, cached int64) {
	t.Helper()
	arguments := ""
	for _, event := range events {
		if event.Type == "content_block_delta" && gjson.Get(event.Payload, "delta.type").String() == "input_json_delta" {
			arguments += gjson.Get(event.Payload, "delta.partial_json").String()
		}
		if event.Type == "message_delta" {
			if got := gjson.Get(event.Payload, "usage.input_tokens").Int(); got != input {
				t.Fatalf("input tokens = %d, want %d", got, input)
			}
			if got := gjson.Get(event.Payload, "usage.output_tokens").Int(); got != output {
				t.Fatalf("output tokens = %d, want %d", got, output)
			}
			if got := gjson.Get(event.Payload, "usage.cache_read_input_tokens").Int(); got != cached {
				t.Fatalf("cached tokens = %d, want %d", got, cached)
			}
		}
	}
	if !gjson.Valid(arguments) || gjson.Get(arguments, "file_path").String() != "/project/src/main.py" {
		t.Fatalf("complete arguments were not delivered: %q", arguments)
	}
	if countByType(events, "message_delta") != 1 || countByType(events, "message_stop") != 1 || lastStopReason(events) != "tool_use" {
		t.Fatalf("unexpected terminal events: %+v", events)
	}
}
