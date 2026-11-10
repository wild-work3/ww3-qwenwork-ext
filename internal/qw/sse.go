package qw

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"wild-work3/qwenwork-ext/internal/protocol/errkind"
)

// envelope 是网关返回的嵌套 SSE 信封。
type envelope struct {
	Body            json.RawMessage `json:"body"`
	StatusCodeValue int             `json:"statusCodeValue"`
	StatusCode      string          `json:"statusCode"`
}

// SSEError 表示上游在信封里返回的错误（HTTP 200 也可能是错误）。
type SSEError struct {
	Status int
	Msg    string
}

func (e *SSEError) Error() string { return fmt.Sprintf("upstream %d: %s", e.Status, e.Msg) }

// Kind 把上游错误映射为协议错误种类。
func (e *SSEError) Kind() errkind.Kind { return Classify(e.Status, e.Msg) }

// errText 从信封 body 中提取错误文案。
func errText(status int, body []byte) string {
	if status < 400 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		var parts []string
		for _, k := range []string{"message", "msg", "error_description", "error", "code"} {
			if v, ok := m[k]; ok {
				if s := strings.TrimSpace(fmt.Sprint(v)); s != "" {
					parts = append(parts, s)
				}
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	return truncate(string(body), 200)
}

// innerChunk 解出内层 OpenAI chunk；空帧/结束帧返回 nil。
func innerChunk(env envelope) map[string]any {
	body := env.Body
	if len(body) == 0 {
		return nil
	}
	var inner string
	if json.Unmarshal(body, &inner) == nil {
		s := strings.TrimSpace(inner)
		if s == "" || s == "[DONE]" || s == "{}" {
			return nil
		}
		body = []byte(s)
	}
	var chunk map[string]any
	if json.Unmarshal(body, &chunk) != nil {
		return nil
	}
	if len(chunk) == 0 {
		return nil
	}
	return chunk
}

// ParseNestedSSE 逐行解析嵌套 SSE，把内层 chunk 交给 onChunk。
// truncated 在半帧/EOS 时置 true（截断优先于错误）。
func ParseNestedSSE(r io.Reader, onChunk func(map[string]any) error, truncated *bool) error {
	br := bufio.NewReaderSize(r, 256*1024)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				if truncated != nil {
					*truncated = true
				}
				return err
			}
			if strings.TrimSpace(line) != "" && truncated != nil {
				*truncated = true
			}
			return nil
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		var env envelope
		if json.Unmarshal([]byte(payload), &env) != nil {
			continue
		}
		status := env.StatusCodeValue
		if status != 0 && status >= 400 {
			return &SSEError{Status: status, Msg: errText(status, env.Body)}
		}
		chunk := innerChunk(env)
		if chunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return err
		}
	}
}

// MergeToolCallDelta 把增量 tool_call 合并进已累积的调用（id/type/name 覆盖，arguments 拼接）。
func MergeToolCallDelta(dst map[string]any, delta map[string]any) {
	if dst == nil || delta == nil {
		return
	}
	if v, ok := delta["id"]; ok && fmt.Sprint(v) != "" {
		dst["id"] = v
	}
	if v, ok := delta["type"]; ok && fmt.Sprint(v) != "" {
		dst["type"] = v
	}
	dfn, _ := delta["function"].(map[string]any)
	if dfn == nil {
		return
	}
	fn, _ := dst["function"].(map[string]any)
	if fn == nil {
		fn = map[string]any{}
		dst["function"] = fn
	}
	if v, ok := dfn["name"]; ok && fmt.Sprint(v) != "" {
		fn["name"] = v
	}
	if v, ok := dfn["arguments"]; ok {
		fn["arguments"] = fmt.Sprint(fn["arguments"]) + fmt.Sprint(v)
	}
}

func truncate(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
