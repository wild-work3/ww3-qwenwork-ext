package qw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"wild-work3/qwenwork-ext/internal/protocol/chat"
	"wild-work3/qwenwork-ext/internal/protocol/errkind"
)

// Emitter 是流式事件的发射回调（对应 plugin.Emit）。
type Emitter func(event string, payload map[string]any) error

// Stream 走真实上游流式对话，把增量翻译成协议事件并 emit。
// 返回最终用量；错误一律用 *AuthError 携带 errkind。
//
// 注意：本实现不伪造 "[DONE]"（契约要求完成事件由 usage/completed 表达），
// 也不在截断后合成假成功。
func (c *Client) Stream(ctx context.Context, a *Auth, req *chat.GenerateRequest, emit Emitter) (*chat.Usage, error) {
	if a == nil {
		return nil, &AuthError{Kind: errkind.SessionDead, Msg: "缺少凭据"}
	}
	body, err := buildChatBody(req)
	if err != nil {
		return nil, &AuthError{Kind: errkind.BadParams, Msg: err.Error()}
	}
	// 本地模型校验：上游对未知模型会静默回落默认模型并返回 200，
	// 若不本地拒绝，用户输错模型名会拿到一个“看似成功”的错误模型回答。
	// 静态表命中即放行；否则先拉一次动态目录（真实上游会新增模型，
	// 而每次调用都是新进程、内存缓存不可用），仍未知才拒绝。
	if !c.KnownModel(req.Model) && !c.knownInCatalog(req.Model, a) {
		return nil, &AuthError{Kind: errkind.NotFound, Msg: "未知模型: " + req.Model}
	}
	prepared, err := c.prepareChatBody(body)
	if err != nil {
		return nil, &AuthError{Kind: errkind.BadParams, Msg: err.Error()}
	}
	rc, status, respBody, err := c.ChatStream(a, prepared)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &AuthError{Kind: errkind.Cancel, Msg: "已取消"}
		}
		return nil, &AuthError{Kind: errkind.Conn, Msg: "请求上游失败: " + err.Error()}
	}
	// 注意：非 2xx 时 rc 为 nil（错误体已在 ChatStream 里读走）。
	// 必须先判 nil 再 defer Close，否则 defer rc.Close() 会空指针 panic。
	if rc == nil {
		return nil, &AuthError{
			Kind: Classify(status, string(respBody)),
			Msg:  fmt.Sprintf("上游 %d: %s", status, truncate(string(respBody), 300)),
		}
	}
	defer rc.Close()

	if status >= 300 {
		return nil, &AuthError{
			Kind: Classify(status, string(respBody)),
			Msg:  fmt.Sprintf("上游 %d: %s", status, truncate(string(respBody), 300)),
		}
	}

	// 取消时关闭响应体，打断阻塞的读取。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = rc.Close()
		case <-stop:
		}
	}()

	start := time.Now()
	usage := &chat.Usage{}
	var (
		firstTokenAt time.Time
		validEvents  int
		finish       string
		truncated    bool
	)

	onChunk := func(chunk map[string]any) error {
		if e, ok := chunk["error"].(map[string]any); ok && e != nil {
			msg := str(e["message"])
			if msg == "" {
				msg = str(e["code"])
			}
			return &AuthError{Kind: Classify(200, msg), Msg: "上游错误: " + orDefault(msg, str(e["code"]))}
		}
		validEvents++
		if us, ok := chunk["usage"].(map[string]any); ok {
			applyUsage(usage, us)
		}
		choices, _ := chunk["choices"].([]any)
		for _, cv := range choices {
			ch, _ := cv.(map[string]any)
			if ch == nil {
				continue
			}
			if fr := str(ch["finish_reason"]); fr != "" {
				finish = fr
			}
			delta, _ := ch["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			if r := reasoningDeltaOf(delta); r != "" && emit != nil {
				if err := emit("reasoning.delta", map[string]any{"content": r}); err != nil {
					return err
				}
			}
			if content, ok := delta["content"].(string); ok && content != "" {
				if firstTokenAt.IsZero() {
					firstTokenAt = time.Now()
				}
				if emit != nil {
					if err := emit("text.delta", map[string]any{"content": content}); err != nil {
						return err
					}
				}
			}
			if tcs, ok := delta["tool_calls"].([]any); ok {
				if err := emitToolCalls(tcs, emit); err != nil {
					return err
				}
			}
		}
		return nil
	}

	parseErr := ParseNestedSSE(rc, onChunk, &truncated)
	usage.TimeMs = time.Since(start).Milliseconds()
	if !firstTokenAt.IsZero() {
		usage.FirstTokenMs = firstTokenAt.Sub(start).Milliseconds()
	}

	if parseErr != nil {
		if ctx.Err() != nil {
			return nil, &AuthError{Kind: errkind.Cancel, Msg: "已取消"}
		}
		var se *SSEError
		if errors.As(parseErr, &se) {
			return nil, &AuthError{Kind: se.Kind(), Msg: se.Error()}
		}
		var ae *AuthError
		if errors.As(parseErr, &ae) {
			return nil, ae
		}
		return nil, &AuthError{Kind: errkind.Conn, Msg: "读取上游流失败: " + parseErr.Error()}
	}
	if truncated {
		return nil, &AuthError{Kind: errkind.Truncated, Msg: "上游流已中断（响应不完整）"}
	}
	if validEvents == 0 {
		return nil, &AuthError{Kind: errkind.Server, Msg: "上游返回空流（未收到任何有效事件）"}
	}

	if emit != nil {
		if err := emit("finish_reason", map[string]any{"reason": finish}); err != nil {
			return nil, err
		}
		if err := emit("usage", usageFields(usage)); err != nil {
			return nil, err
		}
		if err := emit("completed", map[string]any{"finish_reason": finish}); err != nil {
			return nil, err
		}
	}
	return usage, nil
}

// buildChatBody 把协议请求翻译成上游 body（未签名前的原始 JSON）。
func buildChatBody(req *chat.GenerateRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("缺少请求")
	}
	if strings.TrimSpace(req.Model) == "" {
		return nil, errors.New("缺少 model")
	}
	if len(req.Messages) == 0 {
		return nil, errors.New("缺少 messages")
	}
	body := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
		"stream":   true,
		// 缺省补 include_usage：否则末帧无 usage（旧版 D7；客户端显式给了就不覆盖）。
		"stream_options": map[string]any{"include_usage": true},
	}
	if len(req.Tools) > 0 {
		body["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		body["tool_choice"] = req.ToolChoice
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil {
		body["max_tokens"] = *req.MaxTokens
	}
	if req.ReasoningEffort != "" {
		body["reasoning_effort"] = req.ReasoningEffort
	}
	if req.Thinking {
		body["thinking"] = map[string]any{"type": "enabled"}
	}
	return json.Marshal(body)
}

// applyUsage 把上游 usage 增量合并进最终用量（末帧覆盖）。
func applyUsage(u *chat.Usage, m map[string]any) {
	if u == nil || m == nil {
		return
	}
	if v, ok := m["prompt_tokens"]; ok {
		u.PromptTokens = intOf(v)
	}
	if v, ok := m["completion_tokens"]; ok {
		u.CompletionTokens = intOf(v)
	}
	if v, ok := m["total_tokens"]; ok {
		u.TotalTokens = intOf(v)
	}
	if u.TotalTokens == 0 && u.PromptTokens > 0 && u.CompletionTokens > 0 {
		u.TotalTokens = u.PromptTokens + u.CompletionTokens
	}
	cached, cachedReported := 0, false
	for _, k := range []string{"prompt_cache_hit_tokens", "cache_read_input_tokens"} {
		if v, ok := m[k]; ok {
			cached, cachedReported = intOf(v), true
			break
		}
	}
	write, writeReported := 0, false
	if d, ok := m["prompt_tokens_details"].(map[string]any); ok {
		if v, ok := d["cached_tokens"]; ok && !cachedReported {
			cached, cachedReported = intOf(v), true
		}
		if v, ok := d["cache_write_tokens"]; ok {
			write, writeReported = intOf(v), true
		}
	}
	if cachedReported || writeReported {
		u.Cache = &chat.CacheUsage{
			Cached:         cached,
			CachedReported: cachedReported,
			Write:          write,
			WriteReported:  writeReported,
		}
	}
	markReported(u)
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0
		}
		return int(n)
	case int:
		if n < 0 {
			return 0
		}
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0
		}
		return int(i)
	}
	return 0
}

// reasoningDeltaOf 取出思维链增量，兼容多种上游字段命名。
func reasoningDeltaOf(d map[string]any) string {
	if s, ok := d["reasoning_content"].(string); ok && s != "" {
		return s
	}
	if s, ok := d["reasoning"].(string); ok && s != "" {
		return s
	}
	if rd, ok := d["reasoning_details"].([]any); ok {
		var sb strings.Builder
		for _, item := range rd {
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			if s, ok := m["text"].(string); ok && s != "" {
				sb.WriteString(s)
			}
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	return ""
}

// emitToolCalls 把一次增量里的工具调用分片发射成 tool_call.delta。
func emitToolCalls(tcs []any, emit Emitter) error {
	if emit == nil {
		return nil
	}
	for i, tcv := range tcs {
		tc, _ := tcv.(map[string]any)
		if tc == nil {
			continue
		}
		idx := i
		if v, ok := tc["index"].(float64); ok {
			idx = int(v)
		}
		p := map[string]any{"index": idx}
		if s := str(tc["id"]); s != "" {
			p["id"] = s
		}
		if s := str(tc["type"]); s != "" {
			p["type"] = s
		}
		if fn, ok := tc["function"].(map[string]any); ok {
			if s := str(fn["name"]); s != "" {
				p["name"] = s
			}
			if v, ok := fn["arguments"]; ok {
				if s := fmt.Sprint(v); s != "" {
					p["arguments_fragment"] = s
				}
			}
		}
		if err := emit("tool_call.delta", p); err != nil {
			return err
		}
	}
	return nil
}

// usageFields 把 usage 摊平成事件 payload。
func usageFields(u *chat.Usage) map[string]any {
	if u == nil {
		return map[string]any{}
	}
	// 三维 token 的来源标志（W3-34）：值来自上游同一 usage 对象，明确 0 也是有效实报。
	// 不带标志时 core 只能把「全 0」当未知处理（旧副本兼容路径），无法区分明确 0。
	m := map[string]any{
		"prompt_tokens":       u.PromptTokens,
		"completion_tokens":   u.CompletionTokens,
		"total_tokens":        u.TotalTokens,
		"prompt_reported":     u.PromptReported,
		"completion_reported": u.CompletionReported,
		"total_reported":      u.TotalReported,
	}
	if u.TimeMs > 0 {
		m["time_ms"] = u.TimeMs
	}
	if u.FirstTokenMs > 0 {
		m["first_token_ms"] = u.FirstTokenMs
	}
	if u.Cache != nil {
		m["cache"] = map[string]any{
			"cached":          u.Cache.Cached,
			"cached_reported": u.Cache.CachedReported,
			"write":           u.Cache.Write,
			"write_reported":  u.Cache.WriteReported,
		}
	}
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// markReported 标记三维 token 来自上游 usage 对象（W3-34）。
// 本地加出来的 total 不是上游实报，必须清掉 TotalReported，否则把自算的数谎报成实报。
func markReported(u *chat.Usage) {
	if u == nil {
		return
	}
	derived := u.TotalTokens == 0 && u.PromptTokens > 0 && u.CompletionTokens > 0
	if derived {
		u.TotalTokens = u.PromptTokens + u.CompletionTokens
	}
	u.MarkReported()
	if derived {
		u.TotalReported = false
	}
}
