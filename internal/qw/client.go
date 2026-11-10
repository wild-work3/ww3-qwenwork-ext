package qw

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wild-work3/qwenwork-ext/internal/protocol/errkind"
)

// ErrSessionDead 表示凭据过期/失效。
var ErrSessionDead = errors.New("qw: 会话已失效")

// Client 是 qwenwork 上游 HTTP 客户端。
type Client struct {
	HTTP        *http.Client
	StreamHTTP  *http.Client
	Gateway     string
	Web         string
	IdleTimeout time.Duration
}

// New 使用默认 180s 超时。
func New() *Client { return NewWithTimeout(180 * time.Second) }

// newTransport 构造 transport；proxy 为空时走环境变量。强制 HTTP/1.1。
func newTransport(proxy string) *http.Transport {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		// 强制 HTTP/1.1（网关对 SSE 的 HTTP/2 支持不稳定）。
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return tr
}

// NewWithTimeout 构造客户端；流式请求不设整体超时。
func NewWithTimeout(d time.Duration) *Client {
	if d <= 0 {
		d = 180 * time.Second
	}
	return &Client{
		HTTP:        &http.Client{Timeout: d, Transport: newTransport("")},
		StreamHTTP:  &http.Client{Timeout: 0, Transport: newTransport("")},
		Gateway:     GatewayBase,
		Web:         WebBase,
		IdleTimeout: 300 * time.Second,
	}
}

// Configure 按渠道配置覆盖代理 / 超时 / 基址；返回自身便于链式调用。
func (c *Client) Configure(proxy string, timeoutSec int, baseURL string) *Client {
	if timeoutSec > 0 {
		c.HTTP.Timeout = time.Duration(timeoutSec) * time.Second
	}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
				tr.Proxy = http.ProxyURL(u)
			}
			if tr, ok := c.StreamHTTP.Transport.(*http.Transport); ok {
				tr.Proxy = http.ProxyURL(u)
			}
		}
	}
	if baseURL != "" {
		c.Gateway = strings.TrimRight(baseURL, "/")
		c.Web = strings.TrimRight(baseURL, "/")
	}
	return c
}

// identity 返回 COSY 签名所需的身份四元组。
func (c *Client) identity(a *Auth) (uid, name, email, token string) {
	uid = a.UID
	name = a.Nickname
	return uid, name, "", a.AccessToken
}

// AuthError 携带错误种类。
type AuthError struct {
	Kind errkind.Kind
	Msg  string
}

func (e *AuthError) Error() string { return e.Msg }

// RefreshToken 用 refresh_token 换新 device_token。
// expires_in 单位是秒（历史事故：误当毫秒导致刷新风暴被封号）。
func (c *Client) RefreshToken(a *Auth) error {
	if a == nil || a.RefreshToken == "" {
		return &AuthError{Kind: errkind.SessionDead, Msg: "缺少 refresh_token"}
	}
	body := mustJSON(map[string]string{"refresh_token": a.RefreshToken, "target": "c"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Web+EpDTRefresh, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &AuthError{Kind: errkind.Conn, Msg: "刷新请求失败: " + err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &AuthError{Kind: errkind.SessionDead, Msg: "refresh_token 已被拒绝"}
	}
	if resp.StatusCode/100 != 2 {
		return &AuthError{Kind: Classify(resp.StatusCode, string(data)), Msg: fmt.Sprintf("刷新失败 HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))}
	}
	var out struct {
		Token        string `json:"token"`
		DeviceToken  string `json:"device_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return &AuthError{Kind: errkind.Server, Msg: "刷新响应解析失败: " + err.Error()}
	}
	dt := out.DeviceToken
	if dt == "" {
		dt = out.Token
	}
	if dt == "" {
		return &AuthError{Kind: errkind.SessionDead, Msg: "刷新响应不含 token"}
	}
	a.AccessToken = dt
	if out.RefreshToken != "" {
		a.RefreshToken = out.RefreshToken
	}
	switch {
	case out.ExpiresAt != "":
		if t, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil {
			a.ExpiresAt = t.Unix()
		} else {
			a.ExpiresAt = time.Now().Add(84 * time.Hour).Unix()
		}
	case out.ExpiresIn > 0:
		a.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).Unix()
	default:
		a.ExpiresAt = time.Now().Add(84 * time.Hour).Unix()
	}
	return nil
}

// KnownModel 报告客户端模型名是否可服务。
// 上游对未知模型会静默回落默认模型并返回 200，必须在本地拒绝。
// 判定：剥前缀 → 静态别名/表命中即通过。
func (c *Client) KnownModel(name string) bool {
	s := strings.TrimSpace(name)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return false
	}
	return knownModel(ModelKey(s))
}

// knownInCatalog 拉一次动态模型目录，判断客户端模型名是否在其内。
// 供 chat 的未知模型兜底：静态表未命中时才调用（多一次上游请求，换取不误拒新模型）。
func (c *Client) knownInCatalog(name string, a *Auth) bool {
	s := strings.TrimSpace(name)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return false
	}
	models, err := c.FetchModels(a)
	if err != nil {
		return false
	}
	key := ModelKey(s)
	for _, m := range models {
		if m.ID == key || m.ID == s {
			return true
		}
	}
	return false
}

// prepareChatBody 规范化请求体：剥模型前缀、补 request_id/session_id、注入 business、强制 stream。
func (c *Client) prepareChatBody(body []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("qw: 请求体不是合法 JSON: %w", err)
	}
	if s, ok := m["model"].(string); ok {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			s = s[i+1:]
		}
		m["model"] = ModelKey(s)
	}
	if s, _ := m["request_id"].(string); s == "" {
		m["request_id"] = uuid4()
	}
	if s, _ := m["session_id"].(string); s == "" {
		m["session_id"] = uuid4()
	}
	m["business"] = map[string]any{
		"product":          BusinessProduct,
		"type":             BusinessType,
		"version":          "1",
		"feature_switches": map[string]any{},
	}
	m["stream"] = true
	return json.Marshal(m)
}

// modelKeyOf 从已规范化的请求体取上游模型 key。
func modelKeyOf(prepared []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(prepared, &m) != nil || m.Model == "" {
		return "pro"
	}
	return m.Model
}

// ChatStream 发起流式对话。非 2xx 时返回状态码与响应体，err 为 nil。
func (c *Client) ChatStream(a *Auth, body []byte) (rc io.ReadCloser, status int, respBody []byte, err error) {
	prepared, err := c.prepareChatBody(body)
	if err != nil {
		return nil, 0, nil, err
	}
	uid, name, _, token := c.identity(a)
	sess, err := NewCosySession(uid, name, "", token)
	if err != nil {
		return nil, 0, nil, err
	}
	rawURL := c.Gateway + EpChat
	headers := map[string]string{}
	if err := sess.ApplyHeadersWithUID(headers, string(prepared), rawURL, uid); err != nil {
		return nil, 0, nil, err
	}
	headers["x-model-key"] = modelKeyOf(prepared)
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(prepared))
	if err != nil {
		cancel()
		return nil, 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.StreamHTTP.Do(req)
	if err != nil {
		cancel()
		return nil, 0, nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer cancel()
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, resp.StatusCode, b, nil
	}
	return &cancelOnClose{rc: resp.Body, cancel: cancel}, resp.StatusCode, nil, nil
}

type cancelOnClose struct {
	rc     io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Read(p []byte) (int, error) { return c.rc.Read(p) }
func (c *cancelOnClose) Close() error {
	c.cancel()
	return c.rc.Close()
}

// doBearer 发一个 Web Bearer GET 并解 {code,data,msg} 信封。
func (c *Client) doBearer(rawURL string, a *Auth) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qoderwork/0.1.8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &AuthError{Kind: errkind.Conn, Msg: "请求失败: " + err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, &AuthError{Kind: Classify(resp.StatusCode, string(data)), Msg: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))}
	}
	var env struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if env.Code != "" && env.Code != "ok" && env.Code != "200" {
		return nil, &AuthError{Kind: Classify(resp.StatusCode, string(data)), Msg: "上游错误: " + env.Msg}
	}
	if len(env.Data) == 0 {
		return json.RawMessage("{}"), nil
	}
	return env.Data, nil
}

// modelEntry 是 /api/v2/model/list 的 scene 元素。
type modelEntry struct {
	Key            string  `json:"key"`
	DisplayName    string  `json:"display_name"`
	Enable         bool    `json:"enable"`
	IsDefault      bool    `json:"is_default"`
	PriceFactor    float64 `json:"price_factor"`
	MaxInputTokens int     `json:"max_input_tokens"`
}

// FetchModels 通过 COSY 签名拉取模型表；签名 body 必须为空串。
func (c *Client) FetchModels(a *Auth) ([]Model, error) {
	uid, name, _, token := c.identity(a)
	sess, err := NewCosySession(uid, name, "", token)
	if err != nil {
		return nil, err
	}
	rawURL := c.Gateway + EpModels
	const emptyBody = ""
	headers := map[string]string{}
	if err := sess.ApplyHeadersWithUID(headers, emptyBody, rawURL, uid); err != nil {
		return nil, err
	}
	headers["Accept"] = "application/json"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &AuthError{Kind: errkind.Conn, Msg: "拉取模型失败: " + err.Error()}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return nil, &AuthError{Kind: Classify(resp.StatusCode, string(data)), Msg: fmt.Sprintf("拉取模型 HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))}
	}
	var pay struct {
		Scenes map[string][]modelEntry `json:"scenes"`
	}
	if err := json.Unmarshal(data, &pay); err != nil {
		return nil, err
	}
	var out []Model
	for _, e := range pay.Scenes["qwork"] {
		if !e.Enable || e.Key == "" {
			continue
		}
		m := Model{
			ID:            e.Key,
			Name:          e.DisplayName,
			ContextWindow: e.MaxInputTokens,
			SupportsTools: true,
			PriceFactor:   e.PriceFactor,
		}
		if m.Name == "" {
			m.Name = e.Key
		}
		if m.ContextWindow <= 0 {
			m.ContextWindow = 180000
		}
		if e.Key != "pro" {
			m.SupportsImages = true
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return StaticModels(), nil
	}
	return out, nil
}

// FetchNickname 读取用户昵称。
func (c *Client) FetchNickname(a *Auth) (string, error) {
	data, err := c.doBearer(c.Web+EpUserInfo, a)
	if err != nil {
		return "", err
	}
	var pay struct {
		Nickname string `json:"nickname"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	if json.Unmarshal(data, &pay) != nil {
		return "", nil
	}
	for _, s := range []string{pay.Nickname, pay.Name, pay.Username} {
		if s != "" {
			return s, nil
		}
	}
	return "", nil
}
