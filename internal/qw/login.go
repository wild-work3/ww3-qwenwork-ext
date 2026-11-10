package qw

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OAuth / loopback 回调参数（Ory Hydra，state 服务端不校验）。
const (
	OAuthBase    = "https://qwenwork.cn"
	TokenURL     = OAuthBase + "/oauth2/token"
	ClientID     = "qwenwork-desktop-app"
	OAuthScope   = "openid profile email offline_access qwen_work"
	CallbackPath = "/callback"
	AuthDomain   = "qwenwork.cn"
	AuthAPIHost  = "gateway.qwenwork.cn"
)

// LoginResult 是一次成功登录的产物。
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // 秒
	UID          string
	Nickname     string
	IDToken      string
}

// makePKCE 生成 PKCE verifier/challenge（S256，verifier 48 字节 base64url）。
func makePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 48)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// oauthBaseOf 归一化基址：为空时回落到真实上游 OAuthBase。
// 允许渠道配置 base_url 把登录流程指向 mock/自建网关（离线联调用）。
func oauthBaseOf(base string) string {
	if b := oauthBaseOrEmpty(base); b != "" {
		return b
	}
	return OAuthBase
}

// oauthBaseOrEmpty 仅归一化（去空白与尾部斜杠），空值保持为空。
func oauthBaseOrEmpty(base string) string {
	return strings.TrimRight(strings.TrimSpace(base), "/")
}

// tokenURLOf 返回换票地址；base 为空时用真实上游。
func tokenURLOf(base string) string {
	if strings.TrimSpace(base) == "" {
		return TokenURL
	}
	return oauthBaseOf(base) + "/oauth2/token"
}

// BuildAuthURL 拼接 /oauth2/auth 授权地址。base 为空时用真实上游 OAuthBase。
func BuildAuthURL(base, redirectURI, challenge string) string {
	q := url.Values{}
	q.Set("client_id", ClientID)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", OAuthScope)
	q.Set("state", uuid4())
	return oauthBaseOf(base) + "/oauth2/auth?" + q.Encode()
}

// SubmitCallbackURL 从用户粘贴的回调地址/裸查询串里取出 code（容错多种形态）。
func SubmitCallbackURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("回调地址为空")
	}
	if strings.HasPrefix(raw, "?") {
		raw = "http://127.0.0.1/" + raw
	} else if !strings.Contains(raw, "://") {
		if strings.Contains(raw, "=") {
			raw = "http://127.0.0.1/?" + raw
		} else {
			// 直接粘了 code
			return raw, nil
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("无法解析回调地址: %w", err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		return "", fmt.Errorf("授权失败: %s", desc)
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("回调地址里没有 code")
	}
	return code, nil
}

// ExchangeCode 用授权码换取 token。
func ExchangeCode(ctx context.Context, code, redirectURI, verifier, base string) (*LoginResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", ClientID)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURLOf(base), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("令牌交换请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取令牌响应失败: %w", err)
	}
	var pay struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(data, &pay); err != nil {
		return nil, fmt.Errorf("令牌响应解析失败（HTTP %d）", resp.StatusCode)
	}
	if pay.Error != "" {
		return nil, fmt.Errorf("令牌交换失败: %s %s", pay.Error, pay.ErrorDescription)
	}
	if pay.AccessToken == "" {
		return nil, fmt.Errorf("令牌交换失败: 响应缺少 access_token（HTTP %d）", resp.StatusCode)
	}
	uid, name := ParseJWTIdentity(pay.IDToken)
	if uid == "" && pay.AccessToken != "" {
		uid, name = ParseJWTIdentity(pay.AccessToken)
	}
	return &LoginResult{
		AccessToken:  pay.AccessToken,
		RefreshToken: pay.RefreshToken,
		ExpiresIn:    pay.ExpiresIn,
		IDToken:      pay.IDToken,
		UID:          uid,
		Nickname:     name,
	}, nil
}

// ParseJWTIdentity 解析 JWT payload 里的 uid/nickname（base64url 必须补齐 '='）。
func ParseJWTIdentity(token string) (uid, name string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	p := parts[1]
	if r := len(p) % 4; r != 0 {
		p += strings.Repeat("=", 4-r)
	}
	raw, err := base64.URLEncoding.DecodeString(p)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", ""
		}
	}
	var claims struct {
		Sub      string `json:"sub"`
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "", ""
	}
	uid = claims.UserID
	if uid == "" {
		uid = claims.Sub
	}
	name = claims.Username
	if name == "" {
		name = claims.Name
	}
	return uid, name
}

// PrepareFlow 生成并落盘一条 starting 流程，返回 flow ID。
// base 非空时写入流程文件，后续 auth.begin 子进程据此把登录指向该基址。
func PrepareFlow(fs *FlowStore, base string) (string, error) {
	verifier, _, err := makePKCE()
	if err != nil {
		return "", err
	}
	id := uuid4()
	f := &Flow{ID: id, Verifier: verifier, State: FlowStarting, Base: oauthBaseOrEmpty(base), CreatedAt: time.Now().Unix()}
	if err := fs.Save(f); err != nil {
		return "", err
	}
	return id, nil
}

// RunLoopback 绑定回环端口、把 AuthURL 写回流程文件、守候回调，收到 code 后换票落盘。
// 该函数通常在独立子进程中运行（见 main.go login 命令），因此状态全靠流程文件。
func RunLoopback(ctx context.Context, fs *FlowStore, as *Store, id string, onReady func(*Flow)) error {
	f, err := fs.Load(id)
	if err != nil {
		return err
	}
	if f.Verifier == "" {
		return fmt.Errorf("登录流程缺少 PKCE verifier")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("无法监听回环端口: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", port, CallbackPath)
	f.Port = port
	f.RedirectURI = redirectURI
	f.AuthURL = BuildAuthURL(f.Base, redirectURI, challengeOf(f.Verifier))
	f.State = FlowWaitingUser
	if err := fs.Save(f); err != nil {
		return err
	}
	if onReady != nil {
		onReady(f)
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			if desc == "" {
				desc = e
			}
			_, _ = io.WriteString(w, callbackPage(false, desc))
			select {
			case errCh <- fmt.Errorf("授权失败: %s", desc):
			default:
			}
			return
		}
		code := q.Get("code")
		if code == "" {
			_, _ = io.WriteString(w, callbackPage(false, "回调缺少 code 参数"))
			return
		}
		_, _ = io.WriteString(w, callbackPage(true, ""))
		select {
		case codeCh <- code:
		default:
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	timer := time.NewTimer(flowTTL)
	defer timer.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case code := <-codeCh:
			return FinishWithCode(ctx, fs, as, id, code)
		case err := <-errCh:
			_ = fs.Update(id, func(f *Flow) { f.State = FlowFailed; f.Error = err.Error() })
			return err
		case <-timer.C:
			_ = fs.Update(id, func(f *Flow) { f.State = FlowExpired })
			return fmt.Errorf("登录超时（5 分钟），请重试")
		case <-tick.C:
			if _, err := fs.Load(id); os.IsNotExist(err) {
				return nil // 流程被取消/清理
			}
		}
	}
}

// FinishWithCode 用授权码完成换票并落盘凭据，同时把流程置为 success。
func FinishWithCode(ctx context.Context, fs *FlowStore, as *Store, id, code string) error {
	f, err := fs.Load(id)
	if err != nil {
		return err
	}
	res, err := ExchangeCode(ctx, code, f.RedirectURI, f.Verifier, f.Base)
	if err != nil {
		_ = fs.Update(id, func(fl *Flow) { fl.State = FlowFailed; fl.Error = err.Error() })
		return err
	}
	return saveLoginResult(fs, as, id, res)
}

// FinishWithCallbackURL 处理 auth.finish 粘帖的回调地址。
func FinishWithCallbackURL(ctx context.Context, fs *FlowStore, as *Store, id, callbackURL string) error {
	code, err := SubmitCallbackURL(callbackURL)
	if err != nil {
		_ = fs.Update(id, func(fl *Flow) { fl.State = FlowFailed; fl.Error = err.Error() })
		return err
	}
	return FinishWithCode(ctx, fs, as, id, code)
}

func saveLoginResult(fs *FlowStore, as *Store, id string, res *LoginResult) error {
	if res.UID == "" {
		err := fmt.Errorf("登录成功但无法从令牌解析用户标识")
		_ = fs.Update(id, func(fl *Flow) { fl.State = FlowFailed; fl.Error = err.Error() })
		return err
	}
	a := &Auth{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresAt:    expiresAtOf(res.ExpiresIn),
		Domain:       AuthDomain,
		APIHost:      AuthAPIHost,
		UID:          res.UID,
		Nickname:     res.Nickname,
	}
	if err := as.Save(a); err != nil {
		_ = fs.Update(id, func(fl *Flow) { fl.State = FlowFailed; fl.Error = err.Error() })
		return err
	}
	name := AuthName(res.UID)
	return fs.Update(id, func(fl *Flow) {
		fl.State = FlowSuccess
		fl.UID = res.UID
		fl.Nickname = res.Nickname
		fl.AuthFile = name
		fl.Error = ""
	})
}

// expiresAtOf 把 expires_in（秒）换算为 Unix 秒；缺失时兜底 48 小时。
func expiresAtOf(expiresIn int64) int64 {
	if expiresIn > 0 {
		return time.Now().Unix() + expiresIn
	}
	return time.Now().Unix() + int64(48*time.Hour/time.Second)
}
