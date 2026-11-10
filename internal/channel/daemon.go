// Package channel 实现 qwenwork 渠道插件（渠道 ID：qwenwork）。
//
// 数据目录（<data>）：
//
//	<data>/auths/qwenwork-<uid>.json   凭据（token 只落此处，永不过 IPC）
//	<data>/auths/flows/<flow_id>.json  登录流程状态（跨进程：begin/status/finish）
//	<data>/logs/qwenwork.log           日志
//	<data>/stat/                       渠道自记统计
package channel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"wild-work3/qwenwork-ext/internal/protocol/authflow"
	"wild-work3/qwenwork-ext/internal/protocol/chat"
	"wild-work3/qwenwork-ext/internal/protocol/cli"
	"wild-work3/qwenwork-ext/internal/protocol/errkind"
	"wild-work3/qwenwork-ext/internal/protocol/meta"
	"wild-work3/qwenwork-ext/internal/protocol/plugin"
	"wild-work3/qwenwork-ext/internal/protocol/stat"
	"wild-work3/qwenwork-ext/internal/qw"
)

// PluginID 是渠道标识（core 侧 channel_id）。
const PluginID = "qwenwork"

// Log 是插件的日志器；nil 时静默（CLI 早退场景）。
var Log *cli.Logger

// Config 是渠道配置（channel_config）。
type Config struct {
	Proxy   string `json:"proxy,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
}

// Daemon 持有渠道的全部私有序状态。
type Daemon struct {
	dataDir string
	store   *qw.Store
	flow    *qw.FlowStore
	client  *qw.Client
	stat    *stat.Store
}

// NewDaemon 构造渠道实例。
func NewDaemon(dataDir string) *Daemon {
	return &Daemon{
		dataDir: dataDir,
		store:   qw.NewStore(dataDir),
		flow:    qw.NewFlowStore(dataDir),
		client:  qw.New(),
		stat:    stat.Open(dataDir),
	}
}

// Serve 按执行形态跑协议循环（call=一次性；stdio=常连）。
func Serve(ctx context.Context, mode, dataDir string, in io.Reader, out io.Writer) error {
	r := registry(NewDaemon(dataDir))
	switch mode {
	case plugin.ModeCall:
		return r.ServeOnce(ctx, in, out)
	default:
		return r.ServeStdio(ctx, in, out)
	}
}

// Manifest 上报插件元数据与能力清单。
func Manifest() meta.Manifest {
	return meta.Manifest{
		ID:              PluginID,
		Name:            "QwenWork",
		DefaultChannels: []meta.DefaultChannel{{ID: PluginID, Name: "QwenWork", Config: map[string]any{}}},
		Version:         "1.0.0",
		Kind:            "channel",
		Protocol: meta.ProtocolRng{
			Min: 1,
			Max: 1,
		},
		Execution: meta.Execution{
			Control:            plugin.ModeCall,
			Conversation:       plugin.ModeCall,
			MaxWorkers:         4,
			IdleTimeoutSeconds: 0,
		},
		Capabilities: meta.Capabilities{
			Control: []string{
				"models.list",
				"config.schema",
				"config.get",
				"config.set",
				"auth.methods",
				"auth.begin",
				"auth.status",
				"auth.finish",
				"auth.cancel",
				"accounts.list",
				"accounts.resource_detail",
				"accounts.refresh",
				"credits.get",
				"stats.get",
				"health.check",
				"ping",
			},
			Conversation: []string{"chat.generate"},
		},
		Icon:        "qwenwork",
		Color:       "#0e7490",
		Description: "QwenWork（通义千问办公版）渠道：COSY 签名 + 嵌套 SSE，支持 pro/flash/Qwen3.8-Max。",
	}
}

// registry 装配方法表（只注册能力声明里有的方法）。
func registry(d *Daemon) *plugin.Registry {
	r := plugin.New()
	r.Lifecycle(Manifest())
	r.Handle("config.schema", func(ctx context.Context, _ Raw) (Raw, *Err) {
		return mustJSON(configSchema()), nil
	})
	r.Handle("config.get", func(ctx context.Context, _ Raw) (Raw, *Err) {
		return mustJSON(map[string]any{}), nil
	})
	r.Handle("config.set", func(ctx context.Context, _ Raw) (Raw, *Err) {
		return mustJSON(map[string]any{"ok": true}), nil
	})
	r.Handle("auth.methods", d.authMethods)
	r.Handle("auth.begin", d.authBegin)
	r.Handle("auth.status", d.authStatus)
	r.Handle("auth.finish", d.authFinish)
	r.Handle("auth.cancel", d.authCancel)
	r.Handle("accounts.list", d.accountsList)
	r.Handle("accounts.resource_detail", d.resourceDetail)
	r.Handle("accounts.refresh", d.accountRefresh)
	r.Handle("models.list", d.modelsList)
	r.Handle("credits.get", d.creditsGet)
	r.Handle("stats.get", d.statsGet)
	r.HandleStream("chat.generate", d.generate)
	return r
}

// ---- 登录（loopback_callback + PKCE）----

func (d *Daemon) authMethods(ctx context.Context, p Raw) (Raw, *Err) {
	return mustJSON(authflow.MethodsResult{
		Methods: []authflow.Method{{
			ID:          "loopback",
			Type:        authflow.TypeLoopback,
			Label:       "浏览器登录",
			Description: "点击后在浏览器打开 QwenWork 授权页，授权完成后自动回调本机。",
			Default:     true,
		}},
		Note: "登录成功后凭据保存在插件私有目录，不会经 IPC 传输。",
	}), nil
}

func (d *Daemon) authBegin(ctx context.Context, p Raw) (Raw, *Err) {
	var req authflow.BeginRequest
	if err := json.Unmarshal(p, &req); err != nil {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "参数解析失败: %v", err)
	}
	flowID, err := qw.PrepareFlow(d.flow, parseConfig(p).BaseURL)
	if err != nil {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "创建登录流程失败: %v", err)
	}
	// 无常驻进程：登录需要在本机监听随机端口，放到分离子进程里跑。
	if err := d.spawnLogin(flowID); err != nil {
		_ = d.flow.Delete(flowID)
		return nil, errf(errkind.Conn, errkind.ScopeChannel, "启动登录进程失败: %v", err)
	}
	// 短轮询流程文件，等子进程绑端口后拿 AuthURL。
	authURL, state := d.waitFlowURL(ctx, flowID, 5*time.Second)
	if authURL == "" && state == qw.FlowFailed {
		f, _ := d.flow.Load(flowID)
		msg := "登录进程启动后未就绪"
		if f != nil && f.Error != "" {
			msg = f.Error
		}
		_ = d.flow.Delete(flowID)
		return nil, errf(errkind.Conn, errkind.ScopeChannel, "发起登录失败: %s", msg)
	}
	return mustJSON(authflow.BeginResult{
		FlowID:           flowID,
		Type:             authflow.TypeLoopback,
		Method:           orDefault(req.Method, "loopback"),
		AuthURL:          authURL,
		State:            string(authflow.StateWaitingUser),
		Prompt:           "请在弹出的浏览器页面完成登录，完成后回到面板即可。",
		CanPasteCallback: true,
		NextPollMS:       2000,
		ExpiresAt:        time.Now().Add(10 * time.Minute).Format(time.RFC3339),
	}), nil
}

// spawnLogin 起一个分离的登录子进程（自身 login 子命令），由其监听回调端口。
func (d *Daemon) spawnLogin(flowID string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"login", "--flow", flowID}
	if d.dataDir != "" {
		args = append(args, "--data", d.dataDir)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Env = os.Environ()
	return cmd.Start()
}

// waitFlowURL 轮询流程文件直到拿到 AuthURL 或失败/超时。
func (d *Daemon) waitFlowURL(ctx context.Context, flowID string, d2 time.Duration) (string, string) {
	deadline := time.Now().Add(d2)
	for {
		if f, err := d.flow.Load(flowID); err == nil {
			switch f.State {
			case qw.FlowWaitingUser, qw.FlowSuccess:
				if f.AuthURL != "" {
					return f.AuthURL, f.State
				}
			case qw.FlowFailed, qw.FlowExpired, qw.FlowCancelled:
				return f.AuthURL, f.State
			}
		}
		if time.Now().After(deadline) {
			return "", qw.FlowStarting
		}
		select {
		case <-ctx.Done():
			return "", qw.FlowStarting
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *Daemon) authStatus(ctx context.Context, p Raw) (Raw, *Err) {
	var req authflow.StatusRequest
	if err := json.Unmarshal(p, &req); err != nil {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "参数解析失败: %v", err)
	}
	f, err := d.flow.Load(req.FlowID)
	if err != nil {
		return mustJSON(authflow.StatusResult{
			State: authflow.StateFailed,
			Error: &authflow.Error{Kind: string(errkind.NotFound), Message: "登录流程不存在或已过期"},
		}), nil
	}
	res := authflow.StatusResult{State: authflow.State(f.State), Hint: f.Error}
	switch f.State {
	case qw.FlowStarting, qw.FlowWaitingUser:
		res.State = authflow.StateWaitingUser
		res.NextPollMS = 2000
	case qw.FlowSuccess:
		res.State = authflow.StateSuccess
		if f.AuthFile != "" {
			uid := f.UID
			nick := f.Nickname
			exp := ""
			if a, err := d.store.Load(f.AuthFile); err == nil {
				uid = orDefault(a.UID, uid)
				nick = orDefault(a.Nickname, nick)
				if a.ExpiresAt > 0 {
					exp = time.Unix(a.ExpiresAt, 0).Format(time.RFC3339)
				}
			}
			res.Account = &authflow.Account{
				UID:       uid,
				Nickname:  orDefault(nick, uid),
				ChannelID: PluginID,
				ExpiresAt: exp,
				LoginKind: string(authflow.TypeLoopback),
				AuthFile:  f.AuthFile,
			}
		}
	case qw.FlowFailed:
		res.State = authflow.StateFailed
		res.Error = &authflow.Error{Kind: string(errkind.Auth), Message: orDefault(f.Error, "登录失败")}
	case qw.FlowExpired:
		res.State = authflow.StateExpired
		res.Error = &authflow.Error{Kind: string(errkind.Auth), Message: "登录流程已过期，请重新发起"}
	case qw.FlowCancelled:
		res.State = authflow.StateCancelled
	}
	return mustJSON(res), nil
}

// authFinish 是人工粘贴回调地址的兜底入口（CanPasteCallback=true）。
func (d *Daemon) authFinish(ctx context.Context, p Raw) (Raw, *Err) {
	var req authflow.FinishRequest
	if err := json.Unmarshal(p, &req); err != nil {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "参数解析失败: %v", err)
	}
	if req.FlowID == "" {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "缺少 flow_id")
	}
	if raw := strings.TrimSpace(req.CallbackURL); raw != "" {
		if err := qw.FinishWithCallbackURL(ctx, d.flow, d.store, req.FlowID, raw); err != nil {
			k := errKindOf(err)
			return nil, errf(k, scopeOfKind(k), "完成登录失败: %v", err)
		}
		// 必须回传完整 StatusResult（含 Account），否则网关侧只会缓存
		// 这个精简结果而不会调用 status 补账，账号永远落不了库。
		return d.authStatus(ctx, p)
	}
	if code := strings.TrimSpace(req.Values["code"]); code != "" {
		if err := qw.FinishWithCode(ctx, d.flow, d.store, req.FlowID, code); err != nil {
			k := errKindOf(err)
			return nil, errf(k, scopeOfKind(k), "完成登录失败: %v", err)
		}
		return d.authStatus(ctx, p)
	}
	return nil, errf(errkind.BadParams, errkind.ScopeRequest, "请提供回调地址或授权码")
}

func (d *Daemon) authCancel(ctx context.Context, p Raw) (Raw, *Err) {
	var req authflow.CancelRequest
	_ = json.Unmarshal(p, &req)
	ok := d.flow.Delete(req.FlowID) == nil
	if ok {
		if f, err := d.flow.Load(req.FlowID); err == nil {
			f.State = qw.FlowCancelled
			_ = d.flow.Save(f)
		}
	}
	return mustJSON(map[string]any{"ok": ok}), nil
}

// ---- 账号 / 模型 / 额度 ----

// accountsList 上报账号事实（凭据内容绝不上报）。
func (d *Daemon) accountsList(ctx context.Context, p Raw) (Raw, *Err) {
	out := []meta.AccountInfo{}
	list, _ := d.store.List()
	for _, a := range list {
		status := "ok"
		if a.ExpiresAt > 0 && time.Now().Unix() >= a.ExpiresAt {
			status = "expired"
		}
		exp := ""
		if a.ExpiresAt > 0 {
			exp = time.Unix(a.ExpiresAt, 0).Format(time.RFC3339)
		}
		out = append(out, meta.AccountInfo{
			UID:       qw.AuthName(a.UID),
			Nickname:  orDefault(a.Nickname, a.UID),
			Status:    status,
			LoginKind: string(authflow.TypeLoopback),
			ExpiresAt: exp,
			ChannelID: PluginID,
			Prefixes:  []string{PluginID},
			AuthFile:  qw.AuthName(a.UID),
		})
	}
	return mustJSON(map[string]any{"accounts": out}), nil
}

// account 取出（必要时刷新）指定账号；name 为空时取第一个。
func (d *Daemon) account(name string, cfg Config) (*qw.Auth, *qw.Client, error) {
	var picked *qw.Auth
	if name != "" {
		if a, err := d.store.Load(name); err == nil {
			picked = a
		}
	}
	if picked == nil {
		if a, err := d.store.List(); err == nil {
			for _, it := range a {
				if name != "" && it.AuthFile != name && it.UID != name {
					continue
				}
				cp := *it
				picked = &cp
				break
			}
		}
	}
	if picked == nil {
		return nil, nil, &qw.AuthError{Kind: errkind.Auth, Msg: "该渠道尚未登录，请先在面板完成登录"}
	}
	c := qw.New().Configure(cfg.Proxy, cfg.Timeout, cfg.BaseURL)
	if picked.ExpiresAt > 0 && time.Now().Unix() >= picked.ExpiresAt && picked.RefreshToken != "" {
		if err := c.RefreshToken(picked); err != nil {
			return nil, nil, err
		}
		if err := d.store.Save(picked); err != nil && Log != nil {
			Log.Errorf("刷新后写回凭据失败: %v", err)
		}
	}
	return picked, c, nil
}

// modelsList 拉模型目录（模型 ID 带 qwenwork/ 前缀）。
func (d *Daemon) modelsList(ctx context.Context, p Raw) (Raw, *Err) {
	acct, c, err := d.account("", parseConfig(p))
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "%v", err)
	}
	ms, err := c.FetchModels(acct)
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "拉取模型失败: %v", err)
	}
	return mustJSON(map[string]any{"models": qw.ToModelInfo(ms)}), nil
}

// resourceDetail 上报额度明细（ResourceItem 裸数组）。
func (d *Daemon) resourceDetail(ctx context.Context, p Raw) (Raw, *Err) {
	acct, c, err := d.account(uidOf(p), parseConfig(p))
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "%v", err)
	}
	res, err := c.FetchResource(acct)
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "查询额度失败: %v", err)
	}
	items := res.Items
	if items == nil {
		items = []meta.ResourceItem{}
	}
	return mustJSON(items), nil
}

// creditsGet 返回余额与明细（null = 上游未提供 ≠ 0）。
func (d *Daemon) creditsGet(ctx context.Context, p Raw) (Raw, *Err) {
	acct, c, err := d.account(uidOf(p), parseConfig(p))
	if err != nil {
		return mustJSON(map[string]any{"balance": nil, "items": []meta.ResourceItem{}}), nil
	}
	res, err := c.FetchResource(acct)
	if err != nil {
		return mustJSON(map[string]any{"balance": nil, "items": []meta.ResourceItem{}}), nil
	}
	items := res.Items
	if items == nil {
		items = []meta.ResourceItem{}
	}
	return mustJSON(map[string]any{"balance": res.Balance, "items": items, "unit": "credits"}), nil
}

// accountRefresh 刷新账号（token 续期 + 额度回读）。
func (d *Daemon) accountRefresh(ctx context.Context, p Raw) (Raw, *Err) {
	acct, c, err := d.account(uidOf(p), parseConfig(p))
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "%v", err)
	}
	if acct.RefreshToken != "" {
		if err := c.RefreshToken(acct); err != nil {
			k := errKindOf(err)
			return nil, errf(k, scopeOfKind(k), "刷新凭据失败: %v", err)
		}
		if err := d.store.Save(acct); err != nil {
			return nil, errf(errkind.AccountFault, errkind.ScopeAccount, "写回凭据失败: %v", err)
		}
	}
	msg := "已刷新"
	if res, err := c.FetchResource(acct); err == nil && res != nil {
		msg = fmt.Sprintf("已刷新，剩余 %.2f 积分", res.Balance)
	}
	return mustJSON(map[string]any{"ok": true, "message": msg}), nil
}

// ---- 配置 / 统计 ----

func configSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"proxy": map[string]any{
				"type":  "string",
				"title": "代理",
			},
			"timeout": map[string]any{
				"type":    "integer",
				"title":   "超时（秒）",
				"default": 300,
			},
			"base_url": map[string]any{
				"type":        "string",
				"title":       "上游基址覆盖",
				"description": "留空使用默认网关；调试时可指向 mock。",
			},
		},
	}
}

func parseConfig(p Raw) Config {
	var wrap struct {
		Config Config `json:"config"`
	}
	_ = json.Unmarshal(p, &wrap)
	if wrap.Config.Timeout <= 0 {
		wrap.Config.Timeout = 300
	}
	return wrap.Config
}

// mergeChannelConfig 用请求内嵌的 channel_config 覆盖外层配置（会话面不传 params.config）。
// 不合并会导致 base_url/proxy 丢失，联调基址失效并回落真实上游。
func mergeChannelConfig(cfg Config, req chat.GenerateRequest) Config {
	if len(req.ChannelConfig) == 0 {
		return cfg
	}
	var in Config
	_ = json.Unmarshal(req.ChannelConfig, &in)
	if in.Proxy != "" {
		cfg.Proxy = in.Proxy
	}
	if in.BaseURL != "" {
		cfg.BaseURL = in.BaseURL
	}
	if in.Timeout > 0 {
		cfg.Timeout = in.Timeout
	}
	return cfg
}

func uidOf(p Raw) string {
	var wrap struct {
		UID string `json:"uid"`
	}
	_ = json.Unmarshal(p, &wrap)
	return wrap.UID
}

func (d *Daemon) statsGet(ctx context.Context, p Raw) (Raw, *Err) {
	var req struct {
		Days int `json:"days"`
	}
	_ = json.Unmarshal(p, &req)
	if req.Days <= 0 {
		req.Days = 7
	}
	if d.stat == nil {
		return mustJSON(stat.Summary{Days: []stat.Day{}}), nil
	}
	return mustJSON(stat.Summarize(d.stat.Query(req.Days))), nil
}

// recordChat 记录一次会话统计（未上报 token 记 -1，不写 0）。
func (d *Daemon) recordChat(acct *qw.Auth, model string, u *chat.Usage, ok bool, kind string) {
	if d.stat == nil {
		return
	}
	r := stat.Record{
		Kind:             stat.KindChat,
		Channel:          PluginID,
		Model:            model,
		OK:               ok,
		ErrKind:          kind,
		PromptTokens:     -1,
		CompletionTokens: -1,
		TotalTokens:      -1,
	}
	if acct != nil {
		r.Account = qw.AuthName(acct.UID)
	}
	if u != nil {
		// 未上报的 token 保持 -1（不写 0）。
		if u.PromptTokens > 0 {
			r.PromptTokens = u.PromptTokens
		}
		if u.CompletionTokens > 0 {
			r.CompletionTokens = u.CompletionTokens
		}
		if u.TotalTokens > 0 {
			r.TotalTokens = u.TotalTokens
		} else if u.PromptTokens > 0 || u.CompletionTokens > 0 {
			r.TotalTokens = u.PromptTokens + u.CompletionTokens
		}
		r.TimeMs = int(u.TimeMs)
		r.FirstTokenMs = int(u.FirstTokenMs)
		if u.Cache != nil {
			r.CachedTokens = u.Cache.Cached
			r.CachedReported = u.Cache.CachedReported || u.Cache.WriteReported
		}
	}
	d.stat.Append(r)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
