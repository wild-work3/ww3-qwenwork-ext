package channel

import (
	"context"
	"encoding/json"
	"errors"

	"wild-work3/qwenwork-ext/internal/protocol/chat"
	"wild-work3/qwenwork-ext/internal/protocol/errkind"
	"wild-work3/qwenwork-ext/internal/protocol/plugin"
	"wild-work3/qwenwork-ext/internal/qw"
)

// generate 实现 chat.generate：解请求 → 取账号 → 流式桥接上游 SSE → 记账。
func (d *Daemon) generate(ctx context.Context, p Raw, emit plugin.Emit) (Raw, *Err) {
	var req chat.GenerateRequest
	if err := json.Unmarshal(p, &req); err != nil {
		return nil, errf(errkind.BadParams, errkind.ScopeRequest, "请求体解析失败: %v", err)
	}
	cfg := parseConfig(p)
	// 会话面的渠道配置在请求体的 channel_config 里，必须合并（否则 base_url/proxy 丢失）。
	cfg = mergeChannelConfig(cfg, req)

	acct, c, err := d.account(req.AccountUID, cfg)
	if err != nil {
		k := errKindOf(err)
		return nil, errf(k, scopeOfKind(k), "%v", err)
	}
	if Log != nil {
		Log.Infof("chat.generate uid=%s model=%s msgs=%d tools=%d", acct.UID, req.Model, len(req.Messages), len(req.Tools))
	}

	u, err := c.Stream(ctx, acct, &req, qw.Emitter(func(event string, payload map[string]any) error {
		return emit(event, payload)
	}))
	if err != nil {
		if ctx.Err() != nil {
			return nil, errf(errkind.Cancel, errkind.ScopeRequest, "请求已取消")
		}
		k := errKindOf(err)
		d.recordChat(acct, req.Model, u, false, string(k))
		return nil, errf(k, scopeOfKind(k), "%v", err)
	}
	if u == nil {
		u = &chat.Usage{}
	}
	d.recordChat(acct, req.Model, u, true, "")
	return mustJSON(u), nil
}

// errKindOf 把 qw 包错误映射成协议 errkind。
func errKindOf(err error) errkind.Kind {
	if err == nil {
		return errkind.Server
	}
	var ae *qw.AuthError
	if errors.As(err, &ae) {
		return ae.Kind
	}
	var se *qw.SSEError
	if errors.As(err, &se) {
		return se.Kind()
	}
	if errors.Is(err, qw.ErrSessionDead) {
		return errkind.SessionDead
	}
	return errkind.Conn
}

// scopeOfKind 决定错误归属的作用域。
func scopeOfKind(k errkind.Kind) errkind.Scope {
	switch k {
	case errkind.HardCredit, errkind.SoftRate, errkind.SessionDead, errkind.Auth, errkind.AccountFault:
		return errkind.ScopeAccount
	case errkind.NotFound, errkind.ModelBlocked, errkind.PromptTooLong:
		return errkind.ScopeModel
	case errkind.Server, errkind.WafBlock, errkind.Conn:
		return errkind.ScopeChannel
	default:
		return errkind.ScopeRequest
	}
}
