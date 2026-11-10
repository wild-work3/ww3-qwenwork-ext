package qw

import (
	"strings"

	"wild-work3/qwenwork-ext/internal/protocol/errkind"
)

// hardMarkers 命中即判定余额/配额硬性不足。
var hardMarkers = []string{
	"insufficient",
	"balance",
	"credit",
	"quota",
	"积分不足",
	"余额不足",
	"额度不足",
	"欠费",
}

// softRateMarkers 命中即判定为软限流。
var softRateMarkers = []string{
	"rate limit",
	"rate_limit",
	"too many requests",
	"usage limit",
	"请求过于频繁",
	"限流",
	"slow down",
}

// sessionDeadMarkers 命中即判定会话/凭据失效。
var sessionDeadMarkers = []string{
	"signature invalid",
	"unauthorized",
	"token expired",
	"invalid token",
	"登录已失效",
}

// contentBlockedMarkers 命中即判定内容被安全策略拦截。
var contentBlockedMarkers = []string{
	"blocked by security policy",
	"unapproved channel",
	"illegal api invocation",
	"content policy",
	"风险",
}

// Classify 把上游 HTTP 状态与响应体映射为协议错误种类。
func Classify(status int, body string) errkind.Kind {
	low := strings.ToLower(body)
	contains := func(markers []string) bool {
		for _, m := range markers {
			if strings.Contains(low, m) {
				return true
			}
		}
		return false
	}
	switch {
	case status == 402:
		return errkind.HardCredit
	case status == 401:
		return errkind.SessionDead
	case status == 403 && strings.Contains(low, "signature invalid"):
		return errkind.SessionDead
	case status == 429:
		return errkind.SoftRate
	case contains(hardMarkers):
		return errkind.HardCredit
	case contains(sessionDeadMarkers):
		return errkind.SessionDead
	case contains(softRateMarkers):
		return errkind.SoftRate
	case status == 404:
		return errkind.NotFound
	case status >= 500:
		return errkind.Server
	case status >= 400:
		if contains(contentBlockedMarkers) {
			return errkind.ContentBlocked
		}
		if strings.Contains(low, "prompt too long") || strings.Contains(low, "context length") {
			return errkind.PromptTooLong
		}
		return errkind.Client
	default:
		return errkind.Client
	}
}
