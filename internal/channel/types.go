// Package channel 实现 qwenwork 渠道插件的通道层（协议方法表 + 会话执行）。
package channel

import (
	"encoding/json"

	"wild-work3/qwenwork-ext/internal/protocol/errkind"
	"wild-work3/qwenwork-ext/internal/protocol/jsonl"
)

// Raw 是协议 JSON 消息体别名。
type Raw = jsonl.RawMessage

// Err 是协议错误对象别名。
type Err = jsonl.ErrObj

func errf(kind errkind.Kind, scope errkind.Scope, format string, a ...any) *Err {
	return jsonl.Errorf(string(kind), string(scope), format, a...)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
