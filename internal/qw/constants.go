// Package qw 实现 qwenwork 渠道的上游协议：COSY 签名、嵌套 SSE、模型表与错误分类。
package qw

const (
	// GatewayBase 是 COSY 签名网关（/algo 前缀路径）。
	GatewayBase = "https://gateway.qwenwork.cn"
	// WebBase 是 Web Bearer 接口（刷新、额度、用户信息）。
	WebBase = "https://qwenwork.cn"

	EpChat      = "/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common"
	EpModels    = "/api/v2/model/list"
	EpDTRefresh = "/api/v1/deviceToken/refresh"
	EpBalance   = "/user/balance"
	EpUserInfo  = "/user/info"
	EpWallets   = "/user/wallets"
	EpChatModes = "/api/chat-modes"

	// ChannelName 是渠道名（也用作 stat.Channel 与凭据前缀）。
	ChannelName = "qwenwork"

	BusinessProduct = "qoder_work"
	BusinessType    = "agent"
)

// Model 是本地模型描述，避免 qw 包依赖 meta。
type Model struct {
	ID             string
	Name           string
	ContextWindow  int
	SupportsImages bool
	SupportsTools  bool
	PriceFactor    float64
}

// staticModelKeys 把客户端可见名映射到上游 key。
var staticModelKeys = map[string]string{
	"auto":                "pro",
	"qwork-advanced":      "pro",
	"pro":                 "pro",
	"qwork-auto":          "pro",
	"flash":               "flash",
	"qwork-lite":          "flash",
	"qwen3.8-max":         "qwen3.8-max-preview",
	"qwen3.8-max-preview": "qwen3.8-max-preview",
	"qmodel_latest":       "qwen3.8-max-preview",
}

var staticModels = []Model{
	{ID: "pro", Name: "高级", ContextWindow: 180000, SupportsTools: true, PriceFactor: 1.0},
	{ID: "flash", Name: "标准", ContextWindow: 180000, SupportsImages: true, SupportsTools: true, PriceFactor: 0.1},
	{ID: "qwen3.8-max-preview", Name: "Qwen3.8-Max", ContextWindow: 180000, SupportsImages: true, SupportsTools: true, PriceFactor: 1.8},
}

// StaticModels 返回静态兜底模型表副本。
func StaticModels() []Model {
	out := make([]Model, len(staticModels))
	copy(out, staticModels)
	return out
}

// ModelKey 把客户端模型名映射为上游 key；未命中则原样返回。
func ModelKey(clientName string) string {
	if k, ok := staticModelKeys[clientName]; ok {
		return k
	}
	return clientName
}

// priceFactorOf 返回模型的计费倍率。
func priceFactorOf(key string) float64 {
	for _, m := range staticModels {
		if m.ID == key {
			return m.PriceFactor
		}
	}
	return 0
}

// knownModel 判断 key 是否在静态表内。
func knownModel(key string) bool {
	for _, m := range staticModels {
		if m.ID == key {
			return true
		}
	}
	return false
}
