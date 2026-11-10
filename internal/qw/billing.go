package qw

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"wild-work3/qwenwork-ext/internal/protocol/meta"
)

// ToModelInfo 把本地模型表转成协议模型表（前缀 qwenwork/）。
func ToModelInfo(ms []Model) []meta.ModelInfo {
	out := make([]meta.ModelInfo, 0, len(ms))
	for _, m := range ms {
		ctx := m.ContextWindow
		if ctx <= 0 {
			ctx = 180000
		}
		out = append(out, meta.ModelInfo{
			ID:      ChannelName + "/" + m.ID,
			Name:    m.Name,
			Context: &ctx,
			Capabilities: meta.Capabilities2{
				Tools:     m.SupportsTools,
				Vision:    m.SupportsImages,
				Reasoning: true,
			},
		})
	}
	return out
}

// Resource 是账号额度视图。
type Resource struct {
	Balance float64
	Items   []meta.ResourceItem
}

type walletEntry struct {
	Balance float64 `json:"balance"`
	ValidTo string  `json:"valid_to"`
}

type walletTotals struct {
	TotalBalance float64 `json:"total_balance"`
}

// FetchResource 查询总余额（/user/balance）与钱包明细（/user/wallets）。
// 明细失败不影响主流程。
func (c *Client) FetchResource(a *Auth) (*Resource, error) {
	data, err := c.doBearer(c.Web+EpBalance, a)
	if err != nil {
		return nil, err
	}
	var bal struct {
		Balance float64 `json:"balance"`
	}
	if err := json.Unmarshal(data, &bal); err != nil {
		return nil, fmt.Errorf("balance parse: %w", err)
	}
	res := &Resource{Balance: bal.Balance}

	data, err = c.doBearer(c.Web+EpWallets, a)
	if err != nil {
		res.Items = []meta.ResourceItem{allWalletsItem(bal.Balance)}
		return res, nil
	}
	var wallets struct {
		ActiveWallets struct {
			Wallets []walletEntry `json:"wallets"`
		} `json:"active_wallets"`
		DailyCredits    walletTotals `json:"daily_credits"`
		LongtermCredits walletTotals `json:"longterm_credits"`
		MonthlyCredits  walletTotals `json:"monthly_credits"`
	}
	if err := json.Unmarshal(data, &wallets); err != nil {
		res.Items = []meta.ResourceItem{allWalletsItem(bal.Balance)}
		return res, nil
	}
	items := make([]meta.ResourceItem, 0, 4)
	add := func(name, key string, v float64, expireAt string) {
		if v <= 0 {
			return
		}
		total, used, remain := v, 0.0, v
		items = append(items, meta.ResourceItem{
			Name: name, Total: &total, Used: &used, Remain: &remain,
			ExpireAt: expireAt, Key: key, Usable: true,
		})
	}
	if d := wallets.DailyCredits.TotalBalance; d > 0 {
		exp := ""
		for _, w := range wallets.ActiveWallets.Wallets {
			if w.ValidTo != "" {
				exp = expireDate(w.ValidTo)
				break
			}
		}
		add("每日奖励", "daily", d, exp)
	}
	add("长期积分", "longterm", wallets.LongtermCredits.TotalBalance, "")
	add("月度积分", "monthly", wallets.MonthlyCredits.TotalBalance, "")
	if len(items) == 0 {
		items = append(items, allWalletsItem(bal.Balance))
	}
	res.Items = items
	return res, nil
}

func allWalletsItem(balance float64) meta.ResourceItem {
	b, used := balance, 0.0
	return meta.ResourceItem{Name: "全部钱包", Total: &b, Used: &used, Remain: &b, Usable: true}
}

// softRateResetLoc 上游墙钟按固定 UTC+8 解释。
var softRateResetLoc = time.FixedZone("UTC+8", 8*60*60)

// expireDate 把上游 valid_to 转成 RFC3339（UTC+8），丢失时返回空串。
func expireDate(ts string) string {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.In(softRateResetLoc).Format(time.RFC3339)
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, ts, softRateResetLoc); err == nil {
			return t.Format(time.RFC3339)
		}
	}
	return ""
}

// DailyCheckin 千问办公无签到活动。
func DailyCheckin() error {
	return fmt.Errorf("qwenwork 无签到活动（每日积分服务端自动发放，无需领取）")
}
