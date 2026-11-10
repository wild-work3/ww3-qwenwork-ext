// qwenwork-ext 是 QwenWork（通义千问办公版）渠道插件。
//
// 子命令：
//
//	call      协议一次性调用（core/宿主使用；也是所有子命令的真实 IPC 通道）
//	stdio     协议常连模式
//	manifest  打印插件元数据
//	ping      逐个探活协议方法
//	login     执行登录（--flow <id> 时接管已创建的流程；否则新建）
//	status    查询登录流程状态
//	accounts  列出账号
//	models    列出模型
//	chat      发起一次对话（流式打印到 stdout）
//
// 数据目录 <data>（--data / $WW3_DATA / 可执行文件所在目录）：
//
//	<data>/auths/qwenwork-<uid>.json   凭据
//	<data>/auths/flows/<flow_id>.json  登录流程
//	<data>/logs/qwenwork.log           日志
//	<data>/stat/                       统计
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"wild-work3/qwenwork-ext/internal/channel"
	"wild-work3/qwenwork-ext/internal/protocol/chat"
	"wild-work3/qwenwork-ext/internal/protocol/cli"
	"wild-work3/qwenwork-ext/internal/protocol/plugin"
	"wild-work3/qwenwork-ext/internal/qw"
)

// dataDirGlobal 是本进程解析出的数据目录。
var dataDirGlobal string

func main() {
	app := cli.NewApp("qwenwork-ext", "QwenWork 渠道插件（COSY 签名 + 嵌套 SSE）", "call")

	cCall := app.Cmd("call", "协议一次性调用")
	pCall := cCall.Str("data", "", "数据目录（--data / $WW3_DATA / 可执行文件目录）")

	cStdio := app.Cmd("stdio", "协议常连模式")
	pStdio := cStdio.Str("data", "", "数据目录")

	cManifest := app.Cmd("manifest", "打印插件元数据")
	pManOut := cManifest.Str("out", "", "写入文件（默认 stdout）")

	cPing := app.Cmd("ping", "逐个探活协议方法")
	nPing := addNetFlags(cPing)

	cLogin := app.Cmd("login", "执行登录")
	nLogin := addNetFlags(cLogin)
	loginFlow := cLogin.Str("flow", "", "接管已创建的登录流程 ID（由 auth.begin 启动）")
	loginWait := cLogin.Int("wait", 0, "等待登录完成的秒数（0 = 不等待）")

	cStatus := app.Cmd("status", "查询登录流程状态")
	nStatus := addNetFlags(cStatus)
	statusFlow := cStatus.Str("flow", "", "登录流程 ID")

	cAccounts := app.Cmd("accounts", "列出账号")
	nAccounts := addNetFlags(cAccounts)

	cModels := app.Cmd("models", "列出模型")
	nModels := addNetFlags(cModels)

	cChat := app.Cmd("chat", "发起一次对话（流式）")
	nChat := addNetFlags(cChat)
	chatModel := cChat.Str("model", os.Getenv("WW3_MODEL"), "模型 ID（如 qwenwork/pro）")
	chatPrompt := cChat.Str("prompt", "", "用户提示词（--raw 提供完整请求体时忽略）")
	chatRaw := cChat.Str("raw", "", "完整 chat.generate 请求体（JSON）或 @file")

	cmd, err := app.Parse(os.Args[1:])
	if err != nil {
		if err == cli.ErrHelp {
			return
		}
		fmt.Fprintf(os.Stderr, "参数错误: %v\n", err)
		os.Exit(2)
	}

	dataFlag := ""
	switch cmd.CmdName() {
	case plugin.ModeCall:
		dataFlag = *pCall
	case plugin.ModeStdio:
		dataFlag = *pStdio
	case "ping":
		dataFlag = *nPing.data
	case "login":
		dataFlag = *nLogin.data
	case "status":
		dataFlag = *nStatus.data
	case "accounts":
		dataFlag = *nAccounts.data
	case "models":
		dataFlag = *nModels.data
	case "chat":
		dataFlag = *nChat.data
	}
	dataDirGlobal = cli.ResolveData(dataFlag)
	channel.Log, _ = cli.NewLogger("qwenwork", cli.LogPath(dataDirGlobal, "qwenwork"))
	if channel.Log != nil {
		defer channel.Log.Close()
	}

	switch cmd.CmdName() {
	case plugin.ModeCall, plugin.ModeStdio:
		if err := channel.Serve(context.Background(), cmd.CmdName(), dataDirGlobal, os.Stdin, os.Stdout); err != nil {
			fail("%s 退出: %v", cmd.CmdName(), err)
		}
	case "manifest":
		b, err := json.MarshalIndent(channel.Manifest(), "", "  ")
		if err != nil {
			fail("序列化 manifest 失败: %v", err)
		}
		if *pManOut != "" {
			if err := os.WriteFile(*pManOut, append(b, '\n'), 0o644); err != nil {
				fail("写入 %s 失败: %v", *pManOut, err)
			}
			return
		}
		fmt.Println(string(b))
	case "login":
		runLogin(nLogin.cfg(), *loginFlow, *loginWait)
	case "status":
		runStatus(nStatus.cfg(), *statusFlow)
	case "accounts":
		fmt.Println(cli.RedactJSON(callOnce("accounts.list", map[string]any{"config": nAccounts.cfg()})))
	case "models":
		fmt.Println(cli.RedactJSON(callOnce("models.list", map[string]any{"config": nModels.cfg()})))
	case "chat":
		runChat(nChat.cfg(), *nChat.auth, *chatModel, *chatPrompt, *chatRaw)
	case "ping":
		runPing(nPing.cfg())
	default:
		fail("未知命令: %s", cmd.CmdName())
	}
}

// ---- 命令行开关 ----

type netFlags struct {
	data    *string
	config  *string
	auth    *string
	proxy   *string
	baseURL *string
	timeout *int
}

func addNetFlags(c *cli.Command) *netFlags {
	return &netFlags{
		data:    c.Str("data", "", "数据目录"),
		config:  c.Str("config", "", "渠道配置 JSON 或 @file"),
		auth:    c.Str("auth", os.Getenv("WW3_AUTH"), "账号标识（auths/ 文件名）"),
		proxy:   c.Str("proxy", os.Getenv("WW3_PROXY"), "HTTP 代理"),
		baseURL: c.Str("base-url", os.Getenv("WW3_BASE_URL"), "上游基址覆盖"),
		timeout: c.Int("timeout", 300, "超时（秒）"),
	}
}

func (n *netFlags) cfg() map[string]any {
	cfg := map[string]any{}
	if n.config != nil && *n.config != "" {
		if err := json.Unmarshal([]byte(cli.ConfigArg(*n.config)), &cfg); err != nil {
			fail("解析 --config 失败: %v", err)
		}
	}
	if n.baseURL != nil && *n.baseURL != "" {
		cfg["base_url"] = *n.baseURL
	}
	if n.proxy != nil && *n.proxy != "" {
		cfg["proxy"] = *n.proxy
	}
	if n.timeout != nil && *n.timeout > 0 {
		cfg["timeout"] = *n.timeout
	}
	return cfg
}

// ---- 真实 IPC（起自身 call 子进程，无 CLI 专用捷径）----

func callOnce(method string, params any) string {
	raw, err := spawnInvoke(method, params)
	if err != nil {
		fail("%s 失败: %v", method, err)
	}
	return raw
}

func spawnInvoke(method string, params any) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	args := []string{plugin.ModeCall}
	if dataDirGlobal != "" {
		args = append(args, "--data", dataDirGlobal)
	}
	p, err := cli.Spawn("qwenwork-call", exe, args, channel.Log)
	if err != nil {
		return "", err
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := p.InvokeSimple(ctx, method, params)
	if err != nil {
		return "", err
	}
	return string(res.Raw), nil
}

// ---- 各命令实现 ----

func runLogin(cfg map[string]any, flowID string, waitSec int) {
	fs := qw.NewFlowStore(dataDirGlobal)
	as := qw.NewStore(dataDirGlobal)

	if flowID == "" {
		// 独立登录：本进程创建流程并监听回调。
		base, _ := cfg["base_url"].(string)
		id, err := qw.PrepareFlow(fs, base)
		if err != nil {
			fail("创建登录流程失败: %v", err)
		}
		flowID = id
		fmt.Fprintf(os.Stderr, "登录流程 %s 已创建\n", flowID)
	}
	if _, err := fs.Load(flowID); err != nil {
		fail("登录流程 %s 不存在: %v", flowID, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	err := qw.RunLoopback(ctx, fs, as, flowID, func(f *qw.Flow) {
		fmt.Fprintf(os.Stderr, "请在浏览器打开以下地址完成登录：\n\n  %s\n\n", f.AuthURL)
	})
	if err != nil {
		fail("登录失败: %v", err)
	}

	f, err := fs.Load(flowID)
	if err != nil {
		fail("读取登录结果失败: %v", err)
	}
	if f.State != qw.FlowSuccess {
		fail("登录未完成: state=%s %s", f.State, f.Error)
	}
	fmt.Printf("登录成功：uid=%s nickname=%s\n", f.UID, f.Nickname)
	_ = waitSec
}

func runStatus(cfg map[string]any, flowID string) {
	if flowID == "" {
		fail("缺少 --flow")
	}
	fmt.Fprintln(os.Stderr, cli.RedactJSON(callOnce("auth.status", map[string]any{
		"flow_id": flowID,
		"config":  cfg,
	})))
}

func runPing(cfg map[string]any) {
	probes := []string{
		"config.schema",
		"auth.methods",
		"accounts.list",
		"credits.get",
		"accounts.resource_detail",
		"accounts.refresh",
		"stats.get",
	}
	for _, m := range probes {
		raw, err := spawnInvoke(m, map[string]any{"config": cfg})
		if err != nil {
			fmt.Printf("✗ %-26s %v\n", m, err)
			continue
		}
		fmt.Printf("✓ %-26s %s\n", m, truncateStr(cli.RedactJSON(raw), 160))
	}
}

func runChat(cfg map[string]any, authName, model, prompt, rawBody string) {
	if model == "" {
		fail("缺少 --model（如 qwenwork/pro）；也可用 $WW3_MODEL")
	}
	req := chat.GenerateRequest{
		Model:          model,
		Stream:         true,
		AccountUID:     authName,
		ConversationID: fmt.Sprintf("cli-%d", os.Getpid()),
	}
	if rawBody != "" {
		if err := json.Unmarshal([]byte(cli.ConfigArg(rawBody)), &req); err != nil {
			fail("解析 --raw 失败: %v", err)
		}
		req.Stream = true
		req.AccountUID = authName
	} else {
		if prompt == "" {
			fail("缺少 --prompt 或 --raw")
		}
		req.Messages = []chat.ChatMessage{{Role: "user", Content: prompt}}
	}
	if req.ChannelConfig == nil {
		if b, err := json.Marshal(cfg); err == nil {
			req.ChannelConfig = b
		}
	}

	exe, err := os.Executable()
	if err != nil {
		fail("定位可执行文件失败: %v", err)
	}
	args := []string{plugin.ModeCall}
	if dataDirGlobal != "" {
		args = append(args, "--data", dataDirGlobal)
	}
	p, err := cli.Spawn("qwenwork-call", exe, args, channel.Log)
	if err != nil {
		fail("启动 IPC 子进程失败: %v", err)
	}
	defer p.Close()
	p.Out = os.Stdout

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := p.Invoke(ctx, cli.Step{Method: "chat.generate", Params: req, Stream: true})
	if err != nil {
		fail("chat.generate 失败: %v", err)
	}
	if res == nil || !res.OK {
		os.Exit(2)
	}
}

func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}
