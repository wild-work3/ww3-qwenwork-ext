package qw

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Auth 是渠道凭据（token 只落插件私有目录）。
type Auth struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"` // Unix 秒
	Domain       string `json:"domain,omitempty"`
	APIHost      string `json:"apiHost,omitempty"`
	UID          string `json:"uid,omitempty"`
	Nickname     string `json:"nickname,omitempty"`
	AuthFile     string `json:"-"`
}

// Account 是落盘 account 段。
type Account struct {
	UID      string `json:"uid"`
	Nickname string `json:"nickname"`
}

// Store 管理 <data>/auths/qwenwork-<uid>.json 凭据。
type Store struct {
	Dir string
	mu  sync.Mutex
}

// NewStore 构造凭据存储。
func NewStore(dir string) *Store { return &Store{Dir: dir} }

func (s *Store) authDir() string { return filepath.Join(s.Dir, "auths") }

// AuthName 返回文件基名（去 .json），也是 core 的 account_uid。
func AuthName(uid string) string { return ChannelName + "-" + uid }

// Path 返回凭据文件路径。
func (s *Store) Path(name string) string {
	return filepath.Join(s.authDir(), name+".json")
}

// Load 按 account_uid（文件基名）读取凭据。
func (s *Store) Load(name string) (*Auth, error) {
	name = strings.TrimSuffix(filepath.Base(name), ".json")
	if name == "" {
		return nil, errors.New("qw: 凭据名不能为空")
	}
	data, err := os.ReadFile(s.Path(name))
	if err != nil {
		return nil, err
	}
	a, err := parseAuthFile(data)
	if err != nil {
		return nil, err
	}
	a.AuthFile = name
	return a, nil
}

// Save 原子写入凭据（目录 0700、文件 0600），固定嵌套形。
func (s *Store) Save(a *Auth) error {
	if a == nil || a.UID == "" {
		return errors.New("qw: 凭据缺少 uid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.authDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := AuthName(a.UID)
	out := map[string]any{
		"auth": map[string]any{
			"accessToken":  a.AccessToken,
			"refreshToken": a.RefreshToken,
			"expiresAt":    a.ExpiresAt,
			"domain":       a.Domain,
			"apiHost":      a.APIHost,
		},
		"account": map[string]any{
			"uid":      a.UID,
			"nickname": a.Nickname,
		},
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name+".json")); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	a.AuthFile = name
	return nil
}

// List 列出全部 qwenwork 凭据（按文件名排序）。
func (s *Store) List() ([]*Auth, error) {
	entries, err := os.ReadDir(s.authDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Auth
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), ChannelName+"-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		a, err := s.Load(name)
		if err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// Delete 删除凭据。
func (s *Store) Delete(name string) error {
	name = strings.TrimSuffix(filepath.Base(name), ".json")
	return os.Remove(s.Path(name))
}

// UID 返回凭据对应的 uid（文件名去掉前缀）。
func UIDOf(name string) string {
	return strings.TrimPrefix(strings.TrimSuffix(filepath.Base(name), ".json"), ChannelName+"-")
}

// parseAuthFile 兼容嵌套形与扁平形。
func parseAuthFile(data []byte) (*Auth, error) {
	var probe struct {
		Auth    json.RawMessage `json:"auth"`
		Account *Account        `json:"account"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if len(probe.Auth) > 0 && string(probe.Auth) != "null" {
		var a Auth
		if err := json.Unmarshal(probe.Auth, &a); err != nil {
			return nil, err
		}
		if probe.Account != nil {
			a.UID = probe.Account.UID
			a.Nickname = probe.Account.Nickname
		}
		return &a, nil
	}
	var a Auth
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
