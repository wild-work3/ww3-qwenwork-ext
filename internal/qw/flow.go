package qw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// flowTTL 是单次登录流程的最长存活时间。
const flowTTL = 5 * time.Minute

// 流程状态（与 authflow.State 对齐）。
const (
	FlowStarting    = "starting"
	FlowWaitingUser = "waiting_user"
	FlowSuccess     = "success"
	FlowFailed      = "failed"
	FlowExpired     = "expired"
	FlowCancelled   = "cancelled"
)

// Flow 是一次 loopback 登录的持久化状态。渠道无常驻进程，
// auth.begin / auth.status / auth.finish / auth.cancel 各在不同进程，
// 因此文件即状态。
type Flow struct {
	ID          string `json:"id"`
	Verifier    string `json:"verifier"`
	State       string `json:"state"`
	Port        int    `json:"port,omitempty"`
	RedirectURI string `json:"redirectUri,omitempty"`
	AuthURL     string `json:"authUrl,omitempty"`
	Base        string `json:"base,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	Error       string `json:"error,omitempty"`
	UID         string `json:"uid,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	AuthFile    string `json:"authFile,omitempty"`
}

// FlowStore 把流程落盘到 <data>/auths/flows/<flow_id>.json。
type FlowStore struct {
	Dir string
	mu  sync.Mutex
}

// NewFlowStore 构造流程存储。
func NewFlowStore(dataDir string) *FlowStore {
	return &FlowStore{Dir: filepath.Join(dataDir, "auths", "flows")}
}

func (s *FlowStore) path(id string) string {
	return filepath.Join(s.Dir, flowFileName(id)+".json")
}

// flowFileName 去掉路径成分，杜绝目录穿越。
func flowFileName(id string) string {
	id = filepath.Base(strings.TrimSpace(id))
	if id == "" || id == "." || id == ".." || id == string(filepath.Separator) {
		return "invalid"
	}
	return id
}

// Save 原子写入流程（目录 0700、文件 0600）。
func (s *FlowStore) Save(f *Flow) error {
	if f == nil || f.ID == "" {
		return fmt.Errorf("流程缺少 ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".flow-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path(f.ID))
}

// Load 读取流程；不存在时返回 os.ErrNotExist。
func (s *FlowStore) Load(id string) (*Flow, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("缺少 flow_id")
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var f Flow
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("流程文件损坏: %w", err)
	}
	if f.ID == "" {
		f.ID = flowFileName(id)
	}
	return &f, nil
}

// Update 读-改-写流程。
func (s *FlowStore) Update(id string, fn func(*Flow)) error {
	f, err := s.Load(id)
	if err != nil {
		return err
	}
	fn(f)
	return s.Save(f)
}

// Delete 删除流程文件。
func (s *FlowStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(id))
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// GC 清理超时僵尸流程，返回清理数量。
func (s *FlowStore) GC() int {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-flowTTL * 3).Unix()
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		f, err := s.Load(id)
		if err != nil {
			_ = s.Delete(id)
			n++
			continue
		}
		done := f.State == FlowSuccess || f.State == FlowFailed ||
			f.State == FlowExpired || f.State == FlowCancelled
		if f.CreatedAt < cutoff && done {
			_ = s.Delete(id)
			n++
		}
	}
	return n
}
