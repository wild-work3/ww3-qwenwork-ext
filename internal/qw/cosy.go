package qw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// serverPubKeyPEM 是 Qoder 系客户端共享的 RSA 公钥（用于包裹 AES 会话密钥）。
const serverPubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

var serverPubKey *rsa.PublicKey

func init() {
	block, _ := pem.Decode([]byte(serverPubKeyPEM))
	if block == nil {
		panic("qw: 无法解析 COSY 公钥 PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("qw: 无法解析 COSY 公钥: " + err.Error())
	}
	rk, ok := key.(*rsa.PublicKey)
	if !ok {
		panic("qw: COSY 公钥不是 RSA 公钥")
	}
	serverPubKey = rk
}

// nowUnix 可在测试中注入，保证签名时间戳与 Cosy-Date 头同源。
var nowUnix = func() int64 { return time.Now().Unix() }

// CosySession 持有一次会话的临时密钥与加密后的身份信息。
type CosySession struct {
	TempKey []byte
	CosyKey string
	Info    string
}

// NewCosySession 构造 COSY 会话：RSA 包裹 16 字符 AES 密钥，AES-128-CBC 加密身份。
func NewCosySession(uid, name, email, accessToken string) (*CosySession, error) {
	tempKey := []byte(hexShort(16))
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, serverPubKey, tempKey)
	if err != nil {
		return nil, fmt.Errorf("cosy: RSA 包裹会话密钥失败: %w", err)
	}
	infoPlain, err := json.Marshal(map[string]string{
		"uid":                  uid,
		"aid":                  "",
		"name":                 name,
		"email":                email,
		"security_oauth_token": accessToken,
	})
	if err != nil {
		return nil, fmt.Errorf("cosy: 序列化身份失败: %w", err)
	}
	infoCipher, err := aesCBCEncrypt(infoPlain, tempKey)
	if err != nil {
		return nil, err
	}
	return &CosySession{
		TempKey: tempKey,
		CosyKey: base64.StdEncoding.EncodeToString(wrapped),
		Info:    base64.StdEncoding.EncodeToString(infoCipher),
	}, nil
}

// aesCBCEncrypt 以 key=iv=tempKey 做 AES-128-CBC + PKCS7 填充。
func aesCBCEncrypt(plain, tempKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(tempKey)
	if err != nil {
		return nil, fmt.Errorf("cosy: AES 初始化失败: %w", err)
	}
	padLen := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+padLen)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, tempKey).CryptBlocks(out, padded)
	return out, nil
}

// AuthHeader 生成 Authorization 头与配套的 Cosy-Date（必须与签名同源）。
func (s *CosySession) AuthHeader(body, rawURL string) (auth, date string, err error) {
	header := map[string]string{
		"version":     "v1",
		"requestId":   uuid4(),
		"info":        s.Info,
		"cosyVersion": "1.1.18",
		"ideVersion":  "0.1.8",
	}
	headerB64 := base64.StdEncoding.EncodeToString(mustJSON(header))
	u, perr := url.Parse(rawURL)
	if perr != nil {
		return "", "", fmt.Errorf("cosy: 解析 URL 失败: %w", perr)
	}
	pathSig := strings.TrimPrefix(u.Path, "/algo")
	date = fmt.Sprintf("%d", nowUnix())
	sigInput := headerB64 + "\n" + s.CosyKey + "\n" + date + "\n" + body + "\n" + pathSig
	sum := md5.Sum([]byte(sigInput))
	auth = "Bearer COSY." + headerB64 + "." + hex.EncodeToString(sum[:])
	return auth, date, nil
}

// ApplyHeadersWithUID 把 COSY 四件套与其他固定头写入 h。
func (s *CosySession) ApplyHeadersWithUID(h map[string]string, body, rawURL, uid string) error {
	auth, date, err := s.AuthHeader(body, rawURL)
	if err != nil {
		return err
	}
	h["Authorization"] = auth
	h["Cosy-Key"] = s.CosyKey
	h["Cosy-User"] = uid
	h["Cosy-Date"] = date
	h["Content-Type"] = "application/json"
	h["Accept"] = "text/event-stream"
	return nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func uuid4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func hexShort(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(b)[:n]
}
