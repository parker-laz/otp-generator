package authenticator

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"time"

	"github.com/skip2/go-qrcode"
)

type Authenticator struct {
	issuer    string
	user      string
	secret    string
	algorithm crypto.Hash
	digits    int
	period    time.Duration
}

// GenerateOTP 生成動態密碼
func (a *Authenticator) GenerateOTP(secretKey string) (int, error) {

	// 將時間戳轉換為30秒間隔的整數
	interval := time.Now().Unix() / 30

	// 將interval轉換為大端字節序
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(interval & 0xff)
		interval >>= 8
	}

	// 選擇加密算法
	var algorithm func() hash.Hash
	switch a.algorithm {
	case Sha1:
		algorithm = sha1.New
	case Sha256:
		algorithm = sha256.New
	case Sha512:
		algorithm = sha512.New
	default:
		return 0, ErrAlgorithm
	}

	// 使用HMAC算法計算 hash value
	hmac := hmac.New(algorithm, []byte(secretKey))
	hmac.Write(buf)
	hash := hmac.Sum(nil)

	// 計算動態密碼
	offset := hash[len(hash)-1] & 0xf
	truncatedHash := hash[offset : offset+4]
	truncatedHash[0] &= 0x7f
	otp := int(truncatedHash[0])<<24 | int(truncatedHash[1])<<16 | int(truncatedHash[2])<<8 | int(truncatedHash[3])
	otp %= 1000000

	return otp, nil
}

// QRString 生成 QR Code 圖像的字符串
func (a *Authenticator) QRString(issuer, secret string, user string) string {
	secretEnc := base32.StdEncoding.EncodeToString([]byte(secret))
	return fmt.Sprintf(`otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d`, issuer, user, secretEnc, issuer, 6, 30)
}

// GenerateQRCode 生成 QR Code 圖像
func (a *Authenticator) GenerateQRCode(secret string) (qrCode []byte, err error) {

	// 創建 QR Code 圖像
	qrCode, err = qrcode.Encode(secret, qrcode.Highest, 256)
	if err != nil {
		return
	}

	return
}
