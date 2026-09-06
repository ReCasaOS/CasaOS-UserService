package service

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"golang.org/x/crypto/bcrypt"
)

const totpPeriod = 30 // seconds; the calibration knob is the ±1 step skew below

// VerifyTOTP accepts a six-digit code for the current 30 s step or its two
// neighbours (RFC 6238 §5.2), and only for a step later than lastStep so a
// captured code cannot be replayed within its window. It returns the step
// that matched so the caller can persist it as the new lastStep.
func VerifyTOTP(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	cur := now.Unix() / totpPeriod
	opts := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		ok, err := hotp.ValidateCustom(code, uint64(step), secret, opts)
		if err == nil && ok && step > lastStep {
			return step, true
		}
	}
	return 0, false
}

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRecoveryCodes returns eight single-use codes ("xxxxx-xxxxx", a-z2-7,
// fifty bits each) and their bcrypt hashes; only the hashes are stored.
func NewRecoveryCodes() (plain, hashes []string, err error) {
	for i := 0; i < 8; i++ {
		raw := make([]byte, 7)
		if _, err = rand.Read(raw); err != nil {
			return nil, nil, err
		}
		code := strings.ToLower(recoveryEncoding.EncodeToString(raw))[:10]
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code[:5]+"-"+code[5:])
		hashes = append(hashes, string(hash))
	}
	return plain, hashes, nil
}

// ConsumeRecoveryCode checks code against every stored hash (case-insensitive,
// hyphen optional) and returns the list without the one that matched.
func ConsumeRecoveryCode(hashes []string, code string) ([]string, bool) {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			return append(hashes[:i:i], hashes[i+1:]...), true
		}
	}
	return hashes, false
}
